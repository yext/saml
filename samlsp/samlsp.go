// Package samlsp provides helpers that can be used to protect web
// services using SAML.
package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

const defaultTokenMaxAge = time.Hour

// Options represents the parameters for creating a new middleware
type Options struct {
	URL               url.URL
	Key               *rsa.PrivateKey
	Logger            logger.Interface
	Certificate       *x509.Certificate
	Intermediates     []*x509.Certificate
	AllowIDPInitiated bool
	IDPMetadata       *saml.EntityDescriptor
	IDPMetadataURL    *url.URL
	HTTPClient        *http.Client
	CookieMaxAge      time.Duration
	CookieName        string
	CookieDomain      string
	CookieSecure      bool
	ForceAuthn        bool
}

// New creates a new Middleware
func New(opts Options) (*Middleware, error) {
	metadataRelURL, _ := url.Parse("saml/metadata")
	metadataURL := opts.URL.ResolveReference(metadataRelURL)
	acsRelURL, _ := url.Parse("saml/acs")
	acsURL := opts.URL.ResolveReference(acsRelURL)
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}
	sloRelURL, _ := url.Parse("saml/slo")
	sloURL := opts.URL.ResolveReference(sloRelURL)

	tokenMaxAge := opts.CookieMaxAge
	if opts.CookieMaxAge == 0 {
		tokenMaxAge = defaultTokenMaxAge
	}

	m := &Middleware{
		ServiceProvider: saml.ServiceProvider{
			Key:               opts.Key,
			Logger:            logr,
			Certificate:       opts.Certificate,
			Intermediates:     opts.Intermediates,
			MetadataURL:       *metadataURL,
			AcsURL:            *acsURL,
			SloURL:            *sloURL,
			IDPMetadata:       opts.IDPMetadata,
			ForceAuthn:        &opts.ForceAuthn,
			AllowIDPInitiated: opts.AllowIDPInitiated,
		},
		AllowIDPInitiated: opts.AllowIDPInitiated,
		TokenMaxAge:       tokenMaxAge,
	}

	cookieStore := ClientCookies{
		ServiceProvider: &m.ServiceProvider,
		Name: func() string {
			if opts.CookieName != "" {
				return opts.CookieName
			}
			return defaultCookieName
		}(),
		Domain: func() string {
			if opts.CookieDomain != "" {
				return opts.CookieDomain
			}
			host, _, err := net.SplitHostPort(opts.URL.Host)
			if err != nil {
				return opts.URL.Host
			}
			return host
		}(),
		Secure: opts.CookieSecure,
	}
	m.ClientState = &cookieStore
	m.ClientToken = &cookieStore

	// fetch the IDP metadata if needed.
	if opts.IDPMetadataURL == nil {
		return m, nil
	}

	c := opts.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequest("GET", opts.IDPMetadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	// Some providers (like OneLogin) do not work properly unless the User-Agent header is specified.
	// Setting the user agent prevents the 403 Forbidden errors.
	req.Header.Set("User-Agent", "Golang; github.com/crewjam/saml")

	for i := 0; true; i++ {
		resp, err := c.Do(req)
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
		}
		var data []byte
		if err == nil {
			data, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			if i > 10 {
				return nil, err
			}
			logr.Printf("ERROR: %s: %s (will retry)", opts.IDPMetadataURL, err)
			time.Sleep(5 * time.Second)
			continue
		}

		entity := &saml.EntityDescriptor{}
		err = xml.Unmarshal(data, entity)

		// this comparison is ugly, but it is how the error is generated in encoding/xml
		if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}
			if err := xml.Unmarshal(data, entities); err != nil {
				return nil, err
			}

			err = fmt.Errorf("no entity found with IDPSSODescriptor")
			for i, e := range entities.EntityDescriptors {
				if len(e.IDPSSODescriptors) > 0 {
					entity = &entities.EntityDescriptors[i]
					err = nil
				}
			}
		}
		if err != nil {
			return nil, err
		}

		m.ServiceProvider.IDPMetadata = entity
		return m, nil
	}

	panic("unreachable")
}
