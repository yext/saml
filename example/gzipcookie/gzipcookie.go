package gzipcookie

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/crewjam/saml/samlsp"
)

// GzipSessionCodec compresses signed session tokens.
type GzipSessionCodec struct {
	samlsp.JWTSessionCodec
}

// Encode returns a serialized version of the Session.
func (c GzipSessionCodec) Encode(s samlsp.Session) (string, error) {
	uncompressedToken, err := c.JWTSessionCodec.Encode(s)
	if err != nil {
		return "", err
	}

	parts := strings.Split(uncompressedToken, ".")
	if len(parts) != 3 {
		panic("invalid JWT")
	}

	binary, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	compressedMiddle := bytes.NewBuffer(nil)
	w := gzip.NewWriter(compressedMiddle)
	w.Write(binary)
	w.Close()

	parts[1] = base64.RawURLEncoding.EncodeToString(compressedMiddle.Bytes())
	return strings.Join(parts, "."), nil
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c GzipSessionCodec) Decode(compressed string) (samlsp.Session, error) {
	parts := strings.Split(compressed, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}

	compressedBinary, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(bytes.NewReader(compressedBinary))
	if err != nil {
		return nil, err
	}
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	parts[1] = base64.RawURLEncoding.EncodeToString(buf)
	uncompressedToken := strings.Join(parts, ".")

	return c.JWTSessionCodec.Decode(uncompressedToken)
}
