package gzipcookie

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crewjam/saml/samlsp"
)

var tokenJSON = []byte(`{
	"aud": "https://15661444.ngrok.io/",
	"iss": "https://15661444.ngrok.io/",
	"exp": 1448942229,
	"iat": 1448935029,
	"nbf": 1448935029,
	"sub": "_41bd295976dadd70e1480f318e772841",
	"attr": {
	  "cn": [
		"Me Myself And I"
	  ],
	  "eduPersonAffiliation": [
		"Member",
		"Staff"
	  ],
	  "eduPersonEntitlement": [
		"urn:mace:dir:entitlement:common-lib-terms"
	  ],
	  "eduPersonPrincipalName": [
		"myself@testshib.org"
	  ],
	  "eduPersonScopedAffiliation": [
		"Member@testshib.org",
		"Staff@testshib.org"
	  ],
	  "eduPersonTargetedID": [
		""
	  ],
	  "givenName": [
		"Me Myself"
	  ],
	  "sn": [
		"And I"
	  ],
	  "telephoneNumber": [
		"555-5555"
	  ],
	  "uid": [
		"myself"
	  ]
	},
	"saml-session": true
  }`)

func Test(t *testing.T) {
	var tc samlsp.JWTSessionClaims
	if err := json.Unmarshal(tokenJSON, &tc); err != nil {
		panic(err)
	}

	codec := GzipSessionCodec{}
	buf, err := codec.Encode(tc)
	assert.NoError(t, err)
	assert.Equal(t, "XXX", buf)

	s, err := codec.Decode(buf)
	assert.NoError(t, err)
	assert.Equal(t, "XXX", s)

}
