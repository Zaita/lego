package wif01

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeProvider struct {
	issuer   string
	audience string // overrides the requested audience when not empty.
}

func (p *fakeProvider) Token(_ context.Context, audience string) (string, error) {
	if p.audience != "" {
		audience = p.audience
	}

	return fakeJWT(map[string]any{"iss": p.issuer, "aud": audience}), nil
}

func fakeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"test"}`))

	payload, _ := json.Marshal(claims)

	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

func TestAudienceBindingValue(t *testing.T) {
	// SHA-256("token.thumbprint") computed independently:
	// printf 'token.thumbprint' | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
	abv := AudienceBindingValue("token.thumbprint")

	assert.Equal(t, "urn:ietf:params:acme:wif:61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I", abv)
	assert.Len(t, abv, 68)
}

func TestChallenge_Solve(t *testing.T) {
	server := tester.MockACMEServer().BuildHTTPS(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	testCases := []struct {
		desc       string
		provider   *fakeProvider
		issuers    []string
		requireErr require.ErrorAssertionFunc
	}{
		{
			desc:       "success",
			provider:   &fakeProvider{issuer: "https://token.actions.githubusercontent.com"},
			issuers:    []string{"https://token.actions.githubusercontent.com"},
			requireErr: require.NoError,
		},
		{
			desc:       "no issuer restriction",
			provider:   &fakeProvider{issuer: "https://example.com"},
			requireErr: require.NoError,
		},
		{
			desc:     "issuer not accepted",
			provider: &fakeProvider{issuer: "https://example.com"},
			issuers:  []string{"https://token.actions.githubusercontent.com"},
			requireErr: func(t require.TestingT, err error, _ ...any) {
				require.ErrorContains(t, err, `issuer "https://example.com" is not accepted`)
			},
		},
		{
			desc:     "audience mismatch",
			provider: &fakeProvider{issuer: "https://example.com", audience: "sts.amazonaws.com"},
			requireErr: func(t require.TestingT, err error, _ ...any) {
				require.ErrorContains(t, err, "audience does not contain the Audience Binding Value")
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			var validated bool

			validate := func(_ context.Context, _ *api.Core, domain string, chlng acme.Challenge, payload any) error {
				validated = true

				assert.Equal(t, "example.com", domain)
				assert.Equal(t, "abc", chlng.Token)

				p, ok := payload.(Payload)
				require.True(t, ok)

				keyAuth, err := core.GetKeyAuthorization(chlng.Token)
				require.NoError(t, err)

				require.NoError(t, checkToken(p.WIFToken, AudienceBindingValue(keyAuth), nil))

				return nil
			}

			authz := acme.Authorization{
				Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
				Challenges: []acme.Challenge{
					{Type: challenge.WIF01.String(), Token: "abc", Issuers: test.issuers},
				},
			}

			err := NewChallenge(core, validate, test.provider).Solve(t.Context(), authz)
			test.requireErr(t, err)

			if err == nil {
				assert.True(t, validated)
			} else {
				assert.False(t, validated)
				assert.NotContains(t, err.Error(), "eyJ", "the token must not appear in errors")
			}
		})
	}
}

func Test_checkToken_audienceArray(t *testing.T) {
	token := fakeJWT(map[string]any{"iss": "https://example.com", "aud": []string{"other", "abv"}})

	require.NoError(t, checkToken(token, "abv", []string{"https://example.com"}))
}

func Test_checkToken_malformed(t *testing.T) {
	require.Error(t, checkToken("not-a-jwt", "abv", nil))
	require.Error(t, checkToken("a.!!!.c", "abv", nil))
}

func Test_acceptedIssuers(t *testing.T) {
	dir := acme.Directory{Meta: acme.Meta{WIF: &acme.WIFMeta{Issuers: []string{"a", "b"}}}}

	assert.Equal(t, []string{"a", "b"}, acceptedIssuers(acme.Challenge{}, dir))
	assert.Equal(t, []string{"b"}, acceptedIssuers(acme.Challenge{Issuers: []string{"b"}}, dir))
	assert.Nil(t, acceptedIssuers(acme.Challenge{}, acme.Directory{}))
}
