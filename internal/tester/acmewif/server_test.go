package acmewif_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge/wif01"
	"github.com/go-acme/lego/v5/internal/tester/acmewif"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const issuer = "https://idp.example.com"

// setup creates an account and an order for one identifier, and returns the pending challenge.
func setup(t *testing.T, server *acmewif.Server) (*api.Core, acme.Challenge) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	_, err = core.Accounts.New(t.Context(), acme.Account{TermsOfServiceAgreed: true})
	require.NoError(t, err)

	order, err := core.Orders.New(t.Context(), []string{"a.example.com"}, nil)
	require.NoError(t, err)
	require.Len(t, order.Authorizations, 1)

	authz, err := core.Authorizations.Get(t.Context(), order.Authorizations[0])
	require.NoError(t, err)
	require.Len(t, authz.Challenges, 1)

	chlg := authz.Challenges[0]
	require.Equal(t, "wif-01", chlg.Type)
	require.Equal(t, acme.StatusPending, chlg.Status)

	return core, chlg
}

func audience(t *testing.T, core *api.Core, chlg acme.Challenge) string {
	t.Helper()

	keyAuth, err := core.GetKeyAuthorization(chlg.Token)
	require.NoError(t, err)

	return wif01.AudienceBindingValue(keyAuth)
}

func TestServer_validToken(t *testing.T) {
	idp := acmewif.NewIdP(t, issuer, "k1")
	server := acmewif.NewServer(t, acmewif.Config{Issuers: map[string]jose.JSONWebKeySet{issuer: idp.KeySet()}})

	core, chlg := setup(t, server)

	token := idp.Mint(acmewif.MintOptions{Subject: "s", Audience: []string{audience(t, core, chlg)}})

	resp, err := core.Challenges.NewWithPayload(t.Context(), chlg.URL, wif01.Payload{WIFToken: token})
	require.NoError(t, err)
	require.Equal(t, acme.StatusValid, resp.Status)

	authz, err := core.Authorizations.Get(t.Context(), resp.AuthorizationURL)
	require.NoError(t, err)

	assert.Equal(t, acme.StatusValid, authz.Status)
	// The authorization must not outlive the token.
	assert.WithinDuration(t, time.Now().Add(acmewif.DefaultTokenLifetime), authz.Expires, 5*time.Second)
}

func TestServer_rejections(t *testing.T) {
	idp := acmewif.NewIdP(t, issuer, "k1")
	untrusted := acmewif.NewIdP(t, "https://untrusted.example.com", "k1")

	testCases := []struct {
		desc     string
		token    func(aud string) string
		expected string
	}{
		{
			desc: "alg none",
			token: func(aud string) string {
				enc := base64.RawURLEncoding.EncodeToString
				return enc([]byte(`{"alg":"none","kid":"k1"}`)) + "." +
					enc([]byte(`{"iss":"`+issuer+`","aud":"`+aud+`","exp":9999999999}`)) + "."
			},
			expected: acme.BadWIFTokenErrorType,
		},
		{
			desc: "missing kid",
			token: func(aud string) string {
				return idp.Mint(acmewif.MintOptions{Audience: []string{aud}, NoKID: true})
			},
			expected: acme.BadWIFTokenErrorType,
		},
		{
			desc: "untrusted issuer",
			token: func(aud string) string {
				return untrusted.Mint(acmewif.MintOptions{Audience: []string{aud}})
			},
			expected: acme.WIFIssuerNotAcceptedErrorType,
		},
		{
			desc: "audience mismatch",
			token: func(_ string) string {
				return idp.Mint(acmewif.MintOptions{Audience: []string{"urn:ietf:params:acme:wif:other"}})
			},
			expected: acme.WIFAudienceMismatchErrorType,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := acmewif.NewServer(t, acmewif.Config{Issuers: map[string]jose.JSONWebKeySet{issuer: idp.KeySet()}})

			core, chlg := setup(t, server)

			resp, err := core.Challenges.NewWithPayload(t.Context(), chlg.URL, wif01.Payload{WIFToken: test.token(audience(t, core, chlg))})
			require.NoError(t, err)

			assert.Equal(t, acme.StatusInvalid, resp.Status)
			require.NotNil(t, resp.Error)
			assert.Equal(t, test.expected, resp.Error.Type)
		})
	}
}

func TestServer_emptyResponse(t *testing.T) {
	idp := acmewif.NewIdP(t, issuer, "k1")
	server := acmewif.NewServer(t, acmewif.Config{Issuers: map[string]jose.JSONWebKeySet{issuer: idp.KeySet()}})

	core, chlg := setup(t, server)

	// The RFC 8555 empty object is not a valid wif-01 response.
	_, err := core.Challenges.New(t.Context(), chlg.URL)
	require.ErrorContains(t, err, acme.MalformedErrorType)
}
