package lego

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/wif01"
	"github.com/go-acme/lego/v5/internal/tester/acmewif"
	"github.com/go-acme/lego/v5/registration"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	issuerGitHub = "https://token.actions.githubusercontent.com"
	issuerOther  = "https://other.example.com"
	subjectMain  = "repo:org/app:ref:refs/heads/main"
)

// subjectPolicy allows an identifier only for the given subject.
func subjectPolicy(allowed map[string]string) acmewif.Policy {
	return func(identifier string, claims map[string]any) bool {
		return claims["sub"] == allowed[identifier]
	}
}

func setupWIFClient(t *testing.T, server *acmewif.Server, provider wif01.TokenProvider) *Client {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := NewConfig(mockUser{privatekey: key})
	config.CADirURL = server.URL + "/dir"
	config.HTTPClient = server.Client()
	config.Certificate.Timeout = 5 * time.Second

	client, err := NewClient(config)
	require.NoError(t, err)

	// Ephemeral account, no EAB.
	_, err = client.Registration.Register(t.Context(), registration.RegisterOptions{TermsOfServiceAgreed: true})
	require.NoError(t, err)

	require.NoError(t, client.Challenge.SetWIF01Provider(provider))

	return client
}

func obtain(t *testing.T, client *Client, domains ...string) (*certificate.Resource, error) {
	t.Helper()

	return client.Certificate.Obtain(t.Context(), certificate.ObtainRequest{
		Domains: domains,
		KeyType: certcrypto.EC256,
		Bundle:  true,
	})
}

func TestClient_WIF01_success(t *testing.T) {
	idp := acmewif.NewIdP(t, issuerGitHub, "k1")

	server := acmewif.NewServer(t, acmewif.Config{
		Issuers:          map[string]jose.JSONWebKeySet{idp.Issuer(): idp.KeySet()},
		MaxTokenLifetime: 10 * time.Minute,
		Policy: subjectPolicy(map[string]string{
			"a.example.com": subjectMain,
			"b.example.com": subjectMain,
		}),
	})

	client := setupWIFClient(t, server, idp.Provider(subjectMain))

	meta := client.GetServerMetadata()
	require.NotNil(t, meta.WIF)
	assert.Equal(t, []string{issuerGitHub}, meta.WIF.Issuers)

	res, err := obtain(t, client, "a.example.com", "b.example.com")
	require.NoError(t, err)

	block, _ := pem.Decode(res.Certificate)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, cert.DNSNames)

	// One fresh token per challenge.
	tokens := server.WIFTokens()
	require.Len(t, tokens, 2)
	assert.NotEqual(t, tokens[0], tokens[1])
}

func TestClient_WIF01_serverRejections(t *testing.T) {
	trusted := acmewif.NewIdP(t, issuerGitHub, "k1")

	testCases := []struct {
		desc     string
		provider wif01.TokenProvider
		expected string
	}{
		{
			desc:     "policy denies the subject",
			provider: trusted.Provider("repo:org/app:ref:refs/heads/feature"),
			expected: acme.WIFPolicyDeniedErrorType,
		},
		{
			desc:     "expired token",
			provider: trusted.Provider(subjectMain, acmewif.WithLifetime(-5*time.Minute)),
			expected: acme.BadWIFTokenErrorType,
		},
		{
			desc:     "lifetime above maxTokenLifetime",
			provider: trusted.Provider(subjectMain, acmewif.WithLifetime(time.Hour)),
			expected: acme.BadWIFTokenErrorType,
		},
		{
			desc:     "unknown kid for a trusted issuer",
			provider: acmewif.NewIdP(t, issuerGitHub, "k2").Provider(subjectMain),
			expected: acme.BadWIFTokenErrorType,
		},
		{
			desc:     "forged signature with a known kid",
			provider: acmewif.NewIdP(t, issuerGitHub, "k1").Provider(subjectMain),
			expected: acme.BadWIFTokenErrorType,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := acmewif.NewServer(t, acmewif.Config{
				Issuers:          map[string]jose.JSONWebKeySet{trusted.Issuer(): trusted.KeySet()},
				MaxTokenLifetime: 10 * time.Minute,
				Policy:           subjectPolicy(map[string]string{"a.example.com": subjectMain}),
			})

			client := setupWIFClient(t, server, test.provider)

			_, err := obtain(t, client, "a.example.com")
			require.ErrorContains(t, err, test.expected)

			assert.Len(t, server.WIFTokens(), 1)
		})
	}
}

func TestClient_WIF01_clientSideRejections(t *testing.T) {
	github := acmewif.NewIdP(t, issuerGitHub, "k1")
	other := acmewif.NewIdP(t, issuerOther, "k1")

	testCases := []struct {
		desc             string
		issuers          map[string]jose.JSONWebKeySet
		challengeIssuers []string
		provider         wif01.TokenProvider
		expected         string
	}{
		{
			desc:     "provider ignores the requested audience",
			issuers:  map[string]jose.JSONWebKeySet{issuerGitHub: github.KeySet()},
			provider: github.Provider(subjectMain, acmewif.WithFixedAudience("sts.amazonaws.com")),
			expected: "Audience Binding Value",
		},
		{
			desc:     "issuer not advertised in the directory",
			issuers:  map[string]jose.JSONWebKeySet{issuerGitHub: github.KeySet()},
			provider: other.Provider(subjectMain),
			expected: `issuer "https://other.example.com" is not accepted`,
		},
		{
			desc: "issuer excluded by the challenge issuers",
			issuers: map[string]jose.JSONWebKeySet{
				issuerGitHub: github.KeySet(),
				issuerOther:  other.KeySet(),
			},
			challengeIssuers: []string{issuerGitHub},
			provider:         other.Provider(subjectMain),
			expected:         `issuer "https://other.example.com" is not accepted`,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := acmewif.NewServer(t, acmewif.Config{
				Issuers:          test.issuers,
				ChallengeIssuers: test.challengeIssuers,
			})

			client := setupWIFClient(t, server, test.provider)

			_, err := obtain(t, client, "a.example.com")
			require.ErrorContains(t, err, test.expected)

			// The token must never be sent to the server.
			assert.Empty(t, server.WIFTokens())
		})
	}
}
