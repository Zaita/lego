// Package acmewif provides an in-process fake ACME CA and identity provider
// to test the wif-01 challenge (draft-rasmussen-acme-wif) end-to-end.
package acmewif

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// DefaultTokenLifetime the default lifetime of minted tokens.
const DefaultTokenLifetime = 5 * time.Minute

// IdP a fake workload identity provider issuing ES256 JWTs.
type IdP struct {
	t      testing.TB
	issuer string
	kid    string
	key    *ecdsa.PrivateKey
}

// NewIdP creates a fake identity provider.
func NewIdP(t testing.TB, issuer, kid string) *IdP {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &IdP{t: t, issuer: issuer, kid: kid, key: key}
}

// Issuer returns the issuer identifier.
func (i *IdP) Issuer() string {
	return i.issuer
}

// KeySet returns the public keys of the identity provider.
func (i *IdP) KeySet() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: i.key.Public(), KeyID: i.kid, Algorithm: string(jose.ES256), Use: "sig"},
	}}
}

// MintOptions the content of a minted token.
type MintOptions struct {
	Subject  string
	Audience []string
	// Lifetime the token lifetime from now; negative values produce an already expired token.
	// Defaults to DefaultTokenLifetime.
	Lifetime time.Duration
	// NoKID omits the "kid" header.
	NoKID bool
	// Extra additional claims.
	Extra map[string]any
}

// Mint issues a signed token.
func (i *IdP) Mint(opts MintOptions) string {
	i.t.Helper()

	lifetime := opts.Lifetime
	if lifetime == 0 {
		lifetime = DefaultTokenLifetime
	}

	now := time.Now()
	exp := now.Add(lifetime)

	iat := now
	if lifetime < 0 {
		iat = exp.Add(-DefaultTokenLifetime)
	}

	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: i.key, KeyID: i.kid}}
	if opts.NoKID {
		signingKey.Key = i.key
	}

	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		i.t.Fatal(err)
	}

	jti := make([]byte, 16)
	_, _ = rand.Read(jti)

	claims := jwt.Claims{
		Issuer:   i.issuer,
		Subject:  opts.Subject,
		Audience: opts.Audience,
		Expiry:   jwt.NewNumericDate(exp),
		IssuedAt: jwt.NewNumericDate(iat),
		ID:       hex.EncodeToString(jti),
	}

	builder := jwt.Signed(signer).Claims(claims)
	if opts.Extra != nil {
		builder = builder.Claims(opts.Extra)
	}

	token, err := builder.Serialize()
	if err != nil {
		i.t.Fatal(err)
	}

	return token
}

// Provider returns a token provider (implements wif01.TokenProvider) minting tokens for the subject.
func (i *IdP) Provider(subject string, opts ...ProviderOption) *Provider {
	p := &Provider{idp: i, subject: subject}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithFixedAudience simulates a platform ignoring the requested audience.
func WithFixedAudience(aud string) ProviderOption {
	return func(p *Provider) { p.fixedAudience = aud }
}

// WithLifetime sets the lifetime of the minted tokens.
func WithLifetime(lifetime time.Duration) ProviderOption {
	return func(p *Provider) { p.lifetime = lifetime }
}

// Provider a token provider backed by a fake IdP.
type Provider struct {
	idp           *IdP
	subject       string
	fixedAudience string
	lifetime      time.Duration
}

// Token mints a token with the requested audience.
func (p *Provider) Token(_ context.Context, audience string) (string, error) {
	if p.fixedAudience != "" {
		audience = p.fixedAudience
	}

	return p.idp.Mint(MintOptions{
		Subject:  p.subject,
		Audience: []string{audience},
		Lifetime: p.lifetime,
	}), nil
}
