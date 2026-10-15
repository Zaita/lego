// Package wif01 implements the wif-01 challenge (ACME Workload Identity Federation).
// https://datatracker.ietf.org/doc/draft-rasmussen-acme-wif/
//
// IMPORTANT: this package implements an Internet-Draft and may change without notice.
package wif01

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/log"
)

// audiencePrefix the prefix of the Audience Binding Value.
const audiencePrefix = "urn:ietf:params:acme:wif:"

// ValidateFunc validates a challenge with the ACME server by sending the given payload.
type ValidateFunc func(ctx context.Context, core *api.Core, domain string, chlng acme.Challenge, payload any) error

// TokenProvider obtains a WIF Token (a JWT) from the workload's execution platform.
type TokenProvider interface {
	// Token returns a WIF Token whose "aud" claim contains the given audience.
	// The token MUST be freshly issued and SHOULD have the shortest lifetime the platform allows.
	Token(ctx context.Context, audience string) (string, error)
}

// Payload the wif-01 challenge response payload.
type Payload struct {
	WIFToken string `json:"wifToken"`
}

// Challenge implements the wif-01 challenge.
type Challenge struct {
	core     *api.Core
	validate ValidateFunc
	provider TokenProvider
}

// NewChallenge creates a wif-01 challenge.
func NewChallenge(core *api.Core, validate ValidateFunc, provider TokenProvider) *Challenge {
	return &Challenge{
		core:     core,
		validate: validate,
		provider: provider,
	}
}

// Solve obtains a WIF Token bound to the challenge and the account key, then sends it to the ACME server.
func (c *Challenge) Solve(ctx context.Context, authz acme.Authorization) error {
	domain := challenge.GetTargetedDomain(authz)

	log.Info("wif01: trying to solve the challenge.", log.DomainAttr(domain))

	chlng, err := challenge.FindChallenge(challenge.WIF01, authz)
	if err != nil {
		return err
	}

	if chlng.Token == "" {
		return errors.New("wif01: missing token in challenge object")
	}

	keyAuth, err := c.core.GetKeyAuthorization(chlng.Token)
	if err != nil {
		return fmt.Errorf("wif01: %w", err)
	}

	audience := AudienceBindingValue(keyAuth)

	token, err := c.provider.Token(ctx, audience)
	if err != nil {
		return fmt.Errorf("wif01: get WIF token: %w", err)
	}

	err = checkToken(token, audience, acceptedIssuers(chlng, c.core.GetDirectory()))
	if err != nil {
		return fmt.Errorf("wif01: %w", err)
	}

	return c.validate(ctx, c.core, domain, chlng, Payload{WIFToken: token})
}

// AudienceBindingValue computes the Audience Binding Value (ABV) from a key authorization.
func AudienceBindingValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))

	return audiencePrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// acceptedIssuers returns the issuers accepted for the challenge:
// the challenge "issuers" if present, otherwise the directory "wif" metadata issuers.
func acceptedIssuers(chlng acme.Challenge, dir acme.Directory) []string {
	if len(chlng.Issuers) > 0 {
		return chlng.Issuers
	}

	if dir.Meta.WIF != nil {
		return dir.Meta.WIF.Issuers
	}

	return nil
}

type claims struct {
	Issuer   string   `json:"iss"`
	Audience audience `json:"aud"`
}

// audience the "aud" claim: either a single string or an array of strings (RFC 7519 §4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}

	*a = multi

	return nil
}

// checkToken performs client-side sanity checks to fail early with a clear message.
// It does not verify the signature: this is the ACME server's responsibility.
// Errors never include the token itself.
func checkToken(token, expectedAudience string, issuers []string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("the WIF token is not a JWS compact serialization")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("the WIF token payload is not base64url encoded")
	}

	var cl claims

	err = json.Unmarshal(raw, &cl)
	if err != nil {
		return errors.New("the WIF token payload is not a valid JWT claims set")
	}

	if !slices.Contains(cl.Audience, expectedAudience) {
		return errors.New("the WIF token audience does not contain the Audience Binding Value: the token provider must support custom audiences")
	}

	if len(issuers) > 0 && !slices.Contains(issuers, cl.Issuer) {
		return fmt.Errorf("the WIF token issuer %q is not accepted by the server (accepted: %s)", cl.Issuer, strings.Join(issuers, ", "))
	}

	return nil
}
