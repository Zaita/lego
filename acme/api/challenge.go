package api

import (
	"context"
	"errors"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api/internal/sender"
)

type ChallengeService service

// New Creates a challenge.
func (c *ChallengeService) New(ctx context.Context, chlgURL string) (acme.ExtendedChallenge, error) {
	// Challenge initiation is done by sending a JWS payload containing the trivial JSON object `{}`.
	// We use an empty struct instance as the postJSON payload here to achieve this result.
	return c.NewWithPayload(ctx, chlgURL, struct{}{})
}

// NewWithPayload Creates a challenge by sending the given payload.
// Some challenge types (e.g. wif-01) define a non-empty response payload.
func (c *ChallengeService) NewWithPayload(ctx context.Context, chlgURL string, payload any) (acme.ExtendedChallenge, error) {
	if chlgURL == "" {
		return acme.ExtendedChallenge{}, errors.New("challenge[new]: empty URL")
	}

	var chlng acme.ExtendedChallenge

	resp, err := c.core.post(ctx, chlgURL, payload, &chlng)
	if err != nil {
		return acme.ExtendedChallenge{}, err
	}

	chlng.AuthorizationURL = sender.GetLink(resp.Header, "up")
	chlng.RetryAfter = sender.GetRetryAfter(resp)

	return chlng, nil
}

// Get Gets a challenge.
func (c *ChallengeService) Get(ctx context.Context, chlgURL string) (acme.ExtendedChallenge, error) {
	if chlgURL == "" {
		return acme.ExtendedChallenge{}, errors.New("challenge[get]: empty URL")
	}

	var chlng acme.ExtendedChallenge

	resp, err := c.core.postAsGet(ctx, chlgURL, &chlng)
	if err != nil {
		return acme.ExtendedChallenge{}, err
	}

	chlng.AuthorizationURL = sender.GetLink(resp.Header, "up")
	chlng.RetryAfter = sender.GetRetryAfter(resp)

	return chlng, nil
}
