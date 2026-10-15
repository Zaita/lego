package wif01

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Environment variables used by GitHub Actions to request an OIDC ID token.
// https://docs.github.com/en/actions/reference/security/oidc
const (
	EnvGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// EnvAudience the environment variable containing the audience passed to the command of the CommandProvider.
const EnvAudience = "LEGO_WIF_AUDIENCE"

var _ TokenProvider = (*GitHubActionsProvider)(nil)

// GitHubActionsProvider obtains WIF Tokens from the GitHub Actions OIDC provider.
// The workflow requires the `id-token: write` permission.
type GitHubActionsProvider struct {
	requestURL   string
	requestToken string

	HTTPClient *http.Client
}

// NewGitHubActionsProvider creates a GitHubActionsProvider from the GitHub Actions environment.
func NewGitHubActionsProvider() (*GitHubActionsProvider, error) {
	requestURL := os.Getenv(EnvGitHubRequestURL)
	requestToken := os.Getenv(EnvGitHubRequestToken)

	if requestURL == "" || requestToken == "" {
		return nil, fmt.Errorf("github: %s and %s must be set (does the workflow have the 'id-token: write' permission?)",
			EnvGitHubRequestURL, EnvGitHubRequestToken)
	}

	return &GitHubActionsProvider{
		requestURL:   requestURL,
		requestToken: requestToken,
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Token requests an ID token with the given audience.
func (p *GitHubActionsProvider) Token(ctx context.Context, audience string) (string, error) {
	endpoint, err := url.Parse(p.requestURL)
	if err != nil {
		return "", fmt.Errorf("github: parse request URL: %w", err)
	}

	query := endpoint.Query()
	query.Set("audience", audience)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("github: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: request ID token: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: request ID token: unexpected status code %d", resp.StatusCode)
	}

	var result struct {
		Value string `json:"value"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("github: decode ID token response: %w", err)
	}

	if result.Value == "" {
		return "", errors.New("github: empty ID token")
	}

	return result.Value, nil
}

var _ TokenProvider = (*CommandProvider)(nil)

// CommandProvider obtains WIF Tokens by running an external command.
// The audience is passed to the command through the LEGO_WIF_AUDIENCE environment variable,
// and the command must print the token on its standard output.
type CommandProvider struct {
	name string
	args []string
}

// NewCommandProvider creates a CommandProvider.
func NewCommandProvider(command string) (*CommandProvider, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, errors.New("command: empty command")
	}

	return &CommandProvider{name: fields[0], args: fields[1:]}, nil
}

// Token runs the command to obtain a token with the given audience.
func (p *CommandProvider) Token(ctx context.Context, audience string) (string, error) {
	cmd := exec.CommandContext(ctx, p.name, p.args...)
	cmd.Env = append(os.Environ(), EnvAudience+"="+audience)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	token := strings.TrimSpace(stdout.String())
	if token == "" {
		return "", errors.New("command: empty output")
	}

	return token, nil
}
