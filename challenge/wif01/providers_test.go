package wif01

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubActionsProvider_Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "Bearer secret", req.Header.Get("Authorization"))
		assert.Equal(t, "1.0", req.URL.Query().Get("api-version"))

		if req.URL.Query().Get("audience") != "urn:ietf:params:acme:wif:abc" {
			http.Error(rw, "bad audience", http.StatusBadRequest)
			return
		}

		_, _ = rw.Write([]byte(`{"value":"a.b.c"}`))
	}))
	t.Cleanup(server.Close)

	t.Setenv(EnvGitHubRequestURL, server.URL+"/token?api-version=1.0")
	t.Setenv(EnvGitHubRequestToken, "secret")

	provider, err := NewGitHubActionsProvider()
	require.NoError(t, err)

	token, err := provider.Token(t.Context(), "urn:ietf:params:acme:wif:abc")
	require.NoError(t, err)

	assert.Equal(t, "a.b.c", token)
}

func TestNewGitHubActionsProvider_missingEnv(t *testing.T) {
	t.Setenv(EnvGitHubRequestURL, "")
	t.Setenv(EnvGitHubRequestToken, "")

	_, err := NewGitHubActionsProvider()
	require.Error(t, err)
}

func TestCommandProvider_Token(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires sh")
	}

	script := filepath.Join(t.TempDir(), "token.sh")

	err := os.WriteFile(script, []byte("printf '%s\\n' \"$LEGO_WIF_AUDIENCE\"\n"), 0o600)
	require.NoError(t, err)

	provider, err := NewCommandProvider("sh " + script)
	require.NoError(t, err)

	token, err := provider.Token(t.Context(), "urn:ietf:params:acme:wif:abc")
	require.NoError(t, err)

	assert.Equal(t, "urn:ietf:params:acme:wif:abc", token)
}

func TestNewCommandProvider_empty(t *testing.T) {
	_, err := NewCommandProvider("  ")
	require.Error(t, err)
}
