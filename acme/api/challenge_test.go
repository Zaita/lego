package api

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeService_NewWithPayload(t *testing.T) {
	// small value keeps test fast
	privateKey, errK := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, errK, "Could not generate test key")

	var bodies []string

	server := tester.MockACMEServer().
		Route("POST /chlg",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				body, err := readSignedBody(req, privateKey)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusBadRequest)
					return
				}

				bodies = append(bodies, string(body))

				servermock.JSONEncode(acme.Challenge{Type: "wif-01", Status: acme.StatusValid}).ServeHTTP(rw, req)
			})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	chlng, err := core.Challenges.New(t.Context(), server.URL+"/chlg")
	require.NoError(t, err)
	assert.Equal(t, acme.StatusValid, chlng.Status)

	_, err = core.Challenges.NewWithPayload(t.Context(), server.URL+"/chlg", map[string]string{"wifToken": "a.b.c"})
	require.NoError(t, err)

	assert.Equal(t, []string{`{}`, `{"wifToken":"a.b.c"}`}, bodies)
}
