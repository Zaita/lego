package acmewif

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	audiencePrefix = "urn:ietf:params:acme:wif:"
	clockSkew      = 60 * time.Second
)

// Policy decides whether the token claims permit the identifier.
type Policy func(identifier string, claims map[string]any) bool

// Config the fake CA configuration.
type Config struct {
	// Issuers the trusted issuers and their keys.
	Issuers map[string]jose.JSONWebKeySet
	// ChallengeIssuers optionally narrows the issuers offered in the challenge objects.
	ChallengeIssuers []string
	// MaxTokenLifetime the maximum remaining validity accepted for a token (0: no limit).
	MaxTokenLifetime time.Duration
	// Policy the server policy (nil: allow everything).
	Policy Policy
}

type account struct {
	url string
	jwk *jose.JSONWebKey
}

type authorization struct {
	id         int
	account    string
	identifier acme.Identifier
	status     string
	expires    time.Time
	orderID    int

	chlgToken     string
	chlgStatus    string
	chlgError     *acme.ProblemDetails
	chlgValidated time.Time
}

type order struct {
	id          int
	account     string
	status      string
	identifiers []acme.Identifier
	authzIDs    []int
	certID      int
}

// Server an in-process ACME CA supporting only the wif-01 challenge.
type Server struct {
	*httptest.Server

	cfg Config

	mu        sync.Mutex
	nextID    int
	nonces    map[string]bool
	accounts  map[string]*account
	authzs    map[int]*authorization
	orders    map[int]*order
	certs     map[int][]byte
	seenJTI   map[string]bool
	wifTokens []string

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caPEM  []byte
}

// NewServer starts a fake CA.
func NewServer(t testing.TB, cfg Config) *Server {
	t.Helper()

	s := &Server{
		cfg:      cfg,
		nonces:   map[string]bool{},
		accounts: map[string]*account{},
		authzs:   map[int]*authorization{},
		orders:   map[int]*order{},
		certs:    map[int][]byte{},
		seenJTI:  map[string]bool{},
	}

	s.initCA(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", s.handleDirectory)
	mux.HandleFunc("HEAD /nonce", s.handleNonce)
	mux.HandleFunc("GET /nonce", s.handleNonce)
	mux.HandleFunc("POST /account", s.handleNewAccount)
	mux.HandleFunc("POST /order", s.handleNewOrder)
	mux.HandleFunc("POST /order/{id}", s.handleOrder)
	mux.HandleFunc("POST /authz/{id}", s.handleAuthz)
	mux.HandleFunc("POST /chlg/{id}", s.handleChallenge)
	mux.HandleFunc("POST /finalize/{id}", s.handleFinalize)
	mux.HandleFunc("POST /cert/{id}", s.handleCert)

	s.Server = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)

	return s
}

// WIFTokens returns all the wifToken values received, in order.
func (s *Server) WIFTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.wifTokens)
}

func (s *Server) initCA(t testing.TB) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmewif test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	s.caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	s.caKey = key
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (s *Server) url(format string, args ...any) string {
	return s.URL + fmt.Sprintf(format, args...)
}

func (s *Server) newID() int {
	s.nextID++
	return s.nextID
}

func (s *Server) addNonce(rw http.ResponseWriter) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	nonce := base64.RawURLEncoding.EncodeToString(b)

	s.nonces[nonce] = true

	rw.Header().Set("Replay-Nonce", nonce)
	rw.Header().Set("Cache-Control", "no-store")
}

func (s *Server) handleDirectory(rw http.ResponseWriter, _ *http.Request) {
	issuers := make([]string, 0, len(s.cfg.Issuers))
	for iss := range s.cfg.Issuers {
		issuers = append(issuers, iss)
	}

	slices.Sort(issuers)

	writeJSON(rw, http.StatusOK, acme.Directory{
		NewNonceURL:   s.url("/nonce"),
		NewAccountURL: s.url("/account"),
		NewOrderURL:   s.url("/order"),
		Meta: acme.Meta{
			WIF: &acme.WIFMeta{
				Issuers:          issuers,
				MaxTokenLifetime: int(s.cfg.MaxTokenLifetime.Seconds()),
			},
		},
	})
}

func (s *Server) handleNonce(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	if req.Method == http.MethodGet {
		rw.WriteHeader(http.StatusNoContent)
	}
}

// verifyJWS verifies the request JWS (RFC 8555 §6.2) and returns the payload and the account.
// When newAccount is true, the JWS must contain a "jwk" and the returned account is not yet stored.
// Must be called with s.mu held.
func (s *Server) verifyJWS(req *http.Request, newAccount bool) ([]byte, *account, *acme.ProblemDetails) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, nil, malformed("read body: %v", err)
	}

	jws, err := jose.ParseSigned(string(body), []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, nil, malformed("parse JWS: %v", err)
	}

	if len(jws.Signatures) != 1 {
		return nil, nil, malformed("JWS must have exactly one signature")
	}

	protected := jws.Signatures[0].Protected

	if !s.nonces[protected.Nonce] {
		return nil, nil, &acme.ProblemDetails{Type: acme.BadNonceErrorType, Detail: "unknown or reused nonce", HTTPStatus: http.StatusBadRequest}
	}

	delete(s.nonces, protected.Nonce)

	if u, _ := protected.ExtraHeaders[jose.HeaderKey("url")].(string); u != s.url("%s", req.URL.Path) {
		return nil, nil, malformed("JWS url %q does not match the request URL", u)
	}

	var acct *account

	switch {
	case newAccount:
		if protected.JSONWebKey == nil || protected.KeyID != "" {
			return nil, nil, malformed("newAccount requires a jwk and no kid")
		}

		acct = &account{jwk: protected.JSONWebKey}

	default:
		if protected.JSONWebKey != nil {
			return nil, nil, malformed("requests must use kid")
		}

		acct = s.accounts[protected.KeyID]
		if acct == nil {
			return nil, nil, &acme.ProblemDetails{Type: acme.AccountDoesNotExistErrorType, Detail: "unknown account", HTTPStatus: http.StatusBadRequest}
		}
	}

	payload, err := jws.Verify(acct.jwk)
	if err != nil {
		return nil, nil, malformed("JWS signature: %v", err)
	}

	return payload, acct, nil
}

func (s *Server) handleNewAccount(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	_, acct, prob := s.verifyJWS(req, true)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	acct.url = s.url("/acct/%d", s.newID())
	s.accounts[acct.url] = acct

	rw.Header().Set("Location", acct.url)
	writeJSON(rw, http.StatusCreated, acme.Account{Status: acme.StatusValid})
}

func (s *Server) handleNewOrder(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	payload, acct, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	var msg acme.Order

	err := json.Unmarshal(payload, &msg)
	if err != nil || len(msg.Identifiers) == 0 {
		writeProblem(rw, malformed("invalid order payload"))
		return
	}

	ord := &order{id: s.newID(), account: acct.url, status: acme.StatusPending, identifiers: msg.Identifiers}

	for _, ident := range msg.Identifiers {
		token := make([]byte, 16)
		_, _ = rand.Read(token)

		authz := &authorization{
			id:         s.newID(),
			account:    acct.url,
			identifier: ident,
			status:     acme.StatusPending,
			expires:    time.Now().Add(time.Hour),
			orderID:    ord.id,
			chlgToken:  base64.RawURLEncoding.EncodeToString(token),
			chlgStatus: acme.StatusPending,
		}

		s.authzs[authz.id] = authz
		ord.authzIDs = append(ord.authzIDs, authz.id)
	}

	s.orders[ord.id] = ord

	rw.Header().Set("Location", s.url("/order/%d", ord.id))
	writeJSON(rw, http.StatusCreated, s.orderJSON(ord))
}

func (s *Server) handleOrder(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	_, acct, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	ord := s.orders[pathID(req)]
	if ord == nil || ord.account != acct.url {
		writeProblem(rw, notFound())
		return
	}

	writeJSON(rw, http.StatusOK, s.orderJSON(ord))
}

func (s *Server) handleAuthz(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	payload, acct, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	authz := s.authzs[pathID(req)]
	if authz == nil || authz.account != acct.url {
		writeProblem(rw, notFound())
		return
	}

	// Deactivation (RFC 8555 §7.5.2).
	if len(payload) > 0 {
		var msg struct {
			Status string `json:"status"`
		}

		if json.Unmarshal(payload, &msg) == nil && msg.Status == acme.StatusDeactivated {
			authz.status = acme.StatusDeactivated
			s.updateOrderStatus(s.orders[authz.orderID])
		}
	}

	writeJSON(rw, http.StatusOK, s.authzJSON(authz))
}

func (s *Server) handleChallenge(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	payload, acct, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	authz := s.authzs[pathID(req)]
	if authz == nil || authz.account != acct.url {
		writeProblem(rw, notFound())
		return
	}

	rw.Header().Set("Link", fmt.Sprintf("<%s>;rel=\"up\"", s.url("/authz/%d", authz.id)))

	// POST-as-GET, or the challenge is no longer pending: return the current state.
	if len(payload) == 0 || authz.chlgStatus != acme.StatusPending {
		writeJSON(rw, http.StatusOK, s.challengeJSON(authz))
		return
	}

	var msg struct {
		WIFToken string `json:"wifToken"`
	}

	err := json.Unmarshal(payload, &msg)
	if err != nil || msg.WIFToken == "" {
		writeProblem(rw, malformed("wif-01 response must contain a wifToken"))
		return
	}

	s.wifTokens = append(s.wifTokens, msg.WIFToken)

	exp, prob := s.validateWIFToken(msg.WIFToken, authz, acct)
	if prob != nil {
		authz.chlgStatus = acme.StatusInvalid
		authz.chlgError = prob
		authz.status = acme.StatusInvalid
	} else {
		authz.chlgStatus = acme.StatusValid
		authz.chlgValidated = time.Now()
		authz.status = acme.StatusValid
		// The authorization MUST NOT outlive the token.
		authz.expires = exp
	}

	s.updateOrderStatus(s.orders[authz.orderID])

	writeJSON(rw, http.StatusOK, s.challengeJSON(authz))
}

// validateWIFToken implements the server validation steps of draft-rasmussen-acme-wif.
// The Audience Binding Value is recomputed independently of lego.
func (s *Server) validateWIFToken(raw string, authz *authorization, acct *account) (time.Time, *acme.ProblemDetails) {
	// 1-2. Compact JWS with an allowlisted asymmetric algorithm ("none" and MACs are rejected).
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "cannot parse token: %v", err)
	}

	var unverified jwt.Claims

	err = tok.UnsafeClaimsWithoutVerification(&unverified)
	if err != nil {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "cannot decode claims")
	}

	// 3. Exact issuer match against the configured issuers, narrowed by the challenge.
	keys, ok := s.cfg.Issuers[unverified.Issuer]
	if !ok || (len(s.cfg.ChallengeIssuers) > 0 && !slices.Contains(s.cfg.ChallengeIssuers, unverified.Issuer)) {
		return time.Time{}, wifProblem(acme.WIFIssuerNotAcceptedErrorType, "issuer %q is not accepted", unverified.Issuer)
	}

	// 4. Select the key by kid, from the configured issuer only.
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "missing kid")
	}

	candidates := keys.Key(kid)
	if len(candidates) == 0 {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "unknown kid %q", kid)
	}

	// 5. Signature.
	var (
		claims jwt.Claims
		all    map[string]any
	)

	err = tok.Claims(candidates[0].Key, &claims, &all)
	if err != nil {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "invalid signature")
	}

	// 6. Timing claims.
	now := time.Now()

	if claims.Expiry == nil {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "missing exp")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{Issuer: unverified.Issuer, Time: now}, clockSkew)
	if err != nil {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "timing claims: %v", err)
	}

	exp := claims.Expiry.Time()

	if s.cfg.MaxTokenLifetime > 0 && exp.Sub(now) > s.cfg.MaxTokenLifetime+clockSkew {
		return time.Time{}, wifProblem(acme.BadWIFTokenErrorType, "remaining validity exceeds maxTokenLifetime")
	}

	// 7. Audience Binding Value.
	thumbprint, err := acct.jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return time.Time{}, &acme.ProblemDetails{Type: acme.ServerInternalErrorType, Detail: err.Error(), HTTPStatus: http.StatusInternalServerError}
	}

	keyAuth := authz.chlgToken + "." + base64.RawURLEncoding.EncodeToString(thumbprint)
	sum := sha256.Sum256([]byte(keyAuth))
	abv := audiencePrefix + base64.RawURLEncoding.EncodeToString(sum[:])

	if !claims.Audience.Contains(abv) {
		return time.Time{}, wifProblem(acme.WIFAudienceMismatchErrorType, "audience does not contain the expected value")
	}

	// 8. Replay cache.
	if claims.ID != "" {
		if s.seenJTI[claims.ID] {
			return time.Time{}, wifProblem(acme.WIFTokenReplayedErrorType, "token already used")
		}

		s.seenJTI[claims.ID] = true
	}

	// 9. Policy.
	if s.cfg.Policy != nil && !s.cfg.Policy(authz.identifier.Value, all) {
		return time.Time{}, wifProblem(acme.WIFPolicyDeniedErrorType, "claims do not permit %q (sub=%v)", authz.identifier.Value, all["sub"])
	}

	return exp, nil
}

func (s *Server) handleFinalize(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	payload, acct, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	ord := s.orders[pathID(req)]
	if ord == nil || ord.account != acct.url {
		writeProblem(rw, notFound())
		return
	}

	if ord.status != acme.StatusReady {
		writeProblem(rw, &acme.ProblemDetails{Type: errNS + "orderNotReady", Detail: "order is " + ord.status, HTTPStatus: http.StatusForbidden})
		return
	}

	var msg acme.CSRMessage

	err := json.Unmarshal(payload, &msg)
	if err != nil {
		writeProblem(rw, malformed("invalid finalize payload"))
		return
	}

	der, err := base64.RawURLEncoding.DecodeString(msg.Csr)
	if err != nil {
		writeProblem(rw, badCSR("decode: %v", err))
		return
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		writeProblem(rw, badCSR("parse: %v", err))
		return
	}

	err = csr.CheckSignature()
	if err != nil {
		writeProblem(rw, badCSR("signature: %v", err))
		return
	}

	// RFC 8555 §7.4: the CSR names must match the order identifiers.
	var expected []string
	for _, ident := range ord.identifiers {
		expected = append(expected, ident.Value)
	}

	names := slices.Clone(csr.DNSNames)
	slices.Sort(names)
	slices.Sort(expected)

	if !slices.Equal(names, expected) {
		writeProblem(rw, badCSR("CSR names %v do not match the order identifiers %v", names, expected))
		return
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(s.newID())),
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		writeProblem(rw, &acme.ProblemDetails{Type: acme.ServerInternalErrorType, Detail: err.Error(), HTTPStatus: http.StatusInternalServerError})
		return
	}

	ord.certID = s.newID()
	s.certs[ord.certID] = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), s.caPEM...)
	ord.status = acme.StatusValid

	rw.Header().Set("Location", s.url("/order/%d", ord.id))
	writeJSON(rw, http.StatusOK, s.orderJSON(ord))
}

func (s *Server) handleCert(rw http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addNonce(rw)

	_, _, prob := s.verifyJWS(req, false)
	if prob != nil {
		writeProblem(rw, prob)
		return
	}

	chain, ok := s.certs[pathID(req)]
	if !ok {
		writeProblem(rw, notFound())
		return
	}

	rw.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = rw.Write(chain)
}

func (s *Server) updateOrderStatus(ord *order) {
	if ord == nil || ord.status != acme.StatusPending {
		return
	}

	ready := true

	for _, id := range ord.authzIDs {
		switch s.authzs[id].status {
		case acme.StatusValid:
		case acme.StatusPending:
			ready = false
		default:
			ord.status = acme.StatusInvalid
			return
		}
	}

	if ready {
		ord.status = acme.StatusReady
	}
}

func (s *Server) orderJSON(ord *order) acme.Order {
	o := acme.Order{
		Status:      ord.status,
		Identifiers: ord.identifiers,
		Finalize:    s.url("/finalize/%d", ord.id),
	}

	for _, id := range ord.authzIDs {
		o.Authorizations = append(o.Authorizations, s.url("/authz/%d", id))
	}

	if ord.certID != 0 {
		o.Certificate = s.url("/cert/%d", ord.certID)
	}

	return o
}

func (s *Server) authzJSON(authz *authorization) acme.Authorization {
	return acme.Authorization{
		Status:     authz.status,
		Expires:    authz.expires,
		Identifier: authz.identifier,
		Challenges: []acme.Challenge{s.challengeJSON(authz)},
	}
}

func (s *Server) challengeJSON(authz *authorization) acme.Challenge {
	return acme.Challenge{
		Type:      "wif-01",
		URL:       s.url("/chlg/%d", authz.id),
		Status:    authz.chlgStatus,
		Token:     authz.chlgToken,
		Issuers:   s.cfg.ChallengeIssuers,
		Error:     authz.chlgError,
		Validated: authz.chlgValidated,
	}
}

const errNS = "urn:ietf:params:acme:error:"

func pathID(req *http.Request) int {
	id, _ := strconv.Atoi(req.PathValue("id"))
	return id
}

func malformed(format string, args ...any) *acme.ProblemDetails {
	return &acme.ProblemDetails{Type: acme.MalformedErrorType, Detail: fmt.Sprintf(format, args...), HTTPStatus: http.StatusBadRequest}
}

func badCSR(format string, args ...any) *acme.ProblemDetails {
	return &acme.ProblemDetails{Type: acme.BadCSRErrorType, Detail: fmt.Sprintf(format, args...), HTTPStatus: http.StatusBadRequest}
}

func notFound() *acme.ProblemDetails {
	return &acme.ProblemDetails{Type: acme.MalformedErrorType, Detail: "not found", HTTPStatus: http.StatusNotFound}
}

func wifProblem(typ, format string, args ...any) *acme.ProblemDetails {
	return &acme.ProblemDetails{Type: typ, Detail: fmt.Sprintf(format, args...), HTTPStatus: http.StatusForbidden}
}

func writeProblem(rw http.ResponseWriter, prob *acme.ProblemDetails) {
	rw.Header().Set("Content-Type", "application/problem+json")
	rw.WriteHeader(prob.HTTPStatus)
	_ = json.NewEncoder(rw).Encode(prob)
}

func writeJSON(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}
