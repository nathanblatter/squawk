// Package client is the Go SDK for squawk.nathanblatter.com. It has no
// dependencies beyond the standard library so any service can pull it in
// without inheriting the server's AWS modules.
//
// Two halves:
//
//   - Verifier checks tokens presented TO your service. It fetches the JWKS
//     once, caches it, and refreshes when it meets an unknown key id.
//   - Client obtains tokens FOR your service from its credential and caches
//     them until shortly before expiry.
//
// Typical wiring:
//
//	v := client.NewVerifier("https://squawk.nathanblatter.com", "auth")
//	mux.Handle("/api/", client.RequireToken(v)(apiHandler))
//
//	c := client.NewClient("https://squawk.nathanblatter.com", serviceID, credential)
//	tok, err := c.Token(ctx)
package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrMalformed  = errors.New("auth: malformed token")
	ErrSignature  = errors.New("auth: bad signature")
	ErrUnknownKey = errors.New("auth: unknown signing key")
	ErrExpired    = errors.New("auth: token expired")
	ErrIssuer     = errors.New("auth: wrong issuer")
	ErrAudience   = errors.New("auth: wrong audience")
	ErrCredential = errors.New("auth: credential rejected")
)

// Claims is the verified content of a token.
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
	Email    string `json:"email,omitempty"`
	// PreferredUsername is present on accounts that sign in by name (the
	// password method); such accounts may have no email at all.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// EmailVerified is true once the user's address was proven.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Org and OrgRole are present when the token was issued in an org
	// context: the org id and the subject's role in it (admin | member).
	Org      string `json:"org,omitempty"`
	OrgRole  string `json:"org_role,omitempty"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"`
}

// UserID returns the user id when the token belongs to an end user
// (subject "usr:<id>").
func (c Claims) UserID() (string, bool) { return strings.CutPrefix(c.Subject, "usr:") }

// IsOwner reports whether the token was issued to the owner.
func (c Claims) IsOwner() bool { return c.Subject == "owner" }

// InOrg reports whether the token carries the given org context.
func (c Claims) InOrg(orgID string) bool { return orgID != "" && c.Org == orgID }

// IsOrgAdmin reports whether the token's org role is admin.
func (c Claims) IsOrgAdmin() bool { return c.Org != "" && c.OrgRole == "admin" }

// Scopes splits the space-separated scope claim.
func (c Claims) Scopes() []string { return strings.Fields(c.Scope) }

// HasScope reports whether the token carries a scope.
func (c Claims) HasScope(s string) bool {
	for _, got := range c.Scopes() {
		if got == s {
			return true
		}
	}
	return false
}

// ServiceID returns the service id when the token belongs to a service
// (subject "svc:<id>").
func (c Claims) ServiceID() (string, bool) { return strings.CutPrefix(c.Subject, "svc:") }

// ExpiresAt is the expiry as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Expires, 0) }

// ── Verifier ───────────────────────────────────────────────────────────────

// Verifier validates ES256 tokens against the issuer's JWKS.
type Verifier struct {
	issuer   string
	audience string
	resource string
	http     *http.Client
	now      func() time.Time
	ttl      time.Duration

	mu          sync.Mutex
	keys        map[string]*ecdsa.PublicKey
	fetchedAt   time.Time
	lastRefresh time.Time
}

// VerifierOption tunes a Verifier.
type VerifierOption func(*Verifier)

// WithHTTPClient replaces the HTTP client used to fetch the JWKS.
func WithHTTPClient(h *http.Client) VerifierOption { return func(v *Verifier) { v.http = h } }

// WithJWKSTTL sets how long a fetched key set is trusted before a routine
// refresh (default 10 minutes). Unknown kids trigger an immediate refresh
// regardless, at most once a minute.
func WithJWKSTTL(d time.Duration) VerifierOption { return func(v *Verifier) { v.ttl = d } }

// NewVerifier creates a verifier for tokens issued by issuer and addressed to
// audience. For calls to the auth API itself the audience is "auth"; for your
// own service it is your service id.
func NewVerifier(issuer, audience string, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		issuer: strings.TrimRight(issuer, "/"), audience: audience,
		http: &http.Client{Timeout: 10 * time.Second}, now: time.Now, ttl: 10 * time.Minute,
		keys: map[string]*ecdsa.PublicKey{},
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify checks the token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	hdrRaw, err := b64dec(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var hdr struct{ Alg, Kid string }
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil || hdr.Alg != "ES256" || hdr.Kid == "" {
		return Claims{}, ErrMalformed
	}
	pub, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	sig, err := b64dec(parts[2])
	if err != nil || len(sig) != 64 {
		return Claims{}, ErrMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return Claims{}, ErrSignature
	}
	bodyRaw, err := b64dec(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var c Claims
	if err := json.Unmarshal(bodyRaw, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	now := v.now().Unix()
	if c.Expires <= now {
		return Claims{}, ErrExpired
	}
	if c.Issuer != v.issuer {
		return Claims{}, ErrIssuer
	}
	if c.Audience != v.audience {
		return Claims{}, ErrAudience
	}
	return c, nil
}

// key returns the public key for kid, fetching or refreshing the JWKS as needed.
func (v *Verifier) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	stale := v.fetchedAt.IsZero() || now.Sub(v.fetchedAt) > v.ttl
	if pub, ok := v.keys[kid]; ok && !stale {
		return pub, nil
	}
	// Unknown kid or stale set: refresh, but never hammer the issuer.
	if stale || now.Sub(v.lastRefresh) > time.Minute {
		if err := v.refresh(ctx); err != nil {
			if pub, ok := v.keys[kid]; ok {
				return pub, nil // serve the cached key through a transient outage
			}
			return nil, err
		}
	}
	if pub, ok := v.keys[kid]; ok {
		return pub, nil
	}
	return nil, ErrUnknownKey
}

func (v *Verifier) refresh(ctx context.Context) error {
	v.lastRefresh = v.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: fetch jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct{ Kty, Crv, Kid, X, Y string }
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("auth: decode jwks: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		x, errX := b64dec(k.X)
		y, errY := b64dec(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		point := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("auth: jwks contained no usable keys")
	}
	v.keys = keys
	v.fetchedAt = v.now()
	return nil
}

// ── middleware ─────────────────────────────────────────────────────────────

type claimsKey struct{}

// RequireToken rejects requests without a valid bearer token and stores the
// claims in the request context (see FromContext). Use RequireScope on top
// when an endpoint needs a particular scope.
//
// When the Verifier was given a resource (WithResource), the 401 carries the
// resource_metadata hint the MCP authorization spec expects, so a connector
// client can discover the authorization server on its own.
func RequireToken(v *Verifier) func(http.Handler) http.Handler {
	challenge := `Bearer realm="auth"`
	if v.resource != "" {
		challenge += `, resource_metadata="` + v.resourceMetadataURL() + `"`
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			raw = strings.TrimSpace(raw)
			if !ok || raw == "" {
				w.Header().Set("WWW-Authenticate", challenge)
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			c, err := v.Verify(r.Context(), raw)
			if err != nil {
				w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, c)))
		})
	}
}

// WithResource declares the RFC 8707 resource identifier this service is
// known by at Squawk (for example "https://finforge.nathanblatter.com/mcp").
// It enables ProtectedResourceMetadata and the resource_metadata hint on 401s.
func WithResource(resource string) VerifierOption {
	return func(v *Verifier) { v.resource = strings.TrimRight(resource, "/") }
}

// resourceMetadataURL is where this service publishes its RFC 9728 document:
// the well-known path on the resource's own origin, suffixed with its path.
func (v *Verifier) resourceMetadataURL() string {
	u, err := url.Parse(v.resource)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + u.Path
}

// ProtectedResourceMetadata serves the RFC 9728 document for this service.
// Mount it at the path resourceMetadataURL() names, e.g.
//
//	mux.Handle("GET /.well-known/oauth-protected-resource/mcp", client.ProtectedResourceMetadata(v, "FinForge", []string{"read"}))
func ProtectedResourceMetadata(v *Verifier, name string, scopes []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 v.resource,
			"authorization_servers":    []string{v.issuer},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         scopes,
			"resource_name":            name,
		})
	})
}

// RequireScope must run after RequireToken. It answers 403 when the token
// lacks the scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := FromContext(r.Context())
			if !ok || !c.HasScope(scope) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="auth", error="insufficient_scope", scope="`+scope+`"`)
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FromContext returns the claims RequireToken stored.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok
}

// ── Client ─────────────────────────────────────────────────────────────────

// Client exchanges a service credential for tokens and caches them.
type Client struct {
	issuer, serviceID, credential string
	http                          *http.Client
	now                           func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewClient prepares a client for one service credential. Nothing is fetched
// until Token is called.
func NewClient(issuer, serviceID, credential string) *Client {
	return &Client{
		issuer: strings.TrimRight(issuer, "/"), serviceID: serviceID, credential: credential,
		http: &http.Client{Timeout: 10 * time.Second}, now: time.Now,
	}
}

// Token returns a valid service token, exchanging the credential only when
// the cached one is within 30 seconds of expiry.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Add(30*time.Second).Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.serviceID}, "client_secret": {c.credential}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+"/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", ErrCredential
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth: token request: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("auth: token response malformed")
	}
	c.token = out.AccessToken
	c.expires = c.now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return c.token, nil
}

// Authorize adds a fresh bearer token to an outgoing request.
func (c *Client) Authorize(ctx context.Context, req *http.Request) error {
	tok, err := c.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func b64dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
