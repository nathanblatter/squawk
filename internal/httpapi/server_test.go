package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/squawk/internal/core"
	"github.com/nathanblatter/squawk/internal/oauth"
	"github.com/nathanblatter/squawk/internal/owner"
	"github.com/nathanblatter/squawk/internal/ratelimit"
	"github.com/nathanblatter/squawk/internal/signer"
	"github.com/nathanblatter/squawk/internal/store"
	"github.com/nathanblatter/squawk/internal/users"

	"golang.org/x/crypto/bcrypt"
)

const adminToken = "test-admin-token"

func newServer(t *testing.T) *httptest.Server {
	ts, _ := newServerWithStore(t, "https://auth.test")
	return ts
}

func newServerWithStore(t *testing.T, issuer string) (*httptest.Server, *store.Memory) {
	t.Helper()
	s, err := signer.NewLocal("t1")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := signer.NewRing(s)
	if err != nil {
		t.Fatal(err)
	}
	mem := store.NewMemory()
	c := core.New(mem, ring, issuer)
	own, err := owner.New(mem, issuer)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Core: c, Owner: own, Limit: ratelimit.New(mem), OAuth: oauth.New(c), Users: users.New(mem), AdminTokenHash: core.HashSecret(adminToken), Version: "test"}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	lastServer = srv
	return ts, mem
}

// lastServer lets a test reach into the most recently built Server (to
// install a fake Google provider).
var lastServer *Server

func do(t *testing.T, method, rawURL, auth, contentType string, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("non-json body (%d): %s", resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, out
}

func TestEndToEnd(t *testing.T) {
	ts := newServer(t)
	admin := "Bearer " + adminToken

	// Public endpoints.
	if code, body := do(t, "GET", ts.URL+"/health", "", "", ""); code != 200 || body["status"] != "ok" {
		t.Fatalf("health: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/.well-known/jwks.json", "", "", ""); code != 200 || len(body["keys"].([]any)) != 1 {
		t.Fatalf("jwks: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/.well-known/openid-configuration", "", "", ""); code != 200 || body["issuer"] != "https://auth.test" {
		t.Fatalf("discovery: %d %v", code, body)
	}

	// Admin gate.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "", "", ""); code != 401 {
		t.Fatalf("no admin token: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer wrong", "", ""); code != 401 {
		t.Fatalf("wrong admin token: %d", code)
	}

	// Register a service and mint a credential.
	code, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"FinForge","slug":"finforge"}`)
	if code != 201 {
		t.Fatalf("create service: %d %v", code, svc)
	}
	id := svc["id"].(string)
	if code, body := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Dup","slug":"finforge"}`); code != 409 {
		t.Fatalf("dup slug: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"X","slug":"ok","extra":1}`); code != 400 {
		t.Fatalf("unknown field: %d %v", code, body)
	}
	code, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	if code != 201 || cred["credential"] == nil {
		t.Fatalf("mint: %d %v", code, cred)
	}
	raw := cred["credential"].(string)
	credID := cred["id"].(string)

	// Listing never includes the raw credential or its hash.
	code, list := do(t, "GET", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	if code != 200 {
		t.Fatalf("list creds: %d", code)
	}
	first := list["credentials"].([]any)[0].(map[string]any)
	if _, leak := first["credential"]; leak {
		t.Fatal("raw credential leaked in list")
	}
	if _, leak := first["hash"]; leak {
		t.Fatal("hash leaked in list")
	}
	if first["last4"] != raw[len(raw)-4:] {
		t.Fatalf("last4 mismatch: %v", first["last4"])
	}

	// Token exchange, form body.
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {raw}}
	code, tok := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 || tok["token_type"] != "Bearer" {
		t.Fatalf("token: %d %v", code, tok)
	}
	access := tok["access_token"].(string)

	// Token exchange, basic auth.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/token", strings.NewReader("grant_type=client_credentials"))
	req.SetBasicAuth(id, raw)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("basic auth token: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong grant / bad secret.
	if code, body := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", "grant_type=password"); code != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("bad grant: %d %v", code, body)
	}
	form.Set("client_secret", "nbk_bad")
	if code, body := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 401 || body["error"] != "invalid_client" {
		t.Fatalf("bad secret: %d %v", code, body)
	}

	// Service token works on /v1/me; admin token does not; garbage does not.
	if code, me := do(t, "GET", ts.URL+"/v1/me", "Bearer "+access, "", ""); code != 200 || me["service_id"] != id {
		t.Fatalf("me: %d %v", code, me)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/me", admin, "", ""); code != 401 {
		t.Fatalf("admin token on /v1/me: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/me", "Bearer x.y.z", "", ""); code != 401 {
		t.Fatalf("garbage on /v1/me: %d", code)
	}
	// Service token must not open admin.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer "+access, "", ""); code != 401 {
		t.Fatalf("service token on admin: %d", code)
	}

	// Revoke, then the credential is dead but the already-issued token is still
	// valid until it expires (documented trade-off of stateless tokens).
	if code, _ := do(t, "DELETE", ts.URL+"/admin/services/"+id+"/credentials/"+credID, admin, "", ""); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	form.Set("client_secret", raw)
	if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 401 {
		t.Fatalf("revoked credential exchanged: %d", code)
	}
	if code, _ := do(t, "DELETE", ts.URL+"/admin/services/"+id+"/credentials/nope", admin, "", ""); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/services/svc_nope", admin, "", ""); code != 404 {
		t.Fatalf("unknown service: %d", code)
	}
}

func TestAdminDisabledWhenNoHash(t *testing.T) {
	s, _ := signer.NewLocal("t1")
	ring, _ := signer.NewRing(s)
	mem := store.NewMemory()
	own, _ := owner.New(mem, "https://auth.test")
	c := core.New(mem, ring, "https://auth.test")
	srv := &Server{Core: c, Owner: own, Limit: ratelimit.New(mem), OAuth: oauth.New(c), Users: users.New(mem)}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// Empty hash: even an empty-string token must not match.
	if code, _ := do(t, "GET", ts.URL+"/admin/services", "Bearer ", "", ""); code != 401 {
		t.Fatalf("admin open without hash: %d", code)
	}
}

// doRaw is do() with full control over headers and the raw response.
func doRaw(t *testing.T, method, rawURL string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestConsoleAndSessions(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	ctx := context.Background()

	// The page is served with a strict CSP.
	resp := doRaw(t, "GET", ts.URL+"/admin", nil, "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("console page: %d %v", resp.StatusCode, resp.Header)
	}
	resp.Body.Close()

	// Fresh install: setup required, login refused until a passkey exists.
	if code, body := do(t, "GET", ts.URL+"/admin/session", "", "", ""); code != 200 || body["setup_required"] != true || body["authenticated"] != false {
		t.Fatalf("session (fresh): %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/login/begin", "", "", ""); code != 409 || body["error"] != "setup_required" {
		t.Fatalf("login/begin without passkeys: %d %v", code, body)
	}
	// Registration begin needs admin auth; the bootstrap token works.
	if code, _ := do(t, "POST", ts.URL+"/admin/passkeys/begin", "", "", ""); code != 401 {
		t.Fatalf("passkeys/begin unauthenticated: %d", code)
	}
	code, begin := do(t, "POST", ts.URL+"/admin/passkeys/begin", "Bearer "+adminToken, "", "")
	if code != 200 || begin["challenge_id"] == "" || begin["options"] == nil {
		t.Fatalf("passkeys/begin: %d %v", code, begin)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/passkeys/finish?challenge="+begin["challenge_id"].(string)+"&name=Phone", "Bearer "+adminToken, "application/json", `{"id":"junk"}`); code != 400 || body["error"] != "passkey_rejected" {
		t.Fatalf("passkeys/finish junk: %d %v", code, body)
	}

	// Simulate a completed passkey login by inserting a session directly.
	now := time.Now()
	tok := "session-token-for-tests"
	if err := mem.PutSession(ctx, store.Session{Hash: core.HashSecret(tok), CreatedAt: now, ExpiresAt: now.Add(owner.SessionTTL)}); err != nil {
		t.Fatal(err)
	}
	cookie := map[string]string{"Cookie": sessionCookie + "=" + tok}

	// Cookie authenticates reads.
	resp = doRaw(t, "GET", ts.URL+"/admin/services", cookie, "")
	if resp.StatusCode != 200 {
		t.Fatalf("cookie read: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "GET", ts.URL+"/admin/session", cookie, "")
	var sess map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	if sess["authenticated"] != true || sess["method"] != "passkey" || sess["expires_at"] == nil {
		t.Fatalf("session (cookie): %v", sess)
	}

	// Cookie on a write needs a same-origin Origin header (CSRF).
	body := `{"name":"Svc","slug":"svc"}`
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json"}, body)
	if resp.StatusCode != 401 {
		t.Fatalf("cookie write without Origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json", "Origin": "https://evil.test"}, body)
	if resp.StatusCode != 401 {
		t.Fatalf("cookie write cross-origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok, "Content-Type": "application/json", "Origin": "https://auth.test"}, body)
	if resp.StatusCode != 201 {
		t.Fatalf("cookie write same-origin: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// The audit row names the method.
	last := mem.Audit[len(mem.Audit)-1]
	if last.Kind != "service.create" || last.Actor != "admin:passkey" {
		t.Fatalf("audit actor: %+v", last)
	}

	// Bad cookie is rejected; logout kills the session.
	resp = doRaw(t, "GET", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=nope"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("bad cookie: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "POST", ts.URL+"/admin/logout", cookie, "")
	if resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doRaw(t, "GET", ts.URL+"/admin/services", cookie, "")
	if resp.StatusCode != 401 {
		t.Fatalf("session after logout: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCookieFlags(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	resp := doRaw(t, "POST", ts.URL+"/admin/logout", nil, "")
	resp.Body.Close()
	var c *http.Cookie
	for _, k := range resp.Cookies() {
		if k.Name == sessionCookie {
			c = k
		}
	}
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/admin" {
		t.Fatalf("cookie flags: %+v", c)
	}
}

func TestBruteForceLockout(t *testing.T) {
	ts := newServer(t)
	admin := "Bearer " + adminToken
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Svc","slug":"svc"}`)
	id := svc["id"].(string)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	raw := cred["credential"].(string)

	bad := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"nbk_wrong"}}
	for i := 0; i < ratelimit.TokenClient.Limit; i++ {
		if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", bad.Encode()); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	// The service is now locked, even for the right secret.
	good := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {raw}}
	resp := doRaw(t, "POST", ts.URL+"/v1/token", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, good.Encode())
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("locked client: %d retry-after=%q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Another service from the same IP still works until the IP limit (30) is reached.
	_, svc2 := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Two","slug":"two"}`)
	_, cred2 := do(t, "POST", ts.URL+"/admin/services/"+svc2["id"].(string)+"/credentials", admin, "", "")
	good2 := url.Values{"grant_type": {"client_credentials"}, "client_id": {svc2["id"].(string)}, "client_secret": {cred2["credential"].(string)}}
	if code, _ := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", good2.Encode()); code != 200 {
		t.Fatalf("other client from same ip: %d", code)
	}

	// Passkey ceremonies lock per IP after 20 failures.
	for i := 0; i < ratelimit.LoginIP.Limit; i++ {
		_, begin := do(t, "POST", ts.URL+"/admin/passkeys/begin", admin, "", "")
		if code, _ := do(t, "POST", ts.URL+"/admin/passkeys/finish?challenge="+begin["challenge_id"].(string), admin, "application/json", `{"id":"junk"}`); code != 400 {
			t.Fatalf("junk attestation %d: %d", i, code)
		}
	}
	if code, body := do(t, "POST", ts.URL+"/admin/login/begin", "", "", ""); code != 429 || body["error"] != "too_many_attempts" {
		t.Fatalf("login after lockout: %d %v", code, body)
	}
}

func TestConnectorOAuthFlow(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	ctx := context.Background()
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Metadata advertises the endpoints.
	if code, md := do(t, "GET", ts.URL+"/.well-known/oauth-authorization-server", "", "", ""); code != 200 || md["registration_endpoint"] != "https://auth.test/oauth/register" {
		t.Fatalf("metadata: %d %v", code, md)
	}
	if code, _ := do(t, "GET", ts.URL+"/.well-known/oauth-authorization-server/mcp", "", "", ""); code != 200 {
		t.Fatalf("metadata with suffix: %d", code)
	}

	// Service with a resource.
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"FinForge","slug":"finforge"}`)
	id := svc["id"].(string)
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"ftp://x"}`); code != 400 {
		t.Fatalf("bad resource: %d %v", code, body)
	}
	code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://finforge.test/mcp"}`)
	if code != 200 || len(body["resources"].([]any)) != 1 {
		t.Fatalf("add resource: %d %v", code, body)
	}
	if code, _ := do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://finforge.test/mcp"}`); code != 409 {
		t.Fatalf("dup resource: %d", code)
	}

	// Permissions catalog.
	if code, body := do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read","write"],"roles":{"viewer":["read"]}}`); code != 200 || len(body["scopes"].([]any)) != 2 {
		t.Fatalf("set permissions: %d %v", code, body)
	}
	if code, _ := do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read"],"roles":{"x":["write"]}}`); code != 400 {
		t.Fatalf("role outside catalog: %d", code)
	}

	// DCR.
	code, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Claude","redirect_uris":["https://claude.ai/cb"],"token_endpoint_auth_method":"none"}`)
	if code != 201 || reg["client_id"] == nil || reg["client_secret"] != nil {
		t.Fatalf("register: %d %v", code, reg)
	}
	clientID := reg["client_id"].(string)

	// Authorize: untrusted redirect is a hard 400, no bounce.
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://evil.test"}, "response_type": {"code"}}
	resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("evil redirect: %d", resp.StatusCode)
	}
	// Missing PKCE bounces back with an error.
	q = url.Values{"client_id": {clientID}, "redirect_uri": {"https://claude.ai/cb"}, "response_type": {"code"}, "state": {"s1"}, "resource": {"https://finforge.test/mcp"}}
	resp, _ = noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Host != "claude.ai" || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "s1" {
		t.Fatalf("missing pkce bounce: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Good request goes to the console.
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	q.Set("scope", "read")
	resp, _ = noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ = url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Path != "/admin" || loc.Query().Get("approve") == "" {
		t.Fatalf("approve redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	authzID := loc.Query().Get("approve")

	// Pending details need admin; the bearer token may look but not approve.
	if code, _ := do(t, "GET", ts.URL+"/admin/authorize/"+authzID, "", "", ""); code != 401 {
		t.Fatalf("pending unauthenticated: %d", code)
	}
	code, pend := do(t, "GET", ts.URL+"/admin/authorize/"+authzID, admin, "", "")
	if code != 200 || pend["client_name"] != "Claude" || pend["service"].(map[string]any)["id"] != id {
		t.Fatalf("pending: %d %v", code, pend)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/authorize/"+authzID+"/approve", admin, "", ""); code != 401 || body["error"] != "passkey_required" {
		t.Fatalf("approve with bearer: %d %v", code, body)
	}

	// Passkey session approves (cookie + same-origin).
	now := time.Now()
	tok := "sess"
	_ = mem.PutSession(ctx, store.Session{Hash: core.HashSecret(tok), CreatedAt: now, ExpiresAt: now.Add(owner.SessionTTL), Method: "passkey"})
	hdr := map[string]string{"Cookie": sessionCookie + "=" + tok, "Origin": "https://auth.test"}
	// Session without a recent assertion must step up first.
	resp = doRaw(t, "POST", ts.URL+"/admin/authorize/"+authzID+"/approve", hdr, "")
	var stale map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&stale)
	resp.Body.Close()
	if resp.StatusCode != 401 || stale["error"] != "step_up_required" {
		t.Fatalf("approve with stale session: %d %v", resp.StatusCode, stale)
	}
	_ = mem.TouchSessionVerified(ctx, core.HashSecret(tok), now)
	resp = doRaw(t, "POST", ts.URL+"/admin/authorize/"+authzID+"/approve", hdr, "")
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(out["redirect_to"], "https://claude.ai/cb?") {
		t.Fatalf("approve: %d %v", resp.StatusCode, out)
	}
	cbURL, _ := url.Parse(out["redirect_to"])
	authCode := cbURL.Query().Get("code")
	if authCode == "" || cbURL.Query().Get("state") != "s1" {
		t.Fatalf("callback: %s", out["redirect_to"])
	}
	resp = doRaw(t, "POST", ts.URL+"/admin/authorize/"+authzID+"/approve", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("approve twice: %d", resp.StatusCode)
	}

	// Exchange on /oauth/token (public client: no secret).
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {authCode}, "code_verifier": {verifier}, "redirect_uri": {"https://claude.ai/cb"}}
	code, tk := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 || tk["refresh_token"] == nil || tk["expires_in"].(float64) != 3600 {
		t.Fatalf("exchange: %d %v", code, tk)
	}
	// The access token is for FinForge, not for the auth API.
	if code, _ := do(t, "GET", ts.URL+"/v1/me", "Bearer "+tk["access_token"].(string), "", ""); code != 401 {
		t.Fatalf("connector token on /v1/me: %d", code)
	}
	// Refresh on the legacy /v1/token path works too (same handler).
	form = url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tk["refresh_token"].(string)}}
	if code, tk2 := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 200 || tk2["refresh_token"] == tk["refresh_token"] {
		t.Fatalf("refresh: %d %v", code, tk2)
	}

	// Deny path works with the break-glass token (denying is not sensitive).
	resp, _ = noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ = url.Parse(resp.Header.Get("Location"))
	code, out2 := do(t, "POST", ts.URL+"/admin/authorize/"+loc.Query().Get("approve")+"/deny", admin, "", "")
	if code != 200 || !strings.Contains(out2["redirect_to"].(string), "error=access_denied") {
		t.Fatalf("deny: %d %v", code, out2)
	}
}

func TestRecoveryFlow(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	admin := "Bearer " + adminToken
	if code, st := do(t, "GET", ts.URL+"/admin/recovery-codes", admin, "", ""); code != 200 || st["total"].(float64) != 0 {
		t.Fatalf("status: %d %v", code, st)
	}
	code, gen := do(t, "POST", ts.URL+"/admin/recovery-codes", admin, "", "")
	if code != 201 || len(gen["codes"].([]any)) != owner.RecoveryCodeCount {
		t.Fatalf("generate: %d %v", code, gen)
	}
	first := gen["codes"].([]any)[0].(string)
	if code, _ := do(t, "GET", ts.URL+"/admin/recovery-codes", admin, "", ""); code != 200 {
		t.Fatalf("status after: %d", code)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/recover", "", "application/json", `{"code":"nope-nope-nope-nope"}`); code != 401 || body["error"] != "recovery_code_rejected" {
		t.Fatalf("bad code: %d %v", code, body)
	}
	resp := doRaw(t, "POST", ts.URL+"/admin/recover", map[string]string{"Content-Type": "application/json"}, `{"code":"`+first+`"}`)
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out["method"] != "recovery" {
		t.Fatalf("recover: %d %v", resp.StatusCode, out)
	}
	var tok string
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("no session cookie after recovery")
	}
	hdr := map[string]string{"Cookie": sessionCookie + "=" + tok, "Origin": "https://auth.test"}
	// A recovery session can start passkey registration (the whole point)…
	resp = doRaw(t, "POST", ts.URL+"/admin/passkeys/begin", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("passkeys/begin with recovery session: %d", resp.StatusCode)
	}
	// …but the session endpoint reports its weaker method, and the code is spent.
	resp = doRaw(t, "GET", ts.URL+"/admin/session", hdr, "")
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out["method"] != "recovery" {
		t.Fatalf("session method: %v", out)
	}
	if code, _ := do(t, "POST", ts.URL+"/admin/recover", "", "application/json", `{"code":"`+first+`"}`); code != 401 {
		t.Fatalf("reused code: %d", code)
	}
}

func TestAuditAndLogoutEverywhere(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	ctx := context.Background()
	admin := "Bearer " + adminToken
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Audit","slug":"audit"}`)
	_, _ = do(t, "POST", ts.URL+"/admin/services/"+svc["id"].(string)+"/credentials", admin, "", "")

	if code, _ := do(t, "GET", ts.URL+"/admin/audit", "", "", ""); code != 401 {
		t.Fatalf("audit unauthenticated: %d", code)
	}
	code, body := do(t, "GET", ts.URL+"/admin/audit?limit=1", admin, "", "")
	if code != 200 || len(body["events"].([]any)) != 1 || body["next"] == "" {
		t.Fatalf("audit page: %d %v", code, body)
	}
	first := body["events"].([]any)[0].(map[string]any)
	if first["kind"] != "credential.mint" || first["actor"] != "admin:token" {
		t.Fatalf("newest event: %v", first)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/audit?month=bad", admin, "", ""); code != 400 {
		t.Fatalf("bad month: %d", code)
	}

	// Two sessions; logout-everywhere from one kills both.
	now := time.Now()
	for _, tok := range []string{"s1", "s2"} {
		_ = mem.PutSession(ctx, store.Session{Hash: core.HashSecret(tok), CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(owner.SessionTTL)})
	}
	hdr := map[string]string{"Cookie": sessionCookie + "=s1", "Origin": "https://auth.test"}
	resp := doRaw(t, "POST", ts.URL+"/admin/logout-everywhere", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("logout everywhere: %d", resp.StatusCode)
	}
	for _, tok := range []string{"s1", "s2"} {
		resp = doRaw(t, "GET", ts.URL+"/admin/services", map[string]string{"Cookie": sessionCookie + "=" + tok}, "")
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("session %s survived: %d", tok, resp.StatusCode)
		}
	}
}

func TestStepUp(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	ctx := context.Background()
	admin := "Bearer " + adminToken
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"S","slug":"stepup"}`)
	id := svc["id"].(string)
	now := time.Now()
	tok := "stale"
	_ = mem.PutSession(ctx, store.Session{Hash: core.HashSecret(tok), CreatedAt: now.Add(-20 * time.Minute), ExpiresAt: now.Add(owner.SessionTTL),
		Method: "passkey", VerifiedAt: now.Add(-20 * time.Minute)})
	hdr := map[string]string{"Cookie": sessionCookie + "=" + tok, "Origin": "https://auth.test"}

	// Reads are fine; minting needs a fresh assertion.
	resp := doRaw(t, "GET", ts.URL+"/admin/services", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("read with stale session: %d", resp.StatusCode)
	}
	resp = doRaw(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", hdr, "")
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 401 || body["error"] != "step_up_required" {
		t.Fatalf("mint with stale session: %d %v", resp.StatusCode, body)
	}
	resp = doRaw(t, "GET", ts.URL+"/admin/session", hdr, "")
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body["fresh"] != false {
		t.Fatalf("session fresh flag: %v", body)
	}
	// Step-up begin needs passkeys registered; with none it is a 500-free 409 via BeginLogin.
	resp = doRaw(t, "POST", ts.URL+"/admin/step-up/begin", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 500 && resp.StatusCode != 200 && resp.StatusCode != 409 {
		t.Fatalf("step-up begin: %d", resp.StatusCode)
	}
	// Simulate a completed step-up.
	_ = mem.TouchSessionVerified(ctx, core.HashSecret(tok), now)
	resp = doRaw(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", hdr, "")
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("mint after step-up: %d", resp.StatusCode)
	}
	// A recovery session can never mint.
	_ = mem.PutSession(ctx, store.Session{Hash: core.HashSecret("rec"), CreatedAt: now, ExpiresAt: now.Add(owner.SessionTTL), Method: "recovery", VerifiedAt: now})
	resp = doRaw(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", map[string]string{"Cookie": sessionCookie + "=rec", "Origin": "https://auth.test"}, "")
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 401 || body["error"] != "passkey_required" {
		t.Fatalf("mint with recovery session: %d %v", resp.StatusCode, body)
	}
}

func TestUserPoolHTTP(t *testing.T) {
	ts, mem := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Service: permissions, resource, login config, credential → service token.
	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"FinForge","slug":"finforge"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read","write"],"roles":{"user":["read"],"editor":["read","write"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://finforge.test/api"}`)
	if code, body := do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://finforge.test/login","rp_id":"finforge.test","origins":["https://finforge.test"],"default_roles":["nope"]}`); code != 400 {
		t.Fatalf("bad default role: %d %v", code, body)
	}
	code, body := do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://finforge.test/login","rp_id":"finforge.test","origins":["https://finforge.test"],"default_roles":["user"]}`)
	if code != 200 || body["login_url"] != "https://finforge.test/login" || body["open_signup"] != false {
		t.Fatalf("set login (default invite-only): %d %v", code, body)
	}
	code, body = do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://finforge.test/login","rp_id":"finforge.test","origins":["https://finforge.test"],"default_roles":["user"],"open_signup":true}`)
	if code != 200 || body["open_signup"] != true {
		t.Fatalf("open signup: %d %v", code, body)
	}
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)

	// Users CRUD with the service token.
	if code, _ := do(t, "POST", ts.URL+"/v1/users", "", "application/json", `{"email":"a@x.test"}`); code != 401 {
		t.Fatalf("users without service token: %d", code)
	}
	code, u := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"email":"Alice@x.test","name":"Alice"}`)
	if code != 201 || u["email"] != "alice@x.test" || u["method"] != "passkey" {
		t.Fatalf("create user: %d %v", code, u)
	}
	uid := u["id"].(string)
	if code, _ := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"email":"alice@x.test"}`); code != 409 {
		t.Fatalf("dup user: %d", code)
	}
	if code, list := do(t, "GET", ts.URL+"/v1/users", svcTok, "", ""); code != 200 || len(list["users"].([]any)) != 1 {
		t.Fatalf("list users: %d %v", code, list)
	}
	if code, got := do(t, "PATCH", ts.URL+"/v1/users/"+uid, svcTok, "application/json", `{"roles":["editor"]}`); code != 200 || len(got["roles"].([]any)) != 1 {
		t.Fatalf("patch roles: %d %v", code, got)
	}
	if code, _ := do(t, "PATCH", ts.URL+"/v1/users/"+uid, svcTok, "application/json", `{"roles":["ghost"]}`); code != 400 {
		t.Fatalf("unknown role: %d", code)
	}
	if code, opts := do(t, "POST", ts.URL+"/v1/users/"+uid+"/passkeys/begin", svcTok, "", ""); code != 200 || opts["challenge_id"] == nil {
		t.Fatalf("passkey begin: %d %v", code, opts)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/users/"+uid+"/passkeys", svcTok, "", ""); code != 200 {
		t.Fatalf("list passkeys: %d", code)
	}

	// First-party client + authorize → login_url with login_challenge.
	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"FinForge web","redirect_uris":["https://finforge.test/cb"],"token_endpoint_auth_method":"none"}`)
	clientID := reg["client_id"].(string)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://finforge.test/cb"}, "response_type": {"code"}, "state": {"s1"},
		"resource": {"https://finforge.test/api"}, "scope": {"read write"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Host != "finforge.test" || loc.Path != "/login" || loc.Query().Get("login_challenge") == "" {
		t.Fatalf("authorize for user pool: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	lc := loc.Query().Get("login_challenge")

	// Passkey login begin needs a valid challenge for this service.
	if code, _ := do(t, "POST", ts.URL+"/v1/login/passkey/begin", svcTok, "application/json", `{"login_challenge":"nope"}`); code != 404 {
		t.Fatalf("begin with bad challenge: %d", code)
	}
	code, lb := do(t, "POST", ts.URL+"/v1/login/passkey/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`"}`)
	if code != 200 || lb["options"] == nil {
		t.Fatalf("login begin: %d %v", code, lb)
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/login/passkey/finish?challenge="+lb["challenge_id"].(string), svcTok, "application/json", `{"id":"junk"}`); code != 401 {
		t.Fatalf("junk assertion: %d", code)
	}

	// Owner sign-in on the product's page: needs an owner passkey first.
	if code, body := do(t, "POST", ts.URL+"/v1/login/owner/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`"}`); code != 409 || body["error"] != "setup_required" {
		t.Fatalf("owner begin without passkeys: %d %v", code, body)
	}
	_ = mem.PutPasskey(context.Background(), store.Passkey{ID: "abc", Name: "Seed", CreatedAt: time.Now(),
		Data: []byte(`{"id":"YWJj","publicKey":"AAAA","attestationType":"none","flags":{},"authenticator":{}}`)})
	if code, _ := do(t, "POST", ts.URL+"/v1/login/owner/begin", svcTok, "application/json", `{"login_challenge":"nope"}`); code != 404 {
		t.Fatalf("owner begin with bad challenge: %d", code)
	}
	code, ob := do(t, "POST", ts.URL+"/v1/login/owner/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`"}`)
	if code != 200 || ob["options"] == nil {
		t.Fatalf("owner begin: %d %v", code, ob)
	}
	if pk := ob["options"].(map[string]any)["publicKey"].(map[string]any); pk["rpId"] != "auth.test" {
		t.Fatalf("owner options rpId: %v", pk["rpId"])
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/login/owner/finish?challenge="+ob["challenge_id"].(string), svcTok, "application/json", `{"id":"junk"}`); code != 401 {
		t.Fatalf("junk owner assertion: %d", code)
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/login/owner/finish?challenge=", svcTok, "application/json", `{"id":"junk"}`); code != 401 {
		t.Fatalf("owner finish without challenge: %d", code)
	}

	// Google: disabled until configured.
	resp, _ = noRedirect.Get(ts.URL + "/v1/login/google/start?login_challenge=" + lc)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("google disabled: %d", resp.StatusCode)
	}
	// Fake Google.
	gmux := http.NewServeMux()
	gmux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	gmux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "g42", "email": "g@x.test", "email_verified": true, "name": "G"})
	})
	fake := httptest.NewServer(gmux)
	defer fake.Close()
	srv.Google = users.NewGoogle("cid", "sec", "https://auth.test/v1/login/google/callback")
	srv.Google.AuthURL, srv.Google.TokenURL, srv.Google.UserinfoURL = fake.URL+"/auth", fake.URL+"/token", fake.URL+"/userinfo"

	resp, _ = noRedirect.Get(ts.URL + "/v1/login/google/start?login_challenge=" + lc)
	resp.Body.Close()
	gloc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), fake.URL+"/auth?") || gloc.Query().Get("state") == "" {
		t.Fatalf("google start: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	state := gloc.Query().Get("state")
	resp, _ = noRedirect.Get(ts.URL + "/v1/login/google/callback?state=bogus&code=x")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bogus state: %d", resp.StatusCode)
	}
	resp, _ = noRedirect.Get(ts.URL + "/v1/login/google/callback?state=" + url.QueryEscape(state) + "&code=good")
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || cb.Host != "finforge.test" || cb.Path != "/cb" || cb.Query().Get("code") == "" || cb.Query().Get("state") != "s1" {
		t.Fatalf("google callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Exchange: new Google user has the default role "user" → scope "read" only.
	form = url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {cb.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://finforge.test/cb"}}
	code, ut := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 || ut["scope"] != "read" {
		t.Fatalf("user token: %d %v", code, ut)
	}
	claims, err := srv.Core.VerifyToken(ut["access_token"].(string), id)
	if err != nil || !strings.HasPrefix(claims.Subject, "usr:") || claims.Email != "g@x.test" {
		t.Fatalf("claims: %+v %v", claims, err)
	}
	// Two users now; logout-everywhere on the google user works.
	code, list := do(t, "GET", ts.URL+"/v1/users", svcTok, "", "")
	if code != 200 || len(list["users"].([]any)) != 2 {
		t.Fatalf("users after google: %d %v", code, list)
	}
	gid := strings.TrimPrefix(claims.Subject, "usr:")
	if code, _ := do(t, "POST", ts.URL+"/v1/users/"+gid+"/logout-everywhere", svcTok, "", ""); code != 204 {
		t.Fatalf("user logout everywhere: %d", code)
	}
	// Export then delete; the refresh token dies with the account.
	if code, exp := do(t, "GET", ts.URL+"/v1/users/"+gid+"/export", svcTok, "", ""); code != 200 || exp["user"] == nil || exp["audit"] == nil {
		t.Fatalf("export: %d %v", code, exp)
	}
	if code, _ := do(t, "DELETE", ts.URL+"/v1/users/"+gid, svcTok, "", ""); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/v1/users/"+gid, svcTok, "", ""); code != 404 {
		t.Fatalf("deleted user still readable: %d", code)
	}
	form = url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {ut["refresh_token"].(string)}}
	if code, body := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode()); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after delete: %d %v", code, body)
	}
}

// TestClosedSignupHTTP: an invite-only pool refuses the app's sign-up and
// strangers at Google; the owner provisions accounts and a provisioned Google
// account binds on first sign-in.
func TestClosedSignupHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Personal Site","slug":"personal-site"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read"],"roles":{"user":["read"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://site.test/api"}`)
	// Owner-only service: no accounts at all.
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"me@x.test"}`); code != 409 || body["error"] != "service_not_configured" {
		t.Fatalf("provision on owner-only service: %d %v", code, body)
	}
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://site.test/login","rp_id":"site.test","origins":["https://site.test"],"default_roles":["user"]}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)

	// The app cannot sign anyone up.
	if code, body := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"email":"stranger@x.test"}`); code != 403 || body["error"] != "signup_closed" {
		t.Fatalf("app sign-up on closed pool: %d %v", code, body)
	}
	// The owner can, with either method; the list needs admin, not a service token.
	if code, _ := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", svcTok, "application/json", `{"email":"me@x.test"}`); code != 401 {
		t.Fatalf("provision with service token: %d", code)
	}
	code, me := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"Me@x.test","name":"Nathan"}`)
	if code != 201 || me["method"] != "passkey" || me["email"] != "me@x.test" {
		t.Fatalf("provision passkey: %d %v", code, me)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"me@x.test","method":"sms"}`); code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("bad method: %d %v", code, body)
	}
	code, g := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"g@x.test","method":"google"}`)
	if code != 201 || g["method"] != "google" {
		t.Fatalf("provision google: %d %v", code, g)
	}
	if code, list := do(t, "GET", ts.URL+"/admin/services/"+id+"/users", admin, "", ""); code != 200 || len(list["users"].([]any)) != 2 {
		t.Fatalf("admin list: %d %v", code, list)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/services/nope/users", admin, "", ""); code != 404 {
		t.Fatalf("list on missing service: %d", code)
	}

	// Google: a stranger is sent back to the login page with signup_closed;
	// the provisioned person binds and completes the authorization.
	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Site","redirect_uris":["https://site.test/cb"],"token_endpoint_auth_method":"none"}`)
	clientID := reg["client_id"].(string)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	authorize := func() string {
		q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://site.test/cb"}, "response_type": {"code"}, "state": {"s1"},
			"resource": {"https://site.test/api"}, "scope": {"read"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
		resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if lc := loc.Query().Get("login_challenge"); lc != "" {
			return lc
		}
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		return ""
	}
	who := map[string]any{"sub": "stranger-1", "email": "stranger@x.test", "email_verified": true}
	gmux := http.NewServeMux()
	gmux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	gmux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(who) })
	fake := httptest.NewServer(gmux)
	defer fake.Close()
	srv.Google = users.NewGoogle("cid", "sec", "https://auth.test/v1/login/google/callback")
	srv.Google.AuthURL, srv.Google.TokenURL, srv.Google.UserinfoURL = fake.URL+"/auth", fake.URL+"/token", fake.URL+"/userinfo"
	callback := func() *url.URL {
		resp, _ := noRedirect.Get(ts.URL + "/v1/login/google/start?login_challenge=" + authorize())
		resp.Body.Close()
		gloc, _ := url.Parse(resp.Header.Get("Location"))
		resp, _ = noRedirect.Get(ts.URL + "/v1/login/google/callback?state=" + url.QueryEscape(gloc.Query().Get("state")) + "&code=good")
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 {
			t.Fatalf("callback: %d", resp.StatusCode)
		}
		return loc
	}
	if loc := callback(); loc.Path != "/login" || loc.Query().Get("error") != "signup_closed" || loc.Query().Get("login_challenge") == "" {
		t.Fatalf("stranger at google: %s", loc)
	}
	who = map[string]any{"sub": "g-77", "email": "G@x.test", "email_verified": true, "name": "G"}
	loc := callback()
	if loc.Path != "/cb" || loc.Query().Get("code") == "" {
		t.Fatalf("provisioned google user: %s", loc)
	}
	form = url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://site.test/cb"}}
	code, ut := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 {
		t.Fatalf("token for bound user: %d %v", code, ut)
	}
	if claims, err := srv.Core.VerifyToken(ut["access_token"].(string), id); err != nil || claims.Subject != "usr:"+g["id"].(string) {
		t.Fatalf("bound user claims: %+v %v", claims, err)
	}
	// Same email from another Google account is a stranger again.
	who = map[string]any{"sub": "g-78", "email": "g@x.test", "email_verified": true}
	if loc := callback(); loc.Query().Get("error") != "signup_closed" {
		t.Fatalf("second subject with the same email: %s", loc)
	}
	_, audit := do(t, "GET", ts.URL+"/admin/audit?month="+time.Now().UTC().Format("2006-01")+"&limit=50", admin, "", "")
	var denied, bound int
	for _, e := range audit["events"].([]any) {
		switch e.(map[string]any)["kind"] {
		case "user.signup_denied":
			denied++
		case "user.google.bind":
			bound++
		}
	}
	if denied != 3 || bound != 1 {
		t.Fatalf("audit: denied=%d bound=%d", denied, bound)
	}
}

type captureMail struct{ to, subject, text string }

func (c *captureMail) Send(_ context.Context, to, subject, text string) error {
	c.to, c.subject, c.text = to, subject, text
	return nil
}

func (c *captureMail) code(t *testing.T) string {
	t.Helper()
	for _, w := range strings.Fields(c.text) {
		if len(w) == 6 && strings.Trim(w, "0123456789") == "" {
			return w
		}
	}
	t.Fatalf("no code in %q", c.text)
	return ""
}

// TestEmailCodeHTTP: sign in with an emailed code (open pool), verify an
// app-created passkey account, and the email_verified claim on user tokens.
func TestEmailCodeHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Codenames","slug":"codenames"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read"],"roles":{"user":["read"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://codenames.test/api"}`)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://codenames.test/login","rp_id":"codenames.test","origins":["https://codenames.test"],"default_roles":["user"],"open_signup":true}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)

	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Codenames web","redirect_uris":["https://codenames.test/cb"],"token_endpoint_auth_method":"none"}`)
	clientID := reg["client_id"].(string)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	authorize := func() string {
		q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://codenames.test/cb"}, "response_type": {"code"}, "state": {"s1"},
			"resource": {"https://codenames.test/api"}, "scope": {"read"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
		resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc.Query().Get("login_challenge")
	}
	lc := authorize()

	// No outbox configured → 404 email_disabled, nothing else leaks.
	if code, body := do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"p@x.test"}`); code != 404 || body["error"] != "email_disabled" {
		t.Fatalf("email disabled: %d %v", code, body)
	}
	mail := &captureMail{}
	srv.Users.Mail = mail

	if code, _ := do(t, "POST", ts.URL+"/v1/login/email/begin", "", "application/json", `{}`); code != 401 {
		t.Fatalf("begin without service token: %d", code)
	}
	if code, _ := do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"nope","email":"p@x.test"}`); code != 404 {
		t.Fatalf("begin with bad challenge: %d", code)
	}
	code, begin := do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"Player@X.test"}`)
	if code != 200 || begin["challenge_id"] == nil || mail.to != "player@x.test" || !strings.Contains(mail.subject, "Codenames") {
		t.Fatalf("begin: %d %v to=%q", code, begin, mail.to)
	}
	chID := begin["challenge_id"].(string)
	if code, body := do(t, "POST", ts.URL+"/v1/login/email/finish?challenge="+chID, svcTok, "application/json", `{"code":"000000"}`); code != 401 || body["error"] != "code_rejected" {
		t.Fatalf("wrong code: %d %v", code, body)
	}
	code, fin := do(t, "POST", ts.URL+"/v1/login/email/finish?challenge="+chID, svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`)
	if code != 200 {
		t.Fatalf("finish: %d %v", code, fin)
	}
	user := fin["user"].(map[string]any)
	if user["method"] != "email" || user["email_verified"] != true {
		t.Fatalf("user: %v", user)
	}
	cb, _ := url.Parse(fin["redirect_to"].(string))
	form = url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {cb.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://codenames.test/cb"}}
	code, ut := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 {
		t.Fatalf("token: %d %v", code, ut)
	}
	claims, err := srv.Core.VerifyToken(ut["access_token"].(string), id)
	if err != nil || claims.Subject != "usr:"+user["id"].(string) || claims.Email != "player@x.test" || !claims.EmailVerified {
		t.Fatalf("claims: %+v %v", claims, err)
	}
	// The code is single-use.
	if code, _ := do(t, "POST", ts.URL+"/v1/login/email/finish?challenge="+chID, svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`); code != 401 {
		t.Fatalf("replay: %d", code)
	}
	// A second sign-in from another address raises a new-login alert email.
	doFrom := func(ip, method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", svcTok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	_, b2 := doFrom("203.0.113.9", "POST", "/v1/login/email/begin", `{"login_challenge":"`+authorize()+`","email":"player@x.test"}`)
	if code, _ := doFrom("203.0.113.9", "POST", "/v1/login/email/finish?challenge="+b2["challenge_id"].(string), `{"code":"`+mail.code(t)+`"}`); code != 200 {
		t.Fatalf("second login: %d", code)
	}
	if !strings.Contains(mail.subject, "New sign-in to Codenames") || !strings.Contains(mail.text, "203.0.113.9") {
		t.Fatalf("alert email: subj=%q", mail.subject)
	}
	// Per-address send cap.
	for i := 0; i < 10; i++ {
		code, _ = do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"`+authorize()+`","email":"spam@x.test"}`)
		if code == 429 {
			break
		}
	}
	if code != 429 {
		t.Fatalf("send cap never hit: %d", code)
	}

	// Verification: an app-created passkey account starts unverified.
	code, pk := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"email":"pk@x.test"}`)
	if code != 201 || pk["email_verified"] != false {
		t.Fatalf("create passkey user: %d %v", code, pk)
	}
	pkID := pk["id"].(string)
	code, vb := do(t, "POST", ts.URL+"/v1/users/"+pkID+"/email/verify/begin", svcTok, "", "")
	if code != 200 || mail.to != "pk@x.test" {
		t.Fatalf("verify begin: %d %v to=%q", code, vb, mail.to)
	}
	vch := vb["challenge_id"].(string)
	if code, body := do(t, "POST", ts.URL+"/v1/users/"+pkID+"/email/verify/finish?challenge="+vch, svcTok, "application/json", `{"code":"123456"}`); code != 401 || body["error"] != "code_rejected" {
		t.Fatalf("verify wrong code: %d %v", code, body)
	}
	code, verified := do(t, "POST", ts.URL+"/v1/users/"+pkID+"/email/verify/finish?challenge="+vch, svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`)
	if code != 200 || verified["email_verified"] != true {
		t.Fatalf("verify finish: %d %v", code, verified)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/users/"+pkID+"/email/verify/begin", svcTok, "", ""); code != 409 || body["error"] != "already_verified" {
		t.Fatalf("verify twice: %d %v", code, body)
	}
	// Owner-provisioned email accounts show up with their method.
	if code, p := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"vip@x.test","method":"email"}`); code != 201 || p["method"] != "email" || p["email_verified"] != true {
		t.Fatalf("provision email: %d %v", code, p)
	}
}

// TestPasskeyActivationHTTP: a provisioned passkey account proves its address
// with a code and receives registration options bound to the parked sign-in.
func TestPasskeyActivationHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Site","slug":"site"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["admin"],"roles":{"owner":["admin"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://site.test/api"}`)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://site.test/login","rp_id":"site.test","origins":["https://site.test"],"default_roles":["owner"]}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)
	_, me := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"me@x.test","method":"passkey"}`)

	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Site","redirect_uris":["https://site.test/cb"],"token_endpoint_auth_method":"none"}`)
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	q := url.Values{"client_id": {reg["client_id"].(string)}, "redirect_uri": {"https://site.test/cb"}, "response_type": {"code"}, "state": {"s1"},
		"resource": {"https://site.test/api"}, "scope": {"admin"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	lc := loc.Query().Get("login_challenge")

	mail := &captureMail{}
	srv.Users.Mail = mail
	if code, body := do(t, "POST", ts.URL+"/v1/login/passkey/activate/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"stranger@x.test"}`); code != 403 || body["error"] != "signup_closed" {
		t.Fatalf("stranger: %d %v", code, body)
	}
	code, begin := do(t, "POST", ts.URL+"/v1/login/passkey/activate/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"me@x.test"}`)
	if code != 200 || mail.to != "me@x.test" {
		t.Fatalf("begin: %d %v", code, begin)
	}
	chID := begin["challenge_id"].(string)
	if code, _ := do(t, "POST", ts.URL+"/v1/login/passkey/activate/finish?challenge="+chID, svcTok, "application/json", `{"code":"000000"}`); code != 401 {
		t.Fatalf("wrong code: %d", code)
	}
	code, fin := do(t, "POST", ts.URL+"/v1/login/passkey/activate/finish?challenge="+chID, svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`)
	if code != 200 || fin["options"] == nil || fin["challenge_id"] == nil || fin["user"].(map[string]any)["id"] != me["id"] {
		t.Fatalf("finish: %d %v", code, fin)
	}
	// Junk attestation against the registration challenge is a 400, and the
	// challenge is consumed.
	regID := fin["challenge_id"].(string)
	if code, body := do(t, "POST", ts.URL+"/v1/users/"+me["id"].(string)+"/passkeys/finish?challenge="+regID, svcTok, "application/json", `{"id":"junk"}`); code != 400 || body["error"] != "passkey_rejected" {
		t.Fatalf("junk attestation: %d %v", code, body)
	}
}

// TestOrgHTTP covers auth-service-15: org CRUD and membership under the
// service token, the org context on authorize / login / token / refresh,
// the owner as admin of every org, and the non-member refusal.
func TestOrgHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	mail := &captureMail{}
	srv.Users.Mail = mail

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Therapist","slug":"therapist"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read","write"],"roles":{"user":["read","write"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://therapist.test/api"}`)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://therapist.test/login","rp_id":"therapist.test","origins":["https://therapist.test"],"default_roles":["user"],"open_signup":true}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)

	// Two accounts; alice founds an org.
	_, alice := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"alice@x.test","method":"email"}`)
	_, bob := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"bob@x.test","method":"email"}`)
	aliceID, bobID := alice["id"].(string), bob["id"].(string)

	if code, _ := do(t, "POST", ts.URL+"/v1/orgs", "", "application/json", `{}`); code != 401 {
		t.Fatalf("orgs without service token: %d", code)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/orgs", svcTok, "application/json", `{"name":"","admin_user_id":"`+aliceID+`"}`); code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("blank org name: %d %v", code, body)
	}
	code, org := do(t, "POST", ts.URL+"/v1/orgs", svcTok, "application/json", `{"name":"Sunny Practice","admin_user_id":"`+aliceID+`"}`)
	if code != 201 || org["status"] != "active" || !strings.HasPrefix(org["id"].(string), "org_") {
		t.Fatalf("create org: %d %v", code, org)
	}
	orgID := org["id"].(string)
	if code, body := do(t, "GET", ts.URL+"/v1/orgs/"+orgID+"/members", svcTok, "", ""); code != 200 || len(body["members"].([]any)) != 1 || body["members"].([]any)[0].(map[string]any)["role"] != "admin" {
		t.Fatalf("members: %d %v", code, body)
	}
	if code, body := do(t, "PUT", ts.URL+"/v1/orgs/"+orgID+"/members/"+aliceID, svcTok, "application/json", `{"role":"member"}`); code != 409 || body["error"] != "last_admin" {
		t.Fatalf("demote last admin: %d %v", code, body)
	}
	if code, body := do(t, "PUT", ts.URL+"/v1/orgs/"+orgID+"/members/"+bobID, svcTok, "application/json", `{"role":"owner"}`); code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("bad role: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/v1/users/"+bobID+"/orgs", svcTok, "", ""); code != 200 || len(body["orgs"].([]any)) != 0 {
		t.Fatalf("bob orgs before: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/v1/orgs", svcTok, "", ""); code != 200 || len(body["orgs"].([]any)) != 1 {
		t.Fatalf("list orgs: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/admin/services/"+id+"/orgs", admin, "", ""); code != 200 || len(body["orgs"].([]any)) != 1 {
		t.Fatalf("admin list orgs: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/admin/services/"+id+"/orgs/"+orgID+"/members", admin, "", ""); code != 200 || len(body["members"].([]any)) != 1 {
		t.Fatalf("admin list members: %d %v", code, body)
	}

	// First-party client; authorize with and without an org context.
	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Therapist web","redirect_uris":["https://therapist.test/cb"],"token_endpoint_auth_method":"none"}`)
	clientID := reg["client_id"].(string)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	authorize := func(org string) *url.URL {
		q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://therapist.test/cb"}, "response_type": {"code"}, "state": {"s1"},
			"resource": {"https://therapist.test/api"}, "scope": {"read"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
		if org != "" {
			q.Set("org", org)
		}
		resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc
	}
	if loc := authorize("org_nope"); loc.Host != "therapist.test" || loc.Path != "/cb" || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("unknown org must bounce to the client: %v", loc)
	}
	signIn := func(lc, email string) (int, map[string]any) {
		_, begin := do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"`+email+`"}`)
		return do(t, "POST", ts.URL+"/v1/login/email/finish?challenge="+begin["challenge_id"].(string), svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`)
	}
	exchange := func(redirectTo string) map[string]any {
		cb, _ := url.Parse(redirectTo)
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {cb.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://therapist.test/cb"}}
		code, tok := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
		if code != 200 {
			t.Fatalf("token: %d %v", code, tok)
		}
		return tok
	}

	// Bob is not a member: refused, and the challenge survives for alice.
	lc := authorize(orgID).Query().Get("login_challenge")
	if code, body := signIn(lc, "bob@x.test"); code != 403 || body["error"] != "not_a_member" {
		t.Fatalf("non-member: %d %v", code, body)
	}
	code, fin := signIn(lc, "alice@x.test")
	if code != 200 {
		t.Fatalf("alice sign-in: %d %v", code, fin)
	}
	tok := exchange(fin["redirect_to"].(string))
	claims, err := srv.Core.VerifyToken(tok["access_token"].(string), id)
	if err != nil || claims.Subject != "usr:"+aliceID || claims.Org != orgID || claims.OrgRole != "admin" {
		t.Fatalf("org claims: %+v %v", claims, err)
	}

	// Refresh keeps the org; after a demotion the role follows; an explicit
	// switch to an org she is not in is refused; a plain sign-in has no org.
	refresh := func(rt, org string) (int, map[string]any) {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {rt}}
		if org != "" {
			form.Set("org", org)
		}
		return do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	}
	do(t, "PUT", ts.URL+"/v1/orgs/"+orgID+"/members/"+bobID, svcTok, "application/json", `{"role":"admin"}`)
	do(t, "PUT", ts.URL+"/v1/orgs/"+orgID+"/members/"+aliceID, svcTok, "application/json", `{"role":"member"}`)
	code, r1 := refresh(tok["refresh_token"].(string), "")
	if code != 200 {
		t.Fatalf("refresh: %d %v", code, r1)
	}
	if c, _ := srv.Core.VerifyToken(r1["access_token"].(string), id); c.Org != orgID || c.OrgRole != "member" {
		t.Fatalf("refresh must re-resolve the role: %+v", c)
	}
	code, org2 := do(t, "POST", ts.URL+"/v1/orgs", svcTok, "application/json", `{"name":"Other Clinic","admin_user_id":"`+bobID+`"}`)
	if code != 201 {
		t.Fatalf("second org: %d %v", code, org2)
	}
	if code, body := refresh(r1["refresh_token"].(string), org2["id"].(string)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("switch to a foreign org: %d %v", code, body)
	}
	// A refused switch still consumed that refresh token (rotation), so
	// alice signs in again; without an org in the request there is no context.
	lc = authorize("").Query().Get("login_challenge")
	_, fin = signIn(lc, "alice@x.test")
	tok = exchange(fin["redirect_to"].(string))
	if c, _ := srv.Core.VerifyToken(tok["access_token"].(string), id); c.Org != "" || c.OrgRole != "" {
		t.Fatalf("no org requested, none granted: %+v", c)
	}
	// Switch into her org on refresh, then lose the membership: the next
	// refresh drops the context instead of failing.
	code, r2 := refresh(tok["refresh_token"].(string), orgID)
	if code != 200 {
		t.Fatalf("switch: %d %v", code, r2)
	}
	if c, _ := srv.Core.VerifyToken(r2["access_token"].(string), id); c.Org != orgID || c.OrgRole != "member" {
		t.Fatalf("switched claims: %+v", c)
	}
	if code, _ := do(t, "DELETE", ts.URL+"/v1/orgs/"+orgID+"/members/"+aliceID, svcTok, "", ""); code != 204 {
		t.Fatalf("remove alice: %d", code)
	}
	code, r3 := refresh(r2["refresh_token"].(string), "")
	if code != 200 {
		t.Fatalf("refresh after removal: %d %v", code, r3)
	}
	if c, _ := srv.Core.VerifyToken(r3["access_token"].(string), id); c.Org != "" {
		t.Fatalf("org must be dropped: %+v", c)
	}

	// Deleting the org and a user cleans memberships; export lists orgs.
	if code, body := do(t, "GET", ts.URL+"/v1/users/"+bobID+"/export", svcTok, "", ""); code != 200 || len(body["orgs"].([]any)) != 2 {
		t.Fatalf("export orgs: %d %v", code, body["orgs"])
	}
	if code, _ := do(t, "DELETE", ts.URL+"/v1/orgs/"+org2["id"].(string), svcTok, "", ""); code != 204 {
		t.Fatalf("delete org: %d", code)
	}
	if code, body := do(t, "GET", ts.URL+"/v1/orgs/"+org2["id"].(string), svcTok, "", ""); code != 404 || body["error"] != "not_found" {
		t.Fatalf("deleted org: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/v1/users/"+bobID+"/orgs", svcTok, "", ""); code != 200 || len(body["orgs"].([]any)) != 1 {
		t.Fatalf("bob orgs after: %d %v", code, body)
	}
	name := `{"name":"Sunny","status":"disabled"}`
	if code, body := do(t, "PATCH", ts.URL+"/v1/orgs/"+orgID, svcTok, "application/json", name); code != 200 || body["name"] != "Sunny" || body["status"] != "disabled" {
		t.Fatalf("patch org: %d %v", code, body)
	}
	if loc := authorize(orgID); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("disabled org must bounce: %v", loc)
	}
}

func TestOrgInviteHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	admin := "Bearer " + adminToken
	mail := &captureMail{}
	srv.Users.Mail = mail

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Therapist","slug":"therapist"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read"],"roles":{"user":["read"]}}`)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://therapist.test/login","rp_id":"therapist.test","origins":["https://therapist.test"],"default_roles":["user"],"open_signup":true}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)
	_, alice := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"email":"alice@x.test","method":"email","name":"Alice"}`)
	aliceID := alice["id"].(string)
	_, org := do(t, "POST", ts.URL+"/v1/orgs", svcTok, "application/json", `{"name":"Sunny Practice","admin_user_id":"`+aliceID+`"}`)
	orgID := org["id"].(string)
	inviteURL := ts.URL + "/v1/orgs/" + orgID + "/invites"

	if code, _ := do(t, "POST", inviteURL, "", "application/json", `{}`); code != 401 {
		t.Fatalf("invite without service token: %d", code)
	}
	if code, body := do(t, "POST", inviteURL, svcTok, "application/json", `{"email":"carol@x.test","role":"boss"}`); code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("bad role: %d %v", code, body)
	}
	if code, body := do(t, "POST", inviteURL, svcTok, "application/json", `{"email":"alice@x.test","role":"member"}`); code != 409 || body["error"] != "already_member" {
		t.Fatalf("invite a member: %d %v", code, body)
	}
	code, inv := do(t, "POST", inviteURL, svcTok, "application/json", `{"email":"Carol@x.test","role":"member","invited_by":"`+aliceID+`"}`)
	if code != 201 || inv["email"] != "carol@x.test" || inv["role"] != "member" || inv["invited_by"] != aliceID {
		t.Fatalf("invite: %d %v", code, inv)
	}
	if mail.to != "carol@x.test" || !strings.Contains(mail.text, "Alice (Therapist)") || !strings.Contains(mail.text, "Sunny Practice") {
		t.Fatalf("mail: to=%q text=%q", mail.to, mail.text)
	}
	if code, body := do(t, "GET", inviteURL, svcTok, "", ""); code != 200 || len(body["invites"].([]any)) != 1 {
		t.Fatalf("list invites: %d %v", code, body)
	}
	if code, body := do(t, "GET", ts.URL+"/admin/services/"+id+"/orgs/"+orgID+"/invites", admin, "", ""); code != 200 || len(body["invites"].([]any)) != 1 {
		t.Fatalf("admin list invites: %d %v", code, body)
	}
	// Sends to one address are capped like sign-in codes.
	for i := 0; i < 6; i++ {
		code, body := do(t, "POST", inviteURL, svcTok, "application/json", `{"email":"spam@x.test","role":"member"}`)
		if i < 4 && code != 201 {
			t.Fatalf("invite %d: %d %v", i, code, body)
		}
		if i == 5 && code != 429 {
			t.Fatalf("sixth invite to one address must be limited: %d %v", code, body)
		}
	}
	if code, _ := do(t, "DELETE", inviteURL+"/spam@x.test", svcTok, "", ""); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, body := do(t, "DELETE", inviteURL+"/spam@x.test", svcTok, "", ""); code != 404 || body["error"] != "invite_not_found" {
		t.Fatalf("revoke twice: %d %v", code, body)
	}

	// Carol signs in with a code (open pool): the invite becomes a membership.
	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Therapist web","redirect_uris":["https://therapist.test/cb"],"token_endpoint_auth_method":"none"}`)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	q := url.Values{"client_id": {reg["client_id"].(string)}, "redirect_uri": {"https://therapist.test/cb"}, "response_type": {"code"}, "state": {"s1"},
		"resource": {"https://therapist.test/api"}, "scope": {"read"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://therapist.test/api"}`)
	resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	lc := loc.Query().Get("login_challenge")
	_, begin := do(t, "POST", ts.URL+"/v1/login/email/begin", svcTok, "application/json", `{"login_challenge":"`+lc+`","email":"carol@x.test"}`)
	if code, body := do(t, "POST", ts.URL+"/v1/login/email/finish?challenge="+begin["challenge_id"].(string), svcTok, "application/json", `{"code":"`+mail.code(t)+`"}`); code != 200 {
		t.Fatalf("carol sign-in: %d %v", code, body)
	}
	_, members := do(t, "GET", ts.URL+"/v1/orgs/"+orgID+"/members", svcTok, "", "")
	found := false
	for _, m := range members["members"].([]any) {
		if mm := m.(map[string]any); mm["email"] == "carol@x.test" && mm["role"] == "member" {
			found = true
		}
	}
	if !found {
		t.Fatalf("carol must be a member after signing in: %v", members)
	}
	if code, body := do(t, "GET", inviteURL, svcTok, "", ""); code != 200 || len(body["invites"].([]any)) != 0 {
		t.Fatalf("invite must be consumed: %d %v", code, body)
	}
}

func TestPasswordHTTP(t *testing.T) {
	ts, _ := newServerWithStore(t, "https://auth.test")
	srv := lastServer
	srv.Users.Cost = bcrypt.MinCost
	admin := "Bearer " + adminToken

	_, svc := do(t, "POST", ts.URL+"/admin/services", admin, "application/json", `{"name":"Therapist","slug":"therapist"}`)
	id := svc["id"].(string)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/permissions", admin, "application/json", `{"scopes":["read","write"],"roles":{"participant":["read"],"researcher":["read","write"]}}`)
	do(t, "POST", ts.URL+"/admin/services/"+id+"/resources", admin, "application/json", `{"resource":"https://therapist.test/api"}`)
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://therapist.test/login","rp_id":"therapist.test","origins":["https://therapist.test"],"default_roles":["participant"],"open_signup":false}`)
	_, cred := do(t, "POST", ts.URL+"/admin/services/"+id+"/credentials", admin, "", "")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {cred["credential"].(string)}}
	_, tk := do(t, "POST", ts.URL+"/v1/token", "", "application/x-www-form-urlencoded", form.Encode())
	svcTok := "Bearer " + tk["access_token"].(string)

	// Import: a bcrypt hash straight from the old database, explicit role, no email.
	hash, _ := bcrypt.GenerateFromPassword([]byte("hunter22"), bcrypt.MinCost)
	body, _ := json.Marshal(map[string]any{"method": "password", "username": "p0042", "password_hash": string(hash), "roles": []string{"researcher"}})
	code, user := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", string(body))
	if code != 201 || user["method"] != "password" || user["username"] != "p0042" || user["email"] != "" || user["email_verified"] != true || user["roles"].([]any)[0] != "researcher" {
		t.Fatalf("import: %d %v", code, user)
	}
	if _, has := user["password_hash"]; has {
		t.Fatal("the hash must never be returned")
	}
	userID := user["id"].(string)
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"method":"password","username":"p0043","password":"short"}`); code != 400 || body["error"] != "invalid_request" {
		t.Fatalf("weak password: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/users", admin, "application/json", `{"method":"password","username":"P0042","password":"correct horse"}`); code != 409 || body["error"] != "identity_taken" {
		t.Fatalf("duplicate username: %d %v", code, body)
	}

	// The app cannot create password accounts on this closed pool; it can
	// once the pool opens, with an explicit role from the catalog.
	if code, body := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"method":"password","username":"p0050","password":"correct horse"}`); code != 403 || body["error"] != "signup_closed" {
		t.Fatalf("app create on closed pool: %d %v", code, body)
	}
	do(t, "PUT", ts.URL+"/admin/services/"+id+"/login", admin, "application/json", `{"login_url":"https://therapist.test/login","rp_id":"therapist.test","origins":["https://therapist.test"],"default_roles":["participant"],"open_signup":true}`)
	if code, body := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"method":"password","username":"p0050","password":"correct horse","roles":["researcher"]}`); code != 201 || body["username"] != "p0050" || body["roles"].([]any)[0] != "researcher" {
		t.Fatalf("app create on open pool: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/users", svcTok, "application/json", `{"method":"google","email":"g@x.test"}`); code != 400 {
		t.Fatalf("app create with another method: %d %v", code, body)
	}

	// Login through the parked authorization.
	_, reg := do(t, "POST", ts.URL+"/oauth/register", "", "application/json", `{"client_name":"Therapist web","redirect_uris":["https://therapist.test/cb"],"token_endpoint_auth_method":"none"}`)
	clientID := reg["client_id"].(string)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	authorize := func() string {
		q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://therapist.test/cb"}, "response_type": {"code"}, "state": {"s1"},
			"resource": {"https://therapist.test/api"}, "scope": {"read write"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
		resp, _ := noRedirect.Get(ts.URL + "/oauth/authorize?" + q.Encode())
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc.Query().Get("login_challenge")
	}
	lc := authorize()
	if code, _ := do(t, "POST", ts.URL+"/v1/login/password", "", "application/json", `{}`); code != 401 {
		t.Fatalf("without service token: %d", code)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"nope","username":"p0042","password":"hunter22"}`); code != 404 {
		t.Fatalf("unknown challenge: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"p0042","password":"hunter23"}`); code != 401 || body["error"] != "password_rejected" {
		t.Fatalf("wrong password: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"ghost","password":"hunter22"}`); code != 401 || body["error"] != "password_rejected" {
		t.Fatalf("unknown user must look the same: %d %v", code, body)
	}
	code, fin := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"P0042","password":"hunter22"}`)
	if code != 200 || fin["redirect_to"] == nil {
		t.Fatalf("login: %d %v", code, fin)
	}
	cb, _ := url.Parse(fin["redirect_to"].(string))
	form = url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {cb.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://therapist.test/cb"}}
	code, tok := do(t, "POST", ts.URL+"/oauth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if code != 200 {
		t.Fatalf("token: %d %v", code, tok)
	}
	claims, err := srv.Core.VerifyToken(tok["access_token"].(string), id)
	if err != nil || claims.Subject != "usr:"+userID || claims.PreferredUsername != "p0042" || claims.Email != "" || claims.Scope != "read write" {
		t.Fatalf("claims: %+v %v", claims, err)
	}
	// The challenge was consumed.
	if code, _ := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"p0042","password":"hunter22"}`); code != 404 {
		t.Fatalf("replayed challenge: %d", code)
	}

	// Ten wrong passwords lock the username, whatever the IP.
	lc = authorize()
	for i := 0; i < 10; i++ {
		do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"p0042","password":"wrong"}`)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/login/password", svcTok, "application/json", `{"login_challenge":"`+lc+`","username":"p0042","password":"hunter22"}`); code != 429 {
		t.Fatalf("locked username: %d %v", code, body)
	}

	// The product resets a password under its service token; the admin too.
	if code, body := do(t, "POST", ts.URL+"/v1/users/"+userID+"/password", svcTok, "application/json", `{"password":"brand new pass"}`); code != 200 || body["method"] != "password" {
		t.Fatalf("set password: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/admin/services/"+id+"/users/"+userID+"/password", admin, "application/json", `{"password":"x"}`); code != 400 {
		t.Fatalf("admin weak password: %d %v", code, body)
	}
	if code, body := do(t, "POST", ts.URL+"/v1/users/usr_ghost/password", svcTok, "application/json", `{"password":"brand new pass"}`); code != 404 {
		t.Fatalf("unknown user: %d %v", code, body)
	}
	// A password account may start passkey registration (conversion path).
	if code, body := do(t, "POST", ts.URL+"/v1/users/"+userID+"/passkeys/begin", svcTok, "", ""); code != 200 || body["options"] == nil {
		t.Fatalf("passkey begin for a password account: %d %v", code, body)
	}
}
