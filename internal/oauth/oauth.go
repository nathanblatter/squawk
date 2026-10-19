// Package oauth is the OAuth 2.1 authorization server for connectors (Claude
// on Nathan's phone, first). Clients register dynamically (RFC 7591), start
// an authorization-code + PKCE flow, the owner approves it in the console,
// and tokens come back as ES256 JWTs with rotating refresh tokens.
//
// Headless rule: this package never renders a page. GET /oauth/authorize
// parks the request and redirects to the console, which calls back through
// Approve or Deny.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/nathanblatter/squawk/internal/core"
	"github.com/nathanblatter/squawk/internal/jwt"
	"github.com/nathanblatter/squawk/internal/store"
)

const (
	// AccessTTL / RefreshTTL are Nathan's decision (2026-10-15): 1h / 30d.
	AccessTTL  = time.Hour
	RefreshTTL = 30 * 24 * time.Hour
	// AuthzTTL bounds how long an approval may sit in the console.
	AuthzTTL = 10 * time.Minute
	// CodeTTL is the authorization-code lifetime.
	CodeTTL = 5 * time.Minute

	// OwnerSubject is the sub claim for tokens the owner approved.
	OwnerSubject = "owner"

	// OrgRoleAdmin / OrgRoleMember mirror users.OrgRole*; the owner is
	// always admin of any org in any of the owner's services.
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// ErrNotMember: the signed-in user is not a member of the org the app asked
// for (or the org is disabled). The parked authorization is left intact so
// another account can still complete it.
var ErrNotMember = errors.New("oauth: not a member of the requested org")

// Error is an OAuth-shaped failure: an RFC 6749 error code, a description
// and the HTTP status to answer with.
type Error struct {
	Code, Description string
	Status            int
}

func (e *Error) Error() string { return "oauth: " + e.Code + ": " + e.Description }

func oerr(status int, code, desc string) *Error {
	return &Error{Code: code, Description: desc, Status: status}
}

// Server holds the dependencies.
type Server struct {
	Store  store.Store
	Core   *core.Core
	Issuer string
	Now    func() time.Time
	Log    *slog.Logger
}

// New builds a server on the core's store, ring and issuer.
func New(c *core.Core) *Server {
	return &Server{Store: c.Store, Core: c, Issuer: c.Issuer, Now: c.Now, Log: c.Log}
}

// ── metadata ───────────────────────────────────────────────────────────────

// Metadata is the RFC 8414 authorization-server document.
func (s *Server) Metadata() map[string]any {
	return map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + "/oauth/authorize",
		"token_endpoint":                        s.Issuer + "/oauth/token",
		"registration_endpoint":                 s.Issuer + "/oauth/register",
		"jwks_uri":                              s.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"resource_parameter_supported":          true,
	}
}

// ── dynamic client registration ────────────────────────────────────────────

// RegisterRequest is the RFC 7591 body subset we accept.
type RegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// Register validates and stores a client. The returned secret (if any) is
// shown exactly once.
func (s *Server) Register(ctx context.Context, req RegisterRequest, ip string) (store.OAuthClient, string, error) {
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		return store.OAuthClient{}, "", oerr(400, "invalid_redirect_uri", "1-10 redirect_uris required")
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			return store.OAuthClient{}, "", oerr(400, "invalid_redirect_uri", "redirect URIs must be absolute https URLs (http only for localhost)")
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	switch method {
	case "none", "client_secret_post", "client_secret_basic":
	default:
		return store.OAuthClient{}, "", oerr(400, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return store.OAuthClient{}, "", oerr(400, "invalid_client_metadata", "unsupported grant_type "+g)
		}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			return store.OAuthClient{}, "", oerr(400, "invalid_client_metadata", "unsupported response_type "+rt)
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if len(name) > 200 {
		name = name[:200]
	}
	c := store.OAuthClient{ID: random("nbc_"), Name: name, AuthMethod: method, RedirectURIs: req.RedirectURIs, CreatedAt: s.Now()}
	secret := ""
	if method != "none" {
		secret = random("nbcs_")
		c.SecretHash = core.HashSecret(secret)
	}
	if err := s.Store.CreateOAuthClient(ctx, c); err != nil {
		return store.OAuthClient{}, "", err
	}
	s.audit(ctx, "oauth.client.register", "anonymous", "", "client="+c.ID+" name="+name, ip)
	return c, secret, nil
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// ── authorize ──────────────────────────────────────────────────────────────

// AuthzParams are the query parameters of GET /oauth/authorize.
type AuthzParams struct {
	ClientID, RedirectURI, ResponseType, State, Scope, Challenge, Method, Resource string
	// Org asks for an org context (auth-service-15): the tokens carry the org
	// and the user's role in it; a non-member cannot complete the sign-in.
	Org string
}

// ParseAuthz reads the parameters from a query.
func ParseAuthz(v url.Values) AuthzParams {
	return AuthzParams{ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), ResponseType: v.Get("response_type"),
		State: v.Get("state"), Scope: v.Get("scope"), Challenge: v.Get("code_challenge"), Method: v.Get("code_challenge_method"), Resource: v.Get("resource"),
		Org: v.Get("org")}
}

// AuthzOutcome tells the HTTP layer what to do: either redirect to the
// console to approve, or redirect back to the client with an error. A nil
// outcome with a non-nil error means the client/redirect could not be
// trusted and nothing may be redirected.
type AuthzOutcome struct {
	ApproveURL  string // non-empty: send the browser here
	RedirectURI string // for errors: where to bounce
	Err         *Error // for errors
	State       string
}

// BeginAuthorize validates the request, parks it, and says where to send
// the browser.
func (s *Server) BeginAuthorize(ctx context.Context, p AuthzParams, ip string) (AuthzOutcome, error) {
	c, err := s.Store.GetOAuthClient(ctx, p.ClientID)
	if p.ClientID == "" || errors.Is(err, store.ErrNotFound) {
		return AuthzOutcome{}, oerr(400, "invalid_request", "unknown client_id")
	}
	if err != nil {
		return AuthzOutcome{}, err
	}
	if p.RedirectURI == "" || !contains(c.RedirectURIs, p.RedirectURI) {
		return AuthzOutcome{}, oerr(400, "invalid_request", "redirect_uri is not registered for this client")
	}
	bounce := func(code, desc string) AuthzOutcome {
		return AuthzOutcome{RedirectURI: p.RedirectURI, State: p.State, Err: oerr(302, code, desc)}
	}
	if p.ResponseType != "code" {
		return bounce("unsupported_response_type", "response_type must be code"), nil
	}
	if p.Challenge == "" || p.Method != "S256" {
		return bounce("invalid_request", "PKCE with code_challenge_method=S256 is required"), nil
	}
	if p.Resource == "" {
		return bounce("invalid_target", "resource is required (RFC 8707)"), nil
	}
	svc, err := s.Store.GetServiceByResource(ctx, p.Resource)
	if errors.Is(err, store.ErrNotFound) {
		return bounce("invalid_target", "unknown resource"), nil
	}
	if err != nil {
		return AuthzOutcome{}, err
	}
	if svc.Status != "active" {
		return bounce("invalid_target", "service is disabled"), nil
	}
	// A request for a scope the service never declared is an error, not a
	// silent trim. For owner-only services the grant is fixed now (the owner
	// may have anything in the catalog); for user-pool services the requested
	// scope is kept and narrowed to the user's roles at login.
	granted, ok := core.GrantScope(p.Scope, svc.Scopes)
	if !ok {
		return bounce("invalid_scope", "requested scope is not in this service's catalog"), nil
	}
	if p.Org != "" {
		org, err := s.Store.GetOrg(ctx, svc.ID, p.Org)
		if errors.Is(err, store.ErrNotFound) {
			return bounce("invalid_request", "unknown org for this service"), nil
		}
		if err != nil {
			return AuthzOutcome{}, err
		}
		if org.Status != "active" {
			return bounce("access_denied", "org is disabled"), nil
		}
	}
	a := store.AuthzRequest{
		ID: random(""), ClientID: c.ID, RedirectURI: p.RedirectURI, State: p.State, Scope: granted,
		Challenge: p.Challenge, Resource: p.Resource, ServiceID: svc.ID, Org: p.Org, ExpiresAt: s.Now().Add(AuthzTTL),
	}
	if err := s.Store.PutAuthzRequest(ctx, a); err != nil {
		return AuthzOutcome{}, err
	}
	s.audit(ctx, "oauth.authorize.request", "anonymous", svc.ID, "client="+c.ID+" authz="+a.ID, ip)
	if svc.LoginURL != "" {
		// User pool: the product's own login page runs the ceremony (slice 3).
		loc, err := RedirectWith(svc.LoginURL, url.Values{"login_challenge": {a.ID}})
		if err != nil {
			return AuthzOutcome{}, err
		}
		return AuthzOutcome{ApproveURL: loc}, nil
	}
	return AuthzOutcome{ApproveURL: s.Issuer + "/admin?approve=" + url.QueryEscape(a.ID)}, nil
}

// CompleteForUser finishes a pending authorization for an end user who just
// authenticated through the product's login page. Scope = the request's
// (already catalog-checked) scope ∩ the user's allowed scopes; first-party
// clients need no consent screen. Returns the redirect URL for the browser.
func (s *Server) CompleteForUser(ctx context.Context, authzID string, user store.User, allowed []string, ip string) (string, error) {
	a, err := s.Store.GetAuthzRequest(ctx, authzID, s.Now())
	if err != nil {
		return "", err
	}
	if a.ServiceID != user.ServiceID {
		return "", oerr(400, "invalid_request", "login_challenge belongs to another service")
	}
	// Membership is checked before the request is consumed: a non-member
	// gets a clear refusal and the page can let someone else sign in.
	orgRole := ""
	if a.Org != "" {
		var ok bool
		if orgRole, ok, err = s.orgRole(ctx, a.ServiceID, a.Org, "usr:"+user.ID); err != nil {
			return "", err
		} else if !ok {
			s.audit(ctx, "oauth.org.denied", "usr:"+user.ID, a.ServiceID, "client="+a.ClientID+" org="+a.Org+" not a member", ip)
			return "", ErrNotMember
		}
	}
	if err := s.Store.DeleteAuthzRequest(ctx, authzID); err != nil {
		return "", err
	}
	granted, ok := core.GrantScope(a.Scope, allowed)
	if !ok {
		// The user lacks a role for some requested scope: grant the intersection.
		granted, _ = core.GrantScope("", intersect(strings.Fields(a.Scope), allowed))
	}
	code := random("nbac_")
	if err := s.Store.CreateCode(ctx, core.HashSecret(code), store.Code{
		ClientID: a.ClientID, RedirectURI: a.RedirectURI, Challenge: a.Challenge, Scope: granted,
		Subject: "usr:" + user.ID, ServiceID: a.ServiceID, Org: a.Org, OrgRole: orgRole, ExpiresAt: s.Now().Add(CodeTTL),
	}); err != nil {
		return "", err
	}
	s.audit(ctx, "oauth.approve", "usr:"+user.ID, a.ServiceID, "client="+a.ClientID+" scope="+granted+orgDetail(a.Org, orgRole), ip)
	return RedirectWith(a.RedirectURI, url.Values{"code": {code}, "state": {a.State}})
}

// orgRole resolves a subject's role in an org: the membership's role for a
// user, admin for the owner. ok is false for non-members and disabled orgs.
func (s *Server) orgRole(ctx context.Context, serviceID, orgID, subject string) (role string, ok bool, err error) {
	org, err := s.Store.GetOrg(ctx, serviceID, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil || org.Status != "active" {
		return "", false, err
	}
	if subject == OwnerSubject {
		return OrgRoleAdmin, true, nil
	}
	userID, isUser := strings.CutPrefix(subject, "usr:")
	if !isUser {
		return "", false, nil
	}
	m, err := s.Store.GetOrgMember(ctx, serviceID, orgID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return m.Role, true, nil
}

func orgDetail(org, role string) string {
	if org == "" {
		return ""
	}
	return " org=" + org + " org_role=" + role
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

// PendingApproval is what the console shows the owner.
type PendingApproval struct {
	ID         string
	ClientName string
	ClientID   string
	Service    store.Service
	Scope      string
	Resource   string
	ExpiresAt  time.Time
}

// Pending loads an authorization request for display.
func (s *Server) Pending(ctx context.Context, id string) (PendingApproval, error) {
	a, err := s.Store.GetAuthzRequest(ctx, id, s.Now())
	if err != nil {
		return PendingApproval{}, err
	}
	c, err := s.Store.GetOAuthClient(ctx, a.ClientID)
	if err != nil {
		return PendingApproval{}, err
	}
	svc, err := s.Store.GetService(ctx, a.ServiceID)
	if err != nil {
		return PendingApproval{}, err
	}
	name := c.Name
	if name == "" {
		name = c.ID
	}
	return PendingApproval{ID: a.ID, ClientName: name, ClientID: c.ID, Service: svc, Scope: a.Scope, Resource: a.Resource, ExpiresAt: a.ExpiresAt}, nil
}

// Approve issues a code for a pending request as the owner (console approval)
// and returns the redirect URL for the browser.
func (s *Server) Approve(ctx context.Context, id string, ip string) (string, error) {
	return s.completeForOwner(ctx, id, "console", ip)
}

// CompleteForOwner finishes a pending authorization for the owner, who just
// proved an owner passkey on the product's own login page. The owner gets the
// request's full (catalog-checked) scope: there is no role to narrow to.
func (s *Server) CompleteForOwner(ctx context.Context, authzID string, ip string) (string, error) {
	return s.completeForOwner(ctx, authzID, "login", ip)
}

func (s *Server) completeForOwner(ctx context.Context, id, via, ip string) (string, error) {
	a, err := s.Store.GetAuthzRequest(ctx, id, s.Now())
	if err != nil {
		return "", err
	}
	if err := s.Store.DeleteAuthzRequest(ctx, id); err != nil {
		return "", err
	}
	// The owner is admin of every org in the owner's services.
	orgRole := ""
	if a.Org != "" {
		orgRole = OrgRoleAdmin
	}
	code := random("nbac_")
	if err := s.Store.CreateCode(ctx, core.HashSecret(code), store.Code{
		ClientID: a.ClientID, RedirectURI: a.RedirectURI, Challenge: a.Challenge, Scope: a.Scope,
		Subject: OwnerSubject, ServiceID: a.ServiceID, Org: a.Org, OrgRole: orgRole, ExpiresAt: s.Now().Add(CodeTTL),
	}); err != nil {
		return "", err
	}
	s.audit(ctx, "oauth.approve", "owner", a.ServiceID, "client="+a.ClientID+" scope="+a.Scope+" via="+via+orgDetail(a.Org, orgRole), ip)
	return RedirectWith(a.RedirectURI, url.Values{"code": {code}, "state": {a.State}})
}

// Deny discards a pending request and returns the error redirect.
func (s *Server) Deny(ctx context.Context, id string, ip string) (string, error) {
	a, err := s.Store.GetAuthzRequest(ctx, id, s.Now())
	if err != nil {
		return "", err
	}
	if err := s.Store.DeleteAuthzRequest(ctx, id); err != nil {
		return "", err
	}
	s.audit(ctx, "oauth.deny", "owner", a.ServiceID, "client="+a.ClientID, ip)
	return RedirectWith(a.RedirectURI, url.Values{"error": {"access_denied"}, "state": {a.State}})
}

// ── token ──────────────────────────────────────────────────────────────────

// TokenRequest is the parsed token-endpoint form.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Code         string
	CodeVerifier string
	RedirectURI  string
	RefreshToken string
	// Org, on a refresh_token grant, switches the org context: the new
	// tokens carry this org (the subject must be a member). Empty keeps the
	// token's current org.
	Org string
}

// TokenResponse is the RFC 6749 §5.1 success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles authorization_code and refresh_token grants. Failures are
// *Error values; anything else is a server fault.
func (s *Server) Token(ctx context.Context, req TokenRequest, ip string) (TokenResponse, error) {
	c, err := s.authenticateClient(ctx, req)
	if err != nil {
		return TokenResponse{}, err
	}
	switch req.GrantType {
	case "authorization_code":
		return s.exchangeCode(ctx, c, req, ip)
	case "refresh_token":
		return s.refresh(ctx, c, req, ip)
	default:
		return TokenResponse{}, oerr(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (s *Server) authenticateClient(ctx context.Context, req TokenRequest) (store.OAuthClient, error) {
	if req.ClientID == "" {
		return store.OAuthClient{}, oerr(401, "invalid_client", "client_id is required")
	}
	c, err := s.Store.GetOAuthClient(ctx, req.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return store.OAuthClient{}, oerr(401, "invalid_client", "unknown client")
	}
	if err != nil {
		return store.OAuthClient{}, err
	}
	if c.AuthMethod != "none" {
		if c.SecretHash == "" || req.ClientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(core.HashSecret(req.ClientSecret)), []byte(c.SecretHash)) != 1 {
			return store.OAuthClient{}, oerr(401, "invalid_client", "client authentication failed")
		}
	}
	return c, nil
}

func (s *Server) exchangeCode(ctx context.Context, c store.OAuthClient, req TokenRequest, ip string) (TokenResponse, error) {
	if req.Code == "" || req.CodeVerifier == "" {
		return TokenResponse{}, oerr(400, "invalid_request", "code and code_verifier are required")
	}
	row, err := s.Store.ConsumeCode(ctx, core.HashSecret(req.Code), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		return TokenResponse{}, oerr(400, "invalid_grant", "code is invalid, expired, or already used")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if row.ClientID != c.ID || (req.RedirectURI != "" && req.RedirectURI != row.RedirectURI) || !VerifyPKCE(req.CodeVerifier, row.Challenge) {
		s.audit(ctx, "oauth.token.denied", "anonymous", row.ServiceID, "client="+c.ID+" code mismatch", ip)
		return TokenResponse{}, oerr(400, "invalid_grant", "code does not match this client, redirect_uri, or code_verifier")
	}
	return s.mint(ctx, c.ID, row.ServiceID, row.Subject, row.Scope, row.Org, row.OrgRole, random(""), "oauth.token", ip)
}

func (s *Server) refresh(ctx context.Context, c store.OAuthClient, req TokenRequest, ip string) (TokenResponse, error) {
	if req.RefreshToken == "" {
		return TokenResponse{}, oerr(400, "invalid_request", "refresh_token is required")
	}
	row, reused, err := s.Store.ConsumeRefresh(ctx, core.HashSecret(req.RefreshToken), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token is invalid or expired")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if reused {
		// Replay: someone holds a token that was already rotated away. Kill the
		// whole family so neither party keeps access.
		if err := s.Store.RevokeRefreshFamily(ctx, row.Family); err != nil {
			return TokenResponse{}, err
		}
		s.audit(ctx, "oauth.refresh.reuse", "anonymous", row.ServiceID, "client="+c.ID+" family="+row.Family+" revoked", ip)
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token was already used; all sessions in its family are revoked")
	}
	if row.ClientID != c.ID {
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token belongs to another client")
	}
	var nb time.Time
	switch {
	case row.Subject == OwnerSubject:
		if nb, err = s.Store.GetOwnerNotBefore(ctx); err != nil {
			return TokenResponse{}, err
		}
	case strings.HasPrefix(row.Subject, "usr:"):
		user, err := s.Store.GetUser(ctx, row.ServiceID, strings.TrimPrefix(row.Subject, "usr:"))
		if errors.Is(err, store.ErrNotFound) || (err == nil && user.Status != "active") {
			s.audit(ctx, "oauth.refresh.denied", row.Subject, row.ServiceID, "client="+c.ID+" user missing or disabled", ip)
			return TokenResponse{}, oerr(400, "invalid_grant", "account is not active")
		}
		if err != nil {
			return TokenResponse{}, err
		}
		nb = user.NotBefore
	}
	if !nb.IsZero() && row.IssuedAt.Before(nb) {
		s.audit(ctx, "oauth.refresh.denied", row.Subject, row.ServiceID, "client="+c.ID+" issued before logout-everywhere", ip)
		return TokenResponse{}, oerr(400, "invalid_grant", "session was signed out everywhere; sign in again")
	}
	// Org context: an explicit switch must resolve to a membership; a carried
	// context is re-resolved and silently dropped when the membership is gone
	// (the app sees no org claim and offers the picker again).
	org, orgRole := row.Org, ""
	if req.Org != "" {
		org = req.Org
	}
	if org != "" {
		role, ok, err := s.orgRole(ctx, row.ServiceID, org, row.Subject)
		if err != nil {
			return TokenResponse{}, err
		}
		switch {
		case ok:
			orgRole = role
		case req.Org != "":
			s.audit(ctx, "oauth.org.denied", row.Subject, row.ServiceID, "client="+c.ID+" org="+org+" not a member", ip)
			return TokenResponse{}, oerr(400, "invalid_grant", "not a member of the requested org")
		default:
			s.audit(ctx, "oauth.org.dropped", row.Subject, row.ServiceID, "client="+c.ID+" org="+org, ip)
			org = ""
		}
	}
	return s.mint(ctx, c.ID, row.ServiceID, row.Subject, row.Scope, org, orgRole, row.Family, "oauth.refresh", ip)
}

func (s *Server) mint(ctx context.Context, clientID, serviceID, subject, scope, org, orgRole, family, kind, ip string) (TokenResponse, error) {
	now := s.Now()
	email, username, verified := "", "", false
	if id, ok := strings.CutPrefix(subject, "usr:"); ok {
		if user, err := s.Store.GetUser(ctx, serviceID, id); err == nil {
			email, username, verified = user.Email, user.Username, user.EmailVerified
		}
	}
	access, err := jwt.Sign(ctx, s.Core.Ring.Active(), jwt.Claims{
		Issuer: s.Issuer, Subject: subject, Audience: serviceID, Scope: scope, ClientID: clientID, Email: email, PreferredUsername: username, EmailVerified: verified,
		Org: org, OrgRole: orgRole, IssuedAt: now.Unix(), Expires: now.Add(AccessTTL).Unix(),
	})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("oauth: sign: %w", err)
	}
	refresh := random("nbrt_")
	if err := s.Store.CreateRefresh(ctx, store.RefreshToken{
		Hash: core.HashSecret(refresh), Family: family, ClientID: clientID, ServiceID: serviceID, Subject: subject, Scope: scope,
		Org: org, OrgRole: orgRole, IssuedAt: now, ExpiresAt: now.Add(RefreshTTL),
	}); err != nil {
		return TokenResponse{}, err
	}
	s.audit(ctx, kind, subject, serviceID, "client="+clientID+" family="+family+orgDetail(org, orgRole), ip)
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(AccessTTL.Seconds()), RefreshToken: refresh, Scope: scope}, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// VerifyPKCE checks an S256 code_verifier against the stored challenge.
// "plain" is forbidden by OAuth 2.1 and never offered.
func VerifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// RedirectWith appends params to a redirect URI, dropping empty values.
func RedirectWith(redirectURI string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			if v != "" {
				q.Set(k, v)
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Server) audit(ctx context.Context, kind, actor, serviceID, detail, ip string) {
	e := store.AuditEvent{At: s.Now(), Kind: kind, Actor: actor, ServiceID: serviceID, Detail: detail, IP: ip}
	if err := s.Store.AppendAudit(ctx, e); err != nil {
		s.Log.Error("audit write failed", "kind", kind, "err", err)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func random(prefix string) string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("oauth: crypto/rand failed: %v", err))
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}
