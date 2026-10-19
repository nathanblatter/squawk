package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nathanblatter/squawk/internal/core"
	"github.com/nathanblatter/squawk/internal/oauth"
	"github.com/nathanblatter/squawk/internal/owner"
	"github.com/nathanblatter/squawk/internal/ratelimit"
	"github.com/nathanblatter/squawk/internal/store"
	"github.com/nathanblatter/squawk/internal/users"
)

// Slice 3: end-user accounts and login, driven by a product's backend with
// its service token. The product owns the screens; these endpoints own the
// ceremonies and the records.

func (s *Server) userRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/users", s.requireService(s.createUser))
	mux.HandleFunc("GET /v1/users", s.requireService(s.listUsers))
	mux.HandleFunc("GET /v1/users/{id}", s.requireService(s.getUser))
	mux.HandleFunc("PATCH /v1/users/{id}", s.requireService(s.updateUser))
	mux.HandleFunc("POST /v1/users/{id}/logout-everywhere", s.requireService(s.userLogoutEverywhere))
	mux.HandleFunc("DELETE /v1/users/{id}", s.requireService(s.deleteUser))
	mux.HandleFunc("GET /v1/users/{id}/export", s.requireService(s.exportUser))
	mux.HandleFunc("GET /v1/users/{id}/passkeys", s.requireService(s.listUserPasskeys))
	mux.HandleFunc("POST /v1/users/{id}/passkeys/begin", s.requireService(s.userPasskeyBegin))
	mux.HandleFunc("POST /v1/users/{id}/passkeys/finish", s.requireService(s.userPasskeyFinish))
	mux.HandleFunc("POST /v1/login/passkey/begin", s.requireService(s.loginPasskeyBegin))
	mux.HandleFunc("POST /v1/login/passkey/finish", s.requireService(s.loginPasskeyFinish))
	mux.HandleFunc("POST /v1/login/owner/begin", s.requireService(s.loginOwnerBegin))
	mux.HandleFunc("POST /v1/login/owner/finish", s.requireService(s.loginOwnerFinish))
	mux.HandleFunc("POST /v1/login/passkey/activate/begin", s.requireService(s.loginPasskeyActivateBegin))
	mux.HandleFunc("POST /v1/login/passkey/activate/finish", s.requireService(s.loginPasskeyActivateFinish))
	mux.HandleFunc("POST /v1/login/email/begin", s.requireService(s.loginEmailBegin))
	mux.HandleFunc("POST /v1/login/email/finish", s.requireService(s.loginEmailFinish))
	mux.HandleFunc("POST /v1/users/{id}/email/verify/begin", s.requireService(s.userVerifyEmailBegin))
	mux.HandleFunc("POST /v1/users/{id}/email/verify/finish", s.requireService(s.userVerifyEmailFinish))
	mux.HandleFunc("GET /v1/login/google/start", s.googleStart)
	mux.HandleFunc("GET /v1/login/google/callback", s.googleCallback)
	mux.HandleFunc("PUT /admin/services/{id}/login", s.requireAdmin(s.setLogin))
	mux.HandleFunc("POST /admin/services/{id}/users", s.requireAdmin(s.adminCreateUser))
	mux.HandleFunc("GET /admin/services/{id}/users", s.requireAdmin(s.adminListUsers))
}

// callerService loads the service behind the request's service token.
func (s *Server) callerService(w http.ResponseWriter, r *http.Request) (store.Service, bool) {
	id, _ := serviceFrom(r)
	svc, err := s.Core.GetService(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return store.Service{}, false
	}
	return svc, true
}

// userFail maps users-package errors to responses; returns true when it wrote.
func (s *Server) userFail(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, users.ErrUserNotFound), errors.Is(err, users.ErrOrgNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	case errors.Is(err, users.ErrNotMember):
		writeJSON(w, 404, map[string]string{"error": "not_a_member"})
	case errors.Is(err, users.ErrInviteNotFound):
		writeJSON(w, 404, map[string]string{"error": "invite_not_found"})
	case errors.Is(err, users.ErrAlreadyMember):
		writeJSON(w, 409, map[string]string{"error": "already_member"})
	case errors.Is(err, users.ErrOrgDisabled):
		writeJSON(w, 409, map[string]string{"error": "org_disabled"})
	case errors.Is(err, users.ErrLastAdmin):
		writeJSON(w, 409, map[string]string{"error": "last_admin", "detail": "an org must keep at least one admin; promote someone else first or delete the org"})
	case errors.Is(err, users.ErrInvalidOrgName), errors.Is(err, users.ErrInvalidOrgRole):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, users.ErrIdentityTaken):
		writeJSON(w, 409, map[string]string{"error": "identity_taken"})
	case errors.Is(err, users.ErrNotUserPool), errors.Is(err, users.ErrNoWebAuthn):
		writeJSON(w, 409, map[string]string{"error": "service_not_configured", "detail": err.Error()})
	case errors.Is(err, users.ErrInvalidEmail), errors.Is(err, users.ErrInvalidRole), errors.Is(err, users.ErrWrongMethod), errors.Is(err, users.ErrInvalidMethod):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, users.ErrSignupClosed):
		writeJSON(w, 403, map[string]string{"error": "signup_closed", "detail": "this service does not accept sign-ups; the owner creates accounts"})
	case errors.Is(err, users.ErrEmailDisabled):
		writeJSON(w, 404, map[string]string{"error": "email_disabled", "detail": "this server has no mail outbox configured"})
	case errors.Is(err, users.ErrAlreadyVerified):
		writeJSON(w, 409, map[string]string{"error": "already_verified"})
	case errors.Is(err, users.ErrCodeRejected):
		writeJSON(w, 401, map[string]string{"error": "code_rejected", "detail": "wrong code; try again"})
	case errors.Is(err, users.ErrCeremony):
		writeJSON(w, 401, map[string]string{"error": "code_rejected", "detail": "code expired, already used or out of attempts; request a new one"})
	case errors.Is(err, users.ErrDisabled):
		writeJSON(w, 403, map[string]string{"error": "account_disabled"})
	case errors.Is(err, users.ErrEmailUnverified):
		writeJSON(w, 403, map[string]string{"error": "email_unverified"})
	default:
		s.fail(w, err)
	}
	return true
}

func userJSON(u store.User) map[string]any {
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	out := map[string]any{"id": u.ID, "service_id": u.ServiceID, "method": u.Method, "email": u.Email, "email_verified": u.EmailVerified, "name": u.Name,
		"roles": roles, "status": u.Status, "created_at": u.CreatedAt.UTC().Format(time.RFC3339)}
	if !u.LastLoginAt.IsZero() {
		out["last_login_at"] = u.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct{ Email, Name string }
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Users.Create(r.Context(), svc, in.Email, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, userJSON(u))
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	list, next, err := s.Users.List(r.Context(), svc.ID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, userJSON(u))
	}
	writeJSON(w, 200, map[string]any{"users": out, "next": next})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	u, err := s.Users.Get(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, userJSON(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Roles  *[]string
		Status *string
		Name   *string
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Users.Update(r.Context(), svc, r.PathValue("id"), in.Roles, in.Status, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, userJSON(u))
}

func (s *Server) userLogoutEverywhere(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.LogoutEverywhere(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

// deleteUser is permanent (auth-service-13). The product is responsible for
// its own confirmation / step-up before calling it.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.Delete(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) exportUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	exp, err := s.Users.Export(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+exp.User.ID+`-export.json"`)
	writeJSON(w, 200, exp)
}

func (s *Server) listUserPasskeys(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if _, err := s.Users.Get(r.Context(), svc.ID, r.PathValue("id")); s.userFail(w, err) {
		return
	}
	keys, err := s.Users.Store.ListUserPasskeys(r.Context(), svc.ID, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"id": k.ID, "name": k.Name, "created_at": k.CreatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, 200, map[string]any{"passkeys": out})
}

func (s *Server) userPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	opts, chID, err := s.Users.BeginRegisterPasskey(r.Context(), svc, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) userPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	q := r.URL.Query()
	pk, authzID, err := s.Users.FinishRegisterPasskey(r.Context(), svc, q.Get("challenge"), q.Get("name"), r)
	if errors.Is(err, users.ErrCeremony) {
		writeJSON(w, 400, map[string]string{"error": "passkey_rejected"})
		return
	}
	if s.userFail(w, err) {
		return
	}
	out := map[string]any{"id": pk.ID, "name": pk.Name, "user_id": pk.UserID, "created_at": pk.CreatedAt.UTC().Format(time.RFC3339)}
	if authzID != "" {
		// Registration came from a passkey activation: finish that sign-in too.
		user, err := s.Users.Get(r.Context(), svc.ID, pk.UserID)
		if s.userFail(w, err) {
			return
		}
		loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge expired; the passkey is registered, sign in again"})
			return
		}
		if s.completeFail(w, err) {
			return
		}
		out["redirect_to"] = loc
	}
	writeJSON(w, 201, out)
}

// completeFail maps the errors of OAuth completion after a successful
// ceremony; returns true when it wrote.
func (s *Server) completeFail(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge expired; start over"})
	case errors.Is(err, oauth.ErrNotMember):
		writeJSON(w, 403, map[string]string{"error": "not_a_member", "detail": "this account is not a member of the requested org; the login_challenge is still valid for another account"})
	default:
		return s.oauthFail(w, err)
	}
	return true
}

// pendingFor validates a login_challenge against the calling service.
func (s *Server) pendingFor(w http.ResponseWriter, r *http.Request, svc store.Service, authzID string) bool {
	p, err := s.OAuth.Pending(r.Context(), authzID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && p.Service.ID != svc.ID) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge is unknown, expired, or belongs to another service"})
		return false
	}
	if err != nil {
		s.fail(w, err)
		return false
	}
	return true
}

func (s *Server) loginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		LoginChallenge string `json:"login_challenge"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !s.pendingFor(w, r, svc, in.LoginChallenge) {
		return
	}
	opts, chID, err := s.Users.BeginLoginPasskey(r.Context(), svc, in.LoginChallenge)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

func (s *Server) loginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	user, authzID, err := s.Users.FinishLoginPasskey(r.Context(), svc, r.URL.Query().Get("challenge"), r)
	if errors.Is(err, users.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 401, map[string]string{"error": "passkey_rejected"})
		return
	}
	if s.userFail(w, err) {
		return
	}
	loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
	if s.completeFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"redirect_to": loc, "user": userJSON(user)})
}

// loginOwnerBegin starts an owner passkey sign-in on a product's login page:
// the owner's RP ID with the service's origins, bound to the parked authz.
func (s *Server) loginOwnerBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		LoginChallenge string `json:"login_challenge"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !s.pendingFor(w, r, svc, in.LoginChallenge) {
		return
	}
	opts, chID, err := s.Owner.BeginLoginFor(r.Context(), svc, in.LoginChallenge)
	switch {
	case errors.Is(err, owner.ErrNoPasskeys):
		writeJSON(w, 409, map[string]string{"error": "setup_required", "detail": "the owner has no passkey registered"})
		return
	case errors.Is(err, owner.ErrNoOrigins):
		writeJSON(w, 409, map[string]string{"error": "service_not_configured", "detail": err.Error()})
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "options": opts})
}

// loginOwnerFinish verifies the owner's assertion and completes the parked
// authorization with sub=owner.
func (s *Server) loginOwnerFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	authzID, err := s.Owner.FinishLoginFor(r.Context(), svc, r.URL.Query().Get("challenge"), r)
	if errors.Is(err, owner.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		writeJSON(w, 401, map[string]string{"error": "passkey_rejected"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	loc, err := s.OAuth.CompleteForOwner(r.Context(), authzID, clientIP(r))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge expired; start over"})
		return
	}
	if s.oauthFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"redirect_to": loc, "subject": oauth.OwnerSubject})
}

// googleStart is hit by the browser from the product's login page.
func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if !s.Google.Enabled() {
		writeJSON(w, 404, map[string]string{"error": "google_disabled"})
		return
	}
	authzID := r.URL.Query().Get("login_challenge")
	p, err := s.OAuth.Pending(r.Context(), authzID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && p.Service.LoginURL == "") {
		writeJSON(w, 404, map[string]string{"error": "not_found", "detail": "login_challenge is unknown or expired"})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	state, err := s.Users.SaveGoogleState(r.Context(), p.Service.ID, authzID)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, s.Google.StartURL(state), http.StatusFound) //nolint:gosec // destination is Google's configured auth endpoint, not user input
}

// googleCallback completes the authorization for the Google identity.
func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.Google.Enabled() {
		writeJSON(w, 404, map[string]string{"error": "google_disabled"})
		return
	}
	q := r.URL.Query()
	serviceID, authzID, err := s.Users.LoadGoogleState(r.Context(), q.Get("state"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": "state is unknown or expired; start the sign-in again"})
		return
	}
	svc, err := s.Core.GetService(r.Context(), serviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	backToLogin := func(reason string) {
		loc, _ := oauth.RedirectWith(svc.LoginURL, url.Values{"login_challenge": {authzID}, "error": {reason}})
		http.Redirect(w, r, loc, http.StatusFound)
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		backToLogin("google_" + strings.TrimSpace(q.Get("error")))
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	identity, err := s.Google.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
		s.Log.Warn("google exchange failed", "err", err)
		backToLogin("google_exchange_failed")
		return
	}
	user, err := s.Users.LoginGoogle(r.Context(), svc, identity, clientIP(r))
	switch {
	case errors.Is(err, users.ErrDisabled):
		backToLogin("account_disabled")
		return
	case errors.Is(err, users.ErrEmailUnverified):
		backToLogin("email_unverified")
		return
	case errors.Is(err, users.ErrSignupClosed):
		backToLogin("signup_closed")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
	if errors.Is(err, store.ErrNotFound) {
		backToLogin("expired")
		return
	}
	if errors.Is(err, oauth.ErrNotMember) {
		backToLogin("not_a_member")
		return
	}
	if s.oauthFail(w, err) {
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (s *Server) setLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LoginURL     string   `json:"login_url"`
		RPID         string   `json:"rp_id"`
		Origins      []string `json:"origins"`
		DefaultRoles []string `json:"default_roles"`
		OpenSignup   bool     `json:"open_signup"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	svc, err := s.Core.SetLogin(r.Context(), r.PathValue("id"), in.LoginURL, in.RPID, in.Origins, in.DefaultRoles, in.OpenSignup, s.actor(r))
	switch {
	case errors.Is(err, core.ErrInvalidLogin):
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "detail": err.Error()})
	case errors.Is(err, core.ErrServiceNotFound):
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, 200, serviceJSON(svc))
	}
}

// adminService loads the service named in the path for the owner's user routes.
func (s *Server) adminService(w http.ResponseWriter, r *http.Request) (store.Service, bool) {
	svc, err := s.Core.GetService(r.Context(), r.PathValue("id"))
	if errors.Is(err, core.ErrServiceNotFound) {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return store.Service{}, false
	}
	if err != nil {
		s.fail(w, err)
		return store.Service{}, false
	}
	return svc, true
}

// adminCreateUser provisions an account from the console, open pool or not.
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	var in struct{ Email, Name, Method string }
	if !readJSON(w, r, &in) {
		return
	}
	if in.Method == "" {
		in.Method = users.MethodPasskey
	}
	u, err := s.Users.Provision(r.Context(), svc, in.Method, in.Email, in.Name)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, userJSON(u))
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	list, next, err := s.Users.List(r.Context(), svc.ID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, userJSON(u))
	}
	writeJSON(w, 200, map[string]any{"users": out, "next": next})
}

// ── email codes ────────────────────────────────────────────────────────────

// loginEmailBegin mails a sign-in code for a parked authorization. Sends are
// capped per address and per IP so a stranger cannot turn us into a spam cannon.
func (s *Server) loginEmailBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		LoginChallenge string `json:"login_challenge"`
		Email          string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !s.pendingFor(w, r, svc, in.LoginChallenge) {
		return
	}
	emailKey := "email:send:" + strings.ToLower(strings.TrimSpace(in.Email))
	ipKey := "email:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSend, emailKey) {
		tooMany(w, ratelimit.EmailSend)
		return
	}
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSendIP, ipKey) {
		tooMany(w, ratelimit.EmailSendIP)
		return
	}
	chID, err := s.Users.BeginLoginEmail(r.Context(), svc, in.LoginChallenge, in.Email, clientIP(r))
	if s.userFail(w, err) {
		return
	}
	s.Limit.Fail(r.Context(), ratelimit.EmailSend, emailKey)
	s.Limit.Fail(r.Context(), ratelimit.EmailSendIP, ipKey)
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "expires_in": int(users.CodeTTL.Seconds())})
}

// loginEmailFinish checks the code and completes the authorization, like the
// passkey finish: the app sends the browser to redirect_to.
func (s *Server) loginEmailFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	user, authzID, err := s.Users.FinishLoginEmail(r.Context(), svc, r.URL.Query().Get("challenge"), in.Code, clientIP(r))
	if errors.Is(err, users.ErrCodeRejected) || errors.Is(err, users.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
	}
	if s.userFail(w, err) {
		return
	}
	loc, err := s.OAuth.CompleteForUser(r.Context(), authzID, user, users.AllowedScopes(svc, user), clientIP(r))
	if s.completeFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"redirect_to": loc, "user": userJSON(user)})
}

func (s *Server) userVerifyEmailBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	userKey := "email:send:user:" + r.PathValue("id")
	ipKey := "email:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSend, userKey) {
		tooMany(w, ratelimit.EmailSend)
		return
	}
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSendIP, ipKey) {
		tooMany(w, ratelimit.EmailSendIP)
		return
	}
	chID, err := s.Users.BeginVerifyEmail(r.Context(), svc, r.PathValue("id"), clientIP(r))
	if s.userFail(w, err) {
		return
	}
	s.Limit.Fail(r.Context(), ratelimit.EmailSend, userKey)
	s.Limit.Fail(r.Context(), ratelimit.EmailSendIP, ipKey)
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "expires_in": int(users.CodeTTL.Seconds())})
}

func (s *Server) userVerifyEmailFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	u, err := s.Users.FinishVerifyEmail(r.Context(), svc, r.PathValue("id"), r.URL.Query().Get("challenge"), in.Code, clientIP(r))
	if errors.Is(err, users.ErrCodeRejected) || errors.Is(err, users.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
	}
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, userJSON(u))
}

// ── passkey activation ─────────────────────────────────────────────────────

// loginPasskeyActivateBegin mails a code to a passkey account that has no
// usable passkey on this device (first activation of a provisioned account,
// or a new phone). Same send caps as the email-code login.
func (s *Server) loginPasskeyActivateBegin(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		LoginChallenge string `json:"login_challenge"`
		Email          string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !s.pendingFor(w, r, svc, in.LoginChallenge) {
		return
	}
	emailKey := "email:send:" + strings.ToLower(strings.TrimSpace(in.Email))
	ipKey := "email:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSend, emailKey) {
		tooMany(w, ratelimit.EmailSend)
		return
	}
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSendIP, ipKey) {
		tooMany(w, ratelimit.EmailSendIP)
		return
	}
	chID, err := s.Users.BeginActivatePasskey(r.Context(), svc, in.LoginChallenge, in.Email, clientIP(r))
	if s.userFail(w, err) {
		return
	}
	s.Limit.Fail(r.Context(), ratelimit.EmailSend, emailKey)
	s.Limit.Fail(r.Context(), ratelimit.EmailSendIP, ipKey)
	writeJSON(w, 200, map[string]any{"challenge_id": chID, "expires_in": int(users.CodeTTL.Seconds())})
}

// loginPasskeyActivateFinish checks the code and hands back WebAuthn creation
// options; the browser runs navigator.credentials.create and the app posts the
// result to POST /v1/users/{user_id}/passkeys/finish?challenge=, which also
// completes the sign-in.
func (s *Server) loginPasskeyActivateFinish(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ipKey := "login:ip:" + clientIP(r)
	if !s.Limit.Allow(r.Context(), ratelimit.LoginIP, ipKey) {
		tooMany(w, ratelimit.LoginIP)
		return
	}
	opts, regID, user, err := s.Users.FinishActivatePasskey(r.Context(), svc, r.URL.Query().Get("challenge"), in.Code, clientIP(r))
	if errors.Is(err, users.ErrCodeRejected) || errors.Is(err, users.ErrCeremony) {
		s.Limit.Fail(r.Context(), ratelimit.LoginIP, ipKey)
	}
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": regID, "options": opts, "user": userJSON(user)})
}
