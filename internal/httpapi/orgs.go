package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nathanblatter/squawk/internal/ratelimit"
	"github.com/nathanblatter/squawk/internal/store"
	"github.com/nathanblatter/squawk/internal/users"
)

// Teams and organisations (auth-service-15), driven by the product's backend
// with its service token. The product decides who may call these (normally
// an org admin, judged by the org_role in the caller's token); Squawk keeps
// the records consistent and puts the org context into tokens.

func (s *Server) orgRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/orgs", s.requireService(s.createOrg))
	mux.HandleFunc("GET /v1/orgs", s.requireService(s.listOrgs))
	mux.HandleFunc("GET /v1/orgs/{id}", s.requireService(s.getOrg))
	mux.HandleFunc("PATCH /v1/orgs/{id}", s.requireService(s.updateOrg))
	mux.HandleFunc("DELETE /v1/orgs/{id}", s.requireService(s.deleteOrg))
	mux.HandleFunc("GET /v1/orgs/{id}/members", s.requireService(s.listOrgMembers))
	mux.HandleFunc("PUT /v1/orgs/{id}/members/{user}", s.requireService(s.setOrgMember))
	mux.HandleFunc("DELETE /v1/orgs/{id}/members/{user}", s.requireService(s.removeOrgMember))
	mux.HandleFunc("GET /v1/users/{id}/orgs", s.requireService(s.userOrgs))
	mux.HandleFunc("POST /v1/orgs/{id}/invites", s.requireService(s.inviteOrgMember))
	mux.HandleFunc("GET /v1/orgs/{id}/invites", s.requireService(s.listOrgInvites))
	mux.HandleFunc("DELETE /v1/orgs/{id}/invites/{email}", s.requireService(s.revokeOrgInvite))
	mux.HandleFunc("GET /admin/services/{id}/orgs", s.requireAdmin(s.adminListOrgs))
	mux.HandleFunc("GET /admin/services/{id}/orgs/{org}/members", s.requireAdmin(s.adminListOrgMembers))
	mux.HandleFunc("GET /admin/services/{id}/orgs/{org}/invites", s.requireAdmin(s.adminListOrgInvites))
}

func inviteJSON(inv store.OrgInvite) map[string]any {
	return map[string]any{"org_id": inv.OrgID, "email": inv.Email, "role": inv.Role, "invited_by": inv.InvitedBy,
		"created_at": inv.CreatedAt.UTC().Format(time.RFC3339), "expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339)}
}

func orgJSON(o store.Org) map[string]any {
	return map[string]any{"id": o.ID, "service_id": o.ServiceID, "name": o.Name, "status": o.Status, "created_at": o.CreatedAt.UTC().Format(time.RFC3339)}
}

func memberJSON(m users.Member) map[string]any {
	return map[string]any{"user_id": m.UserID, "role": m.Role, "joined_at": m.CreatedAt.UTC().Format(time.RFC3339),
		"email": m.User.Email, "name": m.User.Name, "status": m.User.Status}
}

func membershipJSON(m users.Membership) map[string]any {
	out := orgJSON(m.Org)
	out["role"] = m.Role
	return out
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Name        string `json:"name"`
		AdminUserID string `json:"admin_user_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org, err := s.Users.CreateOrg(r.Context(), svc, in.Name, in.AdminUserID)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 201, orgJSON(org))
}

func pageLimit(r *http.Request) int {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	return limit
}

func (s *Server) writeOrgList(w http.ResponseWriter, r *http.Request, serviceID string) {
	list, next, err := s.Users.ListOrgs(r.Context(), serviceID, pageLimit(r), r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, o := range list {
		out = append(out, orgJSON(o))
	}
	writeJSON(w, 200, map[string]any{"orgs": out, "next": next})
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	s.writeOrgList(w, r, svc.ID)
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	org, err := s.Users.GetOrg(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, orgJSON(org))
}

func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org, err := s.Users.UpdateOrg(r.Context(), svc.ID, r.PathValue("id"), in.Name, in.Status)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, orgJSON(org))
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.DeleteOrg(r.Context(), svc.ID, r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) writeMembers(w http.ResponseWriter, r *http.Request, serviceID, orgID string) {
	members, err := s.Users.ListMembers(r.Context(), serviceID, orgID)
	if s.userFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, memberJSON(m))
	}
	writeJSON(w, 200, map[string]any{"members": out})
}

func (s *Server) listOrgMembers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	s.writeMembers(w, r, svc.ID, r.PathValue("id"))
}

func (s *Server) setOrgMember(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	m, err := s.Users.SetMember(r.Context(), svc.ID, r.PathValue("id"), r.PathValue("user"), in.Role)
	if s.userFail(w, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"org_id": m.OrgID, "user_id": m.UserID, "role": m.Role, "joined_at": m.CreatedAt.UTC().Format(time.RFC3339)})
}

func (s *Server) removeOrgMember(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.RemoveMember(r.Context(), svc.ID, r.PathValue("id"), r.PathValue("user"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) userOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	list, err := s.Users.UserOrgs(r.Context(), svc.ID, r.PathValue("id"))
	if s.userFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, m := range list {
		out = append(out, membershipJSON(m))
	}
	writeJSON(w, 200, map[string]any{"orgs": out})
}

func (s *Server) adminListOrgs(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	s.writeOrgList(w, r, svc.ID)
}

func (s *Server) adminListOrgMembers(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	s.writeMembers(w, r, svc.ID, r.PathValue("org"))
}

// ── invites (auth-service-32) ──────────────────────────────────────────────

func (s *Server) inviteOrgMember(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	var in struct {
		Email     string `json:"email"`
		Role      string `json:"role"`
		InvitedBy string `json:"invited_by"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	// One address cannot be mailed without bound, whatever the product does.
	emailKey := "email:send:" + strings.ToLower(strings.TrimSpace(in.Email))
	if !s.Limit.Allow(r.Context(), ratelimit.EmailSend, emailKey) {
		tooMany(w, ratelimit.EmailSend)
		return
	}
	inv, err := s.Users.Invite(r.Context(), svc, r.PathValue("id"), in.Email, in.Role, in.InvitedBy, clientIP(r))
	if s.userFail(w, err) {
		return
	}
	s.Limit.Fail(r.Context(), ratelimit.EmailSend, emailKey)
	writeJSON(w, 201, inviteJSON(inv))
}

func (s *Server) writeInvites(w http.ResponseWriter, r *http.Request, serviceID, orgID string) {
	list, err := s.Users.ListInvites(r.Context(), serviceID, orgID)
	if s.userFail(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, inv := range list {
		out = append(out, inviteJSON(inv))
	}
	writeJSON(w, 200, map[string]any{"invites": out})
}

func (s *Server) listOrgInvites(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	s.writeInvites(w, r, svc.ID, r.PathValue("id"))
}

func (s *Server) revokeOrgInvite(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.callerService(w, r)
	if !ok {
		return
	}
	if s.userFail(w, s.Users.RevokeInvite(r.Context(), svc.ID, r.PathValue("id"), r.PathValue("email"), clientIP(r))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) adminListOrgInvites(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.adminService(w, r)
	if !ok {
		return
	}
	s.writeInvites(w, r, svc.ID, r.PathValue("org"))
}
