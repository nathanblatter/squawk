package users

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
)

// Teams and organisations (auth-service-15). DECIDED (Nathan, 2026-10-17):
// an org lives inside one service, like its users; any user may create one
// through the app and becomes its first admin; members are added directly by
// user id (emailed invites later); a user holds 0..n memberships with an
// org role (admin | member) layered on their service roles; the app asks for
// an org context at login and the token carries org + org_role.
//
// Authority: these calls run under the product's service token, so the
// product decides who may call them (normally: an org admin, checked against
// the org_role in the caller's token). Squawk keeps the records consistent:
// one admin always remains.

const (
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"

	// OrgNameMax bounds an org name.
	OrgNameMax = 80
)

var (
	ErrOrgNotFound    = errors.New("users: org not found")
	ErrInvalidOrgName = errors.New("users: org name must be 1-80 characters")
	ErrInvalidOrgRole = errors.New("users: org role must be admin or member")
	ErrLastAdmin      = errors.New("users: an org must keep at least one admin")
	ErrNotMember      = errors.New("users: not a member of this org")
	ErrOrgDisabled    = errors.New("users: org disabled")
)

func validOrgRole(r string) bool { return r == OrgRoleAdmin || r == OrgRoleMember }

func normalizeOrgName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > OrgNameMax {
		return "", ErrInvalidOrgName
	}
	return name, nil
}

// CreateOrg makes an org under the service with creator as its first admin.
func (u *Users) CreateOrg(ctx context.Context, svc store.Service, name, creatorID string) (store.Org, error) {
	if svc.LoginURL == "" {
		return store.Org{}, ErrNotUserPool
	}
	name, err := normalizeOrgName(name)
	if err != nil {
		return store.Org{}, err
	}
	if _, err := u.Get(ctx, svc.ID, creatorID); err != nil {
		return store.Org{}, err
	}
	org := store.Org{ID: "org_" + randomBase32(16), ServiceID: svc.ID, Name: name, Status: "active", CreatedAt: u.Now()}
	if err := u.Store.CreateOrg(ctx, org); err != nil {
		return store.Org{}, err
	}
	if err := u.Store.PutOrgMember(ctx, store.OrgMember{ServiceID: svc.ID, OrgID: org.ID, UserID: creatorID, Role: OrgRoleAdmin, CreatedAt: org.CreatedAt}); err != nil {
		return store.Org{}, err
	}
	u.audit(ctx, "org.create", svc.ID, creatorID, "org="+org.ID+" name="+name, "")
	return org, nil
}

// GetOrg fetches an org of a service.
func (u *Users) GetOrg(ctx context.Context, serviceID, id string) (store.Org, error) {
	org, err := u.Store.GetOrg(ctx, serviceID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Org{}, ErrOrgNotFound
	}
	return org, err
}

// ListOrgs pages a service's orgs, oldest first.
func (u *Users) ListOrgs(ctx context.Context, serviceID string, limit int, cursor string) ([]store.Org, string, error) {
	return u.Store.ListOrgs(ctx, serviceID, limit, cursor)
}

// UpdateOrg changes the name and/or status.
func (u *Users) UpdateOrg(ctx context.Context, serviceID, id string, name, status *string) (store.Org, error) {
	org, err := u.GetOrg(ctx, serviceID, id)
	if err != nil {
		return store.Org{}, err
	}
	if name != nil {
		if org.Name, err = normalizeOrgName(*name); err != nil {
			return store.Org{}, err
		}
	}
	if status != nil {
		if *status != "active" && *status != "disabled" {
			return store.Org{}, errors.New("users: status must be active or disabled")
		}
		org.Status = *status
	}
	if err := u.Store.UpdateOrg(ctx, org); err != nil {
		return store.Org{}, err
	}
	u.audit(ctx, "org.update", serviceID, "", "org="+org.ID+" name="+org.Name+" status="+org.Status, "")
	return org, nil
}

// DeleteOrg removes the org and every membership. Tokens already carrying
// the org run out within the hour; refreshes drop the org context.
func (u *Users) DeleteOrg(ctx context.Context, serviceID, id string) error {
	if _, err := u.GetOrg(ctx, serviceID, id); err != nil {
		return err
	}
	if err := u.Store.DeleteOrg(ctx, serviceID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrOrgNotFound
		}
		return err
	}
	u.audit(ctx, "org.delete", serviceID, "", "org="+id, "")
	return nil
}

// SetMember adds a user to an org or changes their role. Demoting the last
// admin is refused.
func (u *Users) SetMember(ctx context.Context, serviceID, orgID, userID, role string) (store.OrgMember, error) {
	if !validOrgRole(role) {
		return store.OrgMember{}, ErrInvalidOrgRole
	}
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return store.OrgMember{}, err
	}
	if _, err := u.Get(ctx, serviceID, userID); err != nil {
		return store.OrgMember{}, err
	}
	if role == OrgRoleMember {
		if err := u.ensureAnotherAdmin(ctx, serviceID, orgID, userID); err != nil {
			return store.OrgMember{}, err
		}
	}
	m := store.OrgMember{ServiceID: serviceID, OrgID: orgID, UserID: userID, Role: role, CreatedAt: u.Now()}
	if err := u.Store.PutOrgMember(ctx, m); err != nil {
		return store.OrgMember{}, err
	}
	m, err := u.Store.GetOrgMember(ctx, serviceID, orgID, userID)
	if err != nil {
		return store.OrgMember{}, err
	}
	u.audit(ctx, "org.member.set", serviceID, userID, "org="+orgID+" role="+role, "")
	return m, nil
}

// RemoveMember takes a user out of an org. Removing the last admin is refused;
// delete the org instead.
func (u *Users) RemoveMember(ctx context.Context, serviceID, orgID, userID string) error {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return err
	}
	if err := u.ensureAnotherAdmin(ctx, serviceID, orgID, userID); err != nil {
		return err
	}
	if err := u.Store.DeleteOrgMember(ctx, serviceID, orgID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotMember
		}
		return err
	}
	u.audit(ctx, "org.member.remove", serviceID, userID, "org="+orgID, "")
	return nil
}

// ensureAnotherAdmin refuses when userID is currently the only admin.
func (u *Users) ensureAnotherAdmin(ctx context.Context, serviceID, orgID, userID string) error {
	cur, err := u.Store.GetOrgMember(ctx, serviceID, orgID, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.Role != OrgRoleAdmin) {
		return nil // not an admin today, nothing to protect
	}
	if err != nil {
		return err
	}
	members, err := u.Store.ListOrgMembers(ctx, serviceID, orgID)
	if err != nil {
		return err
	}
	for _, m := range members {
		if m.Role == OrgRoleAdmin && m.UserID != userID {
			return nil
		}
	}
	return ErrLastAdmin
}

// Member is a membership joined with the user's account.
type Member struct {
	store.OrgMember
	User store.User
}

// ListMembers returns an org's members with their accounts (a deleted user
// leaves no row, so every membership resolves).
func (u *Users) ListMembers(ctx context.Context, serviceID, orgID string) ([]Member, error) {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return nil, err
	}
	ms, err := u.Store.ListOrgMembers(ctx, serviceID, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		user, err := u.Store.GetUser(ctx, serviceID, m.UserID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Member{OrgMember: m, User: user})
	}
	return out, nil
}

// Membership is an org joined with the user's role in it.
type Membership struct {
	store.Org
	Role string
}

// UserOrgs lists the orgs a user belongs to, with their role in each.
func (u *Users) UserOrgs(ctx context.Context, serviceID, userID string) ([]Membership, error) {
	if _, err := u.Get(ctx, serviceID, userID); err != nil {
		return nil, err
	}
	return u.memberships(ctx, serviceID, userID)
}

func (u *Users) memberships(ctx context.Context, serviceID, userID string) ([]Membership, error) {
	ms, err := u.Store.ListUserOrgs(ctx, serviceID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(ms))
	for _, m := range ms {
		org, err := u.Store.GetOrg(ctx, serviceID, m.OrgID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Membership{Org: org, Role: m.Role})
	}
	return out, nil
}

// ── invites (auth-service-32) ──────────────────────────────────────────────
//
// An org admin (through the product) invites an address with a role. Squawk
// mails the person; the invite is claimed the moment a user with that
// verified address signs in or verifies the address, and becomes a
// membership. No secret link: signing in with the address is the proof.
// An invite does not open a closed pool; on open_signup=false the owner still
// provisions the account and the invite waits for it.

// InviteTTL is how long an invite waits to be claimed.
const InviteTTL = 14 * 24 * time.Hour

var ErrAlreadyMember = errors.New("users: that address already belongs to a member")

// Invite mails an invitation and records it. Re-inviting an address replaces
// the pending invite (new role, fresh expiry) and mails again. invitedBy is
// an optional user id named in the mail.
func (u *Users) Invite(ctx context.Context, svc store.Service, orgID, email, role, invitedBy, ip string) (store.OrgInvite, error) {
	if u.Mail == nil {
		return store.OrgInvite{}, ErrEmailDisabled
	}
	if !validOrgRole(role) {
		return store.OrgInvite{}, ErrInvalidOrgRole
	}
	org, err := u.GetOrg(ctx, svc.ID, orgID)
	if err != nil {
		return store.OrgInvite{}, err
	}
	if org.Status != "active" {
		return store.OrgInvite{}, ErrOrgDisabled
	}
	email, err = normalizeEmail(email)
	if err != nil {
		return store.OrgInvite{}, err
	}
	inviter := ""
	if invitedBy != "" {
		by, err := u.Get(ctx, svc.ID, invitedBy)
		if err != nil {
			return store.OrgInvite{}, err
		}
		inviter = by.Name
		if inviter == "" {
			inviter = by.Email
		}
	}
	members, err := u.Store.ListOrgMembers(ctx, svc.ID, orgID)
	if err != nil {
		return store.OrgInvite{}, err
	}
	for _, m := range members {
		if user, err := u.Store.GetUser(ctx, svc.ID, m.UserID); err == nil && user.Email == email {
			return store.OrgInvite{}, ErrAlreadyMember
		}
	}
	now := u.Now()
	inv := store.OrgInvite{ServiceID: svc.ID, OrgID: orgID, Email: email, Role: role, InvitedBy: invitedBy, CreatedAt: now, ExpiresAt: now.Add(InviteTTL)}
	if err := u.Store.PutOrgInvite(ctx, inv); err != nil {
		return store.OrgInvite{}, err
	}
	who := svc.Name
	if inviter != "" {
		who = inviter + " (" + svc.Name + ")"
	}
	where := svc.Name
	if o, err := url.Parse(svc.LoginURL); err == nil && o.Host != "" {
		where = o.Scheme + "://" + o.Host
	}
	text := fmt.Sprintf("%s has invited you to join %s on %s as %s.\n\nTo accept, sign in to %s with this email address (%s) within %d days. If you do not have an account yet, create one with this address.\n\nIf you were not expecting this, ignore this message; nothing happens until you sign in.",
		who, org.Name, svc.Name, roleWord(role), where, email, int(InviteTTL.Hours()/24))
	if err := u.Mail.Send(ctx, email, fmt.Sprintf("You're invited to %s on %s", org.Name, svc.Name), text); err != nil {
		u.Log.Error("invite email failed", "service", svc.Slug, "org", orgID, "err", err)
		return store.OrgInvite{}, err
	}
	u.audit(ctx, "org.invite.create", svc.ID, invitedBy, "org="+orgID+" email="+email+" role="+role, ip)
	return inv, nil
}

func roleWord(role string) string {
	if role == OrgRoleAdmin {
		return "an admin"
	}
	return "a member"
}

// ListInvites returns an org's pending (unexpired) invites, oldest first.
func (u *Users) ListInvites(ctx context.Context, serviceID, orgID string) ([]store.OrgInvite, error) {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return nil, err
	}
	list, err := u.Store.ListOrgInvites(ctx, serviceID, orgID)
	if err != nil {
		return nil, err
	}
	return u.liveInvites(list), nil
}

func (u *Users) liveInvites(list []store.OrgInvite) []store.OrgInvite {
	now := u.Now()
	out := make([]store.OrgInvite, 0, len(list))
	for _, inv := range list {
		if inv.ExpiresAt.After(now) {
			out = append(out, inv)
		}
	}
	return out
}

// RevokeInvite withdraws a pending invite.
func (u *Users) RevokeInvite(ctx context.Context, serviceID, orgID, email, ip string) error {
	if _, err := u.GetOrg(ctx, serviceID, orgID); err != nil {
		return err
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	if err := u.Store.DeleteOrgInvite(ctx, serviceID, orgID, email); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInviteNotFound
		}
		return err
	}
	u.audit(ctx, "org.invite.revoke", serviceID, "", "org="+orgID+" email="+email, ip)
	return nil
}

var ErrInviteNotFound = errors.New("users: no pending invite for that address")

// claimInvites turns every pending invite for the user's verified address
// into a membership. Called on each successful sign-in and when an address
// gets verified; best effort, never fails the sign-in. A user who is already
// a member keeps their current role (the invite is simply dropped); a
// disabled or deleted org drops the invite too.
func (u *Users) claimInvites(ctx context.Context, svc store.Service, user store.User, ip string) {
	if !user.EmailVerified || user.Email == "" {
		return
	}
	list, err := u.Store.ListEmailInvites(ctx, svc.ID, user.Email)
	if err != nil {
		u.Log.Error("invite lookup failed", "user", user.ID, "err", err)
		return
	}
	for _, inv := range u.liveInvites(list) {
		org, err := u.Store.GetOrg(ctx, svc.ID, inv.OrgID)
		if err == nil && org.Status == "active" {
			if _, err := u.Store.GetOrgMember(ctx, svc.ID, inv.OrgID, user.ID); errors.Is(err, store.ErrNotFound) {
				if err := u.Store.PutOrgMember(ctx, store.OrgMember{ServiceID: svc.ID, OrgID: inv.OrgID, UserID: user.ID, Role: inv.Role, CreatedAt: u.Now()}); err != nil {
					u.Log.Error("invite claim failed", "user", user.ID, "org", inv.OrgID, "err", err)
					continue
				}
				u.audit(ctx, "org.invite.accepted", svc.ID, user.ID, "org="+inv.OrgID+" role="+inv.Role, ip)
			}
		}
		if err := u.Store.DeleteOrgInvite(ctx, svc.ID, inv.OrgID, inv.Email); err != nil && !errors.Is(err, store.ErrNotFound) {
			u.Log.Error("invite delete failed", "user", user.ID, "org", inv.OrgID, "err", err)
		}
	}
}
