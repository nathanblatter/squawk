package users

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
)

func TestOrgs(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	alice, _ := u.Create(ctx, svc, "alice@x.test", "Alice")
	bob, _ := u.Create(ctx, svc, "bob@x.test", "Bob")

	ownerOnly := store.Service{ID: "svc_o", Slug: "o", Name: "O", Status: "active", CreatedAt: u.Now()}
	_ = mem.CreateService(ctx, ownerOnly)
	if _, err := u.CreateOrg(ctx, ownerOnly, "Practice", alice.ID); !errors.Is(err, ErrNotUserPool) {
		t.Fatalf("owner-only service: %v", err)
	}
	if _, err := u.CreateOrg(ctx, svc, "   ", alice.ID); !errors.Is(err, ErrInvalidOrgName) {
		t.Fatalf("blank name: %v", err)
	}
	if _, err := u.CreateOrg(ctx, svc, "Practice", "usr_ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown creator: %v", err)
	}
	org, err := u.CreateOrg(ctx, svc, "  Sunny Practice ", alice.ID)
	if err != nil || org.Name != "Sunny Practice" || org.Status != "active" || org.ServiceID != svc.ID {
		t.Fatalf("create: %+v %v", org, err)
	}
	// The creator is the first admin.
	if ms, err := u.ListMembers(ctx, svc.ID, org.ID); err != nil || len(ms) != 1 || ms[0].UserID != alice.ID || ms[0].Role != OrgRoleAdmin || ms[0].User.Email != "alice@x.test" {
		t.Fatalf("first admin: %+v %v", ms, err)
	}
	// The last admin cannot be demoted or removed.
	if _, err := u.SetMember(ctx, svc.ID, org.ID, alice.ID, OrgRoleMember); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("remove last admin: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, "boss"); !errors.Is(err, ErrInvalidOrgRole) {
		t.Fatalf("bad role: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, org.ID, "usr_ghost", OrgRoleMember); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := u.SetMember(ctx, svc.ID, "org_ghost", bob.ID, OrgRoleMember); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("unknown org: %v", err)
	}
	if m, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, OrgRoleMember); err != nil || m.Role != OrgRoleMember {
		t.Fatalf("add bob: %+v %v", m, err)
	}
	// Promote bob, then alice may step down.
	if m, err := u.SetMember(ctx, svc.ID, org.ID, bob.ID, OrgRoleAdmin); err != nil || m.Role != OrgRoleAdmin {
		t.Fatalf("promote bob: %+v %v", m, err)
	}
	if m, err := u.SetMember(ctx, svc.ID, org.ID, alice.ID, OrgRoleMember); err != nil || m.Role != OrgRoleMember {
		t.Fatalf("demote alice: %+v %v", m, err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); err != nil {
		t.Fatalf("remove alice: %v", err)
	}
	if err := u.RemoveMember(ctx, svc.ID, org.ID, alice.ID); !errors.Is(err, ErrNotMember) {
		t.Fatalf("remove twice: %v", err)
	}
	if orgs, err := u.UserOrgs(ctx, svc.ID, alice.ID); err != nil || len(orgs) != 0 {
		t.Fatalf("alice orgs: %+v %v", orgs, err)
	}
	if orgs, err := u.UserOrgs(ctx, svc.ID, bob.ID); err != nil || len(orgs) != 1 || orgs[0].ID != org.ID || orgs[0].Role != OrgRoleAdmin || orgs[0].Name != "Sunny Practice" {
		t.Fatalf("bob orgs: %+v %v", orgs, err)
	}
	name, status := "Sunny", "disabled"
	if got, err := u.UpdateOrg(ctx, svc.ID, org.ID, &name, &status); err != nil || got.Name != "Sunny" || got.Status != "disabled" {
		t.Fatalf("update: %+v %v", got, err)
	}
	bad := "gone"
	if _, err := u.UpdateOrg(ctx, svc.ID, org.ID, nil, &bad); err == nil {
		t.Fatal("bad status accepted")
	}
	exp, err := u.Export(ctx, svc.ID, bob.ID)
	if err != nil || len(exp.Orgs) != 1 || exp.Orgs[0].ID != org.ID {
		t.Fatalf("export orgs: %+v %v", exp.Orgs, err)
	}
	// Deleting the only admin leaves the org; deleting the org clears memberships.
	if err := u.Delete(ctx, svc.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := u.ListMembers(ctx, svc.ID, org.ID); len(ms) != 0 {
		t.Fatalf("members after delete: %+v", ms)
	}
	if err := u.DeleteOrg(ctx, svc.ID, org.ID); err != nil {
		t.Fatal(err)
	}
	if err := u.DeleteOrg(ctx, svc.ID, org.ID); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if list, next, err := u.ListOrgs(ctx, svc.ID, 10, ""); err != nil || len(list) != 0 || next != "" {
		t.Fatalf("list after delete: %+v %q %v", list, next, err)
	}
	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	for _, k := range []string{"org.create", "org.member.set", "org.member.remove", "org.update", "org.delete"} {
		if kinds[k] == 0 {
			t.Fatalf("missing audit %s: %v", k, kinds)
		}
	}
}

func TestOrgInvites(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	alice, _ := u.Create(ctx, svc, "alice@x.test", "Alice")
	org, _ := u.CreateOrg(ctx, svc, "Sunny Practice", alice.ID)

	if _, err := u.Invite(ctx, svc, org.ID, "carol@x.test", OrgRoleMember, alice.ID, "ip"); !errors.Is(err, ErrEmailDisabled) {
		t.Fatalf("no mailer: %v", err)
	}
	fm := &fakeMail{}
	u.Mail = fm
	if _, err := u.Invite(ctx, svc, org.ID, "carol@x.test", "boss", "", "ip"); !errors.Is(err, ErrInvalidOrgRole) {
		t.Fatalf("bad role: %v", err)
	}
	if _, err := u.Invite(ctx, svc, "org_ghost", "carol@x.test", OrgRoleMember, "", "ip"); !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("unknown org: %v", err)
	}
	if _, err := u.Invite(ctx, svc, org.ID, "not-an-email", OrgRoleMember, "", "ip"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("bad address: %v", err)
	}
	if _, err := u.Invite(ctx, svc, org.ID, "carol@x.test", OrgRoleMember, "usr_ghost", "ip"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown inviter: %v", err)
	}
	if _, err := u.Invite(ctx, svc, org.ID, "Alice@x.test", OrgRoleMember, "", "ip"); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("inviting a member: %v", err)
	}
	if fm.sent != 0 {
		t.Fatalf("nothing should have been mailed yet: %d", fm.sent)
	}
	inv, err := u.Invite(ctx, svc, org.ID, " Carol@X.test ", OrgRoleMember, alice.ID, "ip")
	if err != nil || inv.Email != "carol@x.test" || inv.Role != OrgRoleMember || inv.InvitedBy != alice.ID || !inv.ExpiresAt.Equal(u.Now().Add(InviteTTL)) {
		t.Fatalf("invite: %+v %v", inv, err)
	}
	if fm.sent != 1 || fm.to != "carol@x.test" || !strings.Contains(fm.text, "Alice (FinForge)") || !strings.Contains(fm.text, "Sunny Practice") || !strings.Contains(fm.text, "https://finforge.test") || !strings.Contains(fm.text, "a member") {
		t.Fatalf("mail: sent=%d to=%q text=%q", fm.sent, fm.to, fm.text)
	}
	// Re-inviting replaces the role and mails again.
	if inv, err := u.Invite(ctx, svc, org.ID, "carol@x.test", OrgRoleAdmin, "", "ip"); err != nil || inv.Role != OrgRoleAdmin || fm.sent != 2 || !strings.Contains(fm.text, "an admin") {
		t.Fatalf("re-invite: %+v %v sent=%d", inv, err, fm.sent)
	}
	if list, err := u.ListInvites(ctx, svc.ID, org.ID); err != nil || len(list) != 1 || list[0].Role != OrgRoleAdmin {
		t.Fatalf("list: %+v %v", list, err)
	}
	// A disabled org cannot invite.
	off := "disabled"
	_, _ = u.UpdateOrg(ctx, svc.ID, org.ID, nil, &off)
	if _, err := u.Invite(ctx, svc, org.ID, "dave@x.test", OrgRoleMember, "", "ip"); !errors.Is(err, ErrOrgDisabled) {
		t.Fatalf("disabled org: %v", err)
	}
	on := "active"
	_, _ = u.UpdateOrg(ctx, svc.ID, org.ID, nil, &on)

	// Carol signs in with an emailed code on the open pool: the account is
	// created, the address is proven, the invite becomes a membership.
	ch, _ := u.BeginLoginEmail(ctx, svc, "authz-1", "carol@x.test", "ip")
	carol, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := mem.GetOrgMember(ctx, svc.ID, org.ID, carol.ID); err != nil || m.Role != OrgRoleAdmin {
		t.Fatalf("claimed membership: %+v %v", m, err)
	}
	if list, _ := u.ListInvites(ctx, svc.ID, org.ID); len(list) != 0 {
		t.Fatalf("invite must be consumed: %+v", list)
	}
	// An invite for someone who is already a member never changes their role.
	_, _ = u.SetMember(ctx, svc.ID, org.ID, carol.ID, OrgRoleMember)
	if _, err := u.Invite(ctx, svc, org.ID, "carol@x.test", OrgRoleAdmin, "", "ip"); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("member re-invite: %v", err)
	}
	// Expired invites are neither listed nor claimed.
	if err := mem.PutOrgInvite(ctx, store.OrgInvite{ServiceID: svc.ID, OrgID: org.ID, Email: "late@x.test", Role: OrgRoleMember, CreatedAt: u.Now().Add(-20 * 24 * time.Hour), ExpiresAt: u.Now().Add(-6 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if list, _ := u.ListInvites(ctx, svc.ID, org.ID); len(list) != 0 {
		t.Fatalf("expired invite listed: %+v", list)
	}
	ch, _ = u.BeginLoginEmail(ctx, svc, "authz-2", "late@x.test", "ip")
	late, _, _ := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip")
	if _, err := mem.GetOrgMember(ctx, svc.ID, org.ID, late.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired invite must not be claimed: %v", err)
	}
	// Revoke: once, then not found.
	_, _ = u.Invite(ctx, svc, org.ID, "erin@x.test", OrgRoleMember, "", "ip")
	if err := u.RevokeInvite(ctx, svc.ID, org.ID, "Erin@x.test", "ip"); err != nil {
		t.Fatal(err)
	}
	if err := u.RevokeInvite(ctx, svc.ID, org.ID, "erin@x.test", "ip"); !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
	// An unverified passkey account claims nothing until the address is
	// verified; verification claims it.
	_, _ = u.Invite(ctx, svc, org.ID, "frank@x.test", OrgRoleMember, "", "ip")
	frank, _ := u.Create(ctx, svc, "frank@x.test", "Frank")
	if frank.EmailVerified {
		t.Fatal("app-created passkey account must start unverified")
	}
	vch, _ := u.BeginVerifyEmail(ctx, svc, frank.ID, "ip")
	if _, err := u.FinishVerifyEmail(ctx, svc, frank.ID, vch, fm.code(t), "ip"); err != nil {
		t.Fatal(err)
	}
	if m, err := mem.GetOrgMember(ctx, svc.ID, org.ID, frank.ID); err != nil || m.Role != OrgRoleMember {
		t.Fatalf("claim on verification: %+v %v", m, err)
	}
	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	for _, k := range []string{"org.invite.create", "org.invite.revoke", "org.invite.accepted"} {
		if kinds[k] == 0 {
			t.Fatalf("missing audit %s: %v", k, kinds)
		}
	}
}
