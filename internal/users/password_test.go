package users

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/nathanblatter/squawk/internal/store"
)

func TestPasswordAccounts(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()

	ownerOnly := store.Service{ID: "svc_o", Slug: "o", Name: "O", Status: "active", CreatedAt: u.Now()}
	_ = mem.CreateService(ctx, ownerOnly)
	if _, err := u.ProvisionPassword(ctx, ownerOnly, PasswordAccount{Username: "jdoe", Password: "correct horse"}); !errors.Is(err, ErrNotUserPool) {
		t.Fatalf("owner-only: %v", err)
	}
	bad := []struct {
		in  PasswordAccount
		err error
	}{
		{PasswordAccount{Username: "", Password: "correct horse"}, ErrInvalidUsername},
		{PasswordAccount{Username: "j doe", Password: "correct horse"}, ErrInvalidUsername},
		{PasswordAccount{Username: "jdoe"}, ErrNoPassword},
		{PasswordAccount{Username: "jdoe", Password: "short"}, ErrWeakPassword},
		{PasswordAccount{Username: "jdoe", Password: "correct horse", PasswordHash: "$2a$04$x"}, ErrNoPassword},
		{PasswordAccount{Username: "jdoe", PasswordHash: "not-bcrypt"}, ErrInvalidHash},
		{PasswordAccount{Username: "jdoe", Password: "correct horse", Roles: []string{"boss"}}, ErrInvalidRole},
		{PasswordAccount{Username: "jdoe", Password: "correct horse", Email: "nope"}, ErrInvalidEmail},
	}
	for _, c := range bad {
		if _, err := u.ProvisionPassword(ctx, svc, c.in); !errors.Is(err, c.err) {
			t.Fatalf("%+v: got %v want %v", c.in, err, c.err)
		}
	}

	// Imported hash (as a migration would send it), explicit role, no email.
	hash, _ := bcrypt.GenerateFromPassword([]byte("hunter22"), bcrypt.MinCost)
	jdoe, err := u.ProvisionPassword(ctx, svc, PasswordAccount{Username: " JDoe ", Name: "J. Doe", Roles: []string{"editor"}, PasswordHash: string(hash)})
	if err != nil || jdoe.Method != MethodPassword || jdoe.Identity != "username:jdoe" || jdoe.Username != "JDoe" || jdoe.Email != "" || !jdoe.EmailVerified || jdoe.PasswordHash != string(hash) || len(jdoe.Roles) != 1 || jdoe.Roles[0] != "editor" {
		t.Fatalf("provision: %+v %v", jdoe, err)
	}
	if _, err := u.ProvisionPassword(ctx, svc, PasswordAccount{Username: "jdoe", Password: "correct horse"}); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("duplicate (case-insensitive): %v", err)
	}
	// The app may create password accounts on an open pool only.
	if _, err := u.CreatePassword(ctx, svc, PasswordAccount{Username: "p1", Password: "correct horse"}); err != nil {
		t.Fatalf("app create on open pool: %v", err)
	}
	_ = mem.UpdateServiceLogin(ctx, svc.ID, svc.LoginURL, svc.RPID, svc.Origins, svc.DefaultRoles, false)
	closed, _ := mem.GetService(ctx, svc.ID)
	if _, err := u.CreatePassword(ctx, closed, PasswordAccount{Username: "p2", Password: "correct horse"}); !errors.Is(err, ErrSignupClosed) {
		t.Fatalf("app create on closed pool: %v", err)
	}
	// Squawk-hashed password, default roles, optional email.
	ann, err := u.ProvisionPassword(ctx, svc, PasswordAccount{Username: "ann", Password: "correct horse", Email: "Ann@X.test"})
	if err != nil || ann.Email != "ann@x.test" || len(ann.Roles) != 1 || ann.Roles[0] != "user" || bcrypt.CompareHashAndPassword([]byte(ann.PasswordHash), []byte("correct horse")) != nil {
		t.Fatalf("provision ann: %+v %v", ann, err)
	}

	// Login: unknown name, wrong password and wrong method all refuse.
	if _, _, err := u.LoginPassword(ctx, svc, "authz-1", "ghost", "whatever", "ip"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, _, err := u.LoginPassword(ctx, svc, "authz-1", "jdoe", "hunter23", "ip"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("wrong password: %v", err)
	}
	got, authz, err := u.LoginPassword(ctx, svc, "authz-1", "jdoe", "hunter22", "ip")
	if err != nil || authz != "authz-1" || got.ID != jdoe.ID {
		t.Fatalf("login: %+v %q %v", got, authz, err)
	}
	if after, _ := u.Get(ctx, svc.ID, jdoe.ID); after.LastLoginAt.IsZero() {
		t.Fatal("login must stamp last_login_at")
	}
	off := "disabled"
	_, _ = u.Update(ctx, svc, jdoe.ID, nil, &off, nil)
	if _, _, err := u.LoginPassword(ctx, svc, "authz-1", "jdoe", "hunter22", "ip"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	on := "active"
	_, _ = u.Update(ctx, svc, jdoe.ID, nil, &on, nil)

	// SetPassword replaces the hash; a passkey-method account with no
	// username cannot get one.
	if _, err := u.SetPassword(ctx, svc, jdoe.ID, "new password!", "", "ip"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.LoginPassword(ctx, svc, "authz-2", "jdoe", "hunter22", "ip"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("old password after reset: %v", err)
	}
	if _, _, err := u.LoginPassword(ctx, svc, "authz-2", "JDOE", "new password!", "ip"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	pk, _ := u.Create(ctx, svc, "pk@x.test", "")
	if _, err := u.SetPassword(ctx, svc, pk.ID, "new password!", "", "ip"); !errors.Is(err, ErrWrongMethod) {
		t.Fatalf("password on an email-keyed passkey account: %v", err)
	}

	// Conversion: a registered passkey replaces the password; a new
	// password converts back and removes the passkeys.
	if _, _, err := u.BeginRegisterPasskey(ctx, svc, jdoe.ID); err != nil {
		t.Fatalf("password account must be able to start passkey registration: %v", err)
	}
	cur, _ := u.Get(ctx, svc.ID, jdoe.ID)
	conv, err := u.convertToPasskey(ctx, svc, cur, "ip")
	if err != nil || conv.Method != MethodPasskey || conv.PasswordHash != "" || conv.Username != "JDoe" {
		t.Fatalf("convert: %+v %v", conv, err)
	}
	if _, _, err := u.LoginPassword(ctx, svc, "authz-3", "jdoe", "new password!", "ip"); !errors.Is(err, ErrWrongMethod) {
		t.Fatalf("password after conversion: %v", err)
	}
	_ = mem.PutUserPasskey(ctx, store.UserPasskey{ServiceID: svc.ID, UserID: jdoe.ID, ID: "cred1", Name: "Phone", CreatedAt: u.Now(), Data: []byte("{}")})
	back, err := u.SetPassword(ctx, svc, jdoe.ID, "", string(hash), "ip")
	if err != nil || back.Method != MethodPassword || back.PasswordHash != string(hash) {
		t.Fatalf("convert back: %+v %v", back, err)
	}
	if keys, _ := mem.ListUserPasskeys(ctx, svc.ID, jdoe.ID); len(keys) != 0 {
		t.Fatalf("passkeys must go when the password comes back: %+v", keys)
	}
	if _, _, err := u.LoginPassword(ctx, svc, "authz-4", "jdoe", "hunter22", "ip"); err != nil {
		t.Fatalf("login after convert back: %v", err)
	}
	// A name-only account exports cleanly and has no mail to send.
	if exp, err := u.Export(ctx, svc.ID, jdoe.ID); err != nil || exp.User.Username != "JDoe" {
		t.Fatalf("export: %+v %v", exp.User, err)
	}
	kinds := map[string]int{}
	for _, e := range mem.Audit {
		kinds[e.Kind]++
	}
	for _, k := range []string{"user.provision", "user.login", "user.login_denied", "user.password.set", "user.method.converted"} {
		if kinds[k] == 0 {
			t.Fatalf("missing audit %s: %v", k, kinds)
		}
	}
}
