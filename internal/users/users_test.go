package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
)

func newUsers(t *testing.T) (*Users, *store.Memory, store.Service) {
	t.Helper()
	mem := store.NewMemory()
	u := New(mem)
	u.Cost = 4 // bcrypt.MinCost: keep password tests fast
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	u.Now = func() time.Time { return now }
	ctx := context.Background()
	svc := store.Service{ID: "svc_a", Slug: "finforge", Name: "FinForge", Status: "active", CreatedAt: now}
	if err := mem.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	_ = mem.UpdateServicePermissions(ctx, svc.ID, []string{"read", "write", "admin"}, map[string][]string{"user": {"read"}, "editor": {"read", "write"}, "owner": {"admin", "read", "write"}})
	_ = mem.UpdateServiceLogin(ctx, svc.ID, "https://finforge.test/login", "finforge.test", []string{"https://finforge.test"}, []string{"user"}, true)
	svc, _ = mem.GetService(ctx, svc.ID)
	return u, mem, svc
}

func TestCreateAndManage(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()

	ownerOnly := store.Service{ID: "svc_o", Slug: "o", Name: "O", Status: "active", CreatedAt: u.Now()}
	_ = mem.CreateService(ctx, ownerOnly)
	if _, err := u.Create(ctx, ownerOnly, "a@x.test", "A"); !errors.Is(err, ErrNotUserPool) {
		t.Fatalf("owner-only service: %v", err)
	}
	if _, err := u.Create(ctx, svc, "not an email", "A"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("bad email: %v", err)
	}
	user, err := u.Create(ctx, svc, " Alice@X.test ", "Alice")
	if err != nil || user.Email != "alice@x.test" || user.Method != MethodPasskey || !strings.HasPrefix(user.ID, "usr_") || len(user.Roles) != 1 {
		t.Fatalf("create: %+v %v", user, err)
	}
	if _, err := u.Create(ctx, svc, "alice@x.test", "Again"); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("dup email: %v", err)
	}
	if _, err := u.Get(ctx, svc.ID, "nope"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: %v", err)
	}

	// Allowed scopes follow roles, in catalog order.
	if got := strings.Join(AllowedScopes(svc, user), " "); got != "read" {
		t.Fatalf("default allowed: %q", got)
	}
	roles := []string{"owner", "user"}
	upd, err := u.Update(ctx, svc, user.ID, &roles, nil, nil)
	if err != nil || len(upd.Roles) != 2 {
		t.Fatalf("update roles: %+v %v", upd, err)
	}
	if got := strings.Join(AllowedScopes(svc, upd), " "); got != "read write admin" {
		t.Fatalf("allowed after roles: %q", got)
	}
	bad := []string{"nope"}
	if _, err := u.Update(ctx, svc, user.ID, &bad, nil, nil); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("unknown role: %v", err)
	}
	disabled := "disabled"
	if upd, err := u.Update(ctx, svc, user.ID, nil, &disabled, nil); err != nil || upd.Status != "disabled" {
		t.Fatalf("disable: %+v %v", upd, err)
	}
	if err := u.LogoutEverywhere(ctx, svc.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := u.Get(ctx, svc.ID, user.ID); !got.NotBefore.Equal(u.Now()) {
		t.Fatalf("not-before: %v", got.NotBefore)
	}
	list, next, err := u.List(ctx, svc.ID, 10, "")
	if err != nil || len(list) != 1 || next != "" {
		t.Fatalf("list: %+v %q %v", list, next, err)
	}
}

func TestPasskeyCeremonies(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	user, _ := u.Create(ctx, svc, "p@x.test", "P")

	opts, chID, err := u.BeginRegisterPasskey(ctx, svc, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	var out struct {
		PublicKey struct {
			RP   struct{ ID string }
			User struct{ ID, Name string }
		}
	}
	_ = json.Unmarshal(raw, &out)
	if out.PublicKey.RP.ID != "finforge.test" || out.PublicKey.User.Name != "p@x.test" {
		t.Fatalf("creation options bound to the service: %s", raw)
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishRegisterPasskey(ctx, svc, chID, "Phone", req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("junk attestation: %v", err)
	}
	// Service without rp config cannot run ceremonies.
	noRP := svc
	noRP.RPID = ""
	if _, _, err := u.BeginRegisterPasskey(ctx, noRP, user.ID); !errors.Is(err, ErrNoWebAuthn) {
		t.Fatalf("no rp: %v", err)
	}
	// Google users have no passkeys to register.
	_ = mem.CreateUser(ctx, store.User{ID: "usr_g", ServiceID: svc.ID, Method: MethodGoogle, Identity: "google:1", Status: "active", CreatedAt: u.Now()})
	if _, _, err := u.BeginRegisterPasskey(ctx, svc, "usr_g"); !errors.Is(err, ErrWrongMethod) {
		t.Fatalf("google user registering passkey: %v", err)
	}

	// Login ceremony is bound to the authz request and the service.
	lopts, lch, err := u.BeginLoginPasskey(ctx, svc, "authz-1")
	if err != nil || lopts == nil {
		t.Fatal(err)
	}
	other := svc
	other.ID = "svc_other"
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishLoginPasskey(ctx, other, lch, req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("challenge from another service: %v", err)
	}
	lopts, lch, _ = u.BeginLoginPasskey(ctx, svc, "authz-1")
	_ = lopts
	req = httptest.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishLoginPasskey(ctx, svc, lch, req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("junk assertion: %v", err)
	}
}

func TestGoogleLoginAndProvider(t *testing.T) {
	u, _, svc := newUsers(t)
	ctx := context.Background()

	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: false}, "ip"); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("unverified email: %v", err)
	}
	first, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "G@x.test", EmailVerified: true, Name: "G"}, "ip")
	if err != nil || first.Method != MethodGoogle || first.Email != "g@x.test" || len(first.Roles) != 1 {
		t.Fatalf("first google login: %+v %v", first, err)
	}
	again, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "changed@x.test", EmailVerified: true}, "ip")
	if err != nil || again.ID != first.ID {
		t.Fatalf("second google login must find the same user: %+v %v", again, err)
	}
	// No linking: a passkey account with that email is a different identity.
	pw, err := u.Create(ctx, svc, "g@x.test", "")
	if err != nil || pw.ID == first.ID {
		t.Fatalf("passkey account beside google account: %+v %v", pw, err)
	}
	disabled := "disabled"
	_, _ = u.Update(ctx, svc, first.ID, nil, &disabled, nil)
	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: true}, "ip"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled google user: %v", err)
	}

	// Provider round trip against a fake Google.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "good" || r.PostForm.Get("client_secret") != "sec" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at"})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "42", "email": "u@x.test", "email_verified": true, "name": "U"})
	})
	fake := httptest.NewServer(mux)
	defer fake.Close()
	g := NewGoogle("cid", "sec", "https://auth.test/v1/login/google/callback")
	g.AuthURL, g.TokenURL, g.UserinfoURL = fake.URL+"/auth", fake.URL+"/token", fake.URL+"/userinfo"
	if !strings.Contains(g.StartURL("st"), "client_id=cid") || !strings.Contains(g.StartURL("st"), "state=st") {
		t.Fatalf("start url: %s", g.StartURL("st"))
	}
	id, err := g.Exchange(ctx, "good")
	if err != nil || id.Sub != "42" || !id.EmailVerified || id.Name != "U" {
		t.Fatalf("exchange: %+v %v", id, err)
	}
	if _, err := g.Exchange(ctx, "bad"); err == nil {
		t.Fatal("bad code accepted")
	}
	state, err := u.SaveGoogleState(ctx, svc.ID, "authz-9")
	if err != nil {
		t.Fatal(err)
	}
	sid, aid, err := u.LoadGoogleState(ctx, state)
	if err != nil || sid != svc.ID || aid != "authz-9" {
		t.Fatalf("state: %s %s %v", sid, aid, err)
	}
	if _, _, err := u.LoadGoogleState(ctx, state); !errors.Is(err, ErrCeremony) {
		t.Fatalf("state reuse: %v", err)
	}
}

func TestDeleteAndExport(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	user, _ := u.Create(ctx, svc, "d@x.test", "D")
	_ = mem.PutUserPasskey(ctx, store.UserPasskey{ServiceID: svc.ID, UserID: user.ID, ID: "c1", Name: "Phone", CreatedAt: u.Now(), Data: []byte(`{"id":"x"}`)})

	exp, err := u.Export(ctx, svc.ID, user.ID)
	if err != nil || exp.User.ID != user.ID || len(exp.Passkeys) != 1 || exp.Passkeys[0].Name != "Phone" {
		t.Fatalf("export: %+v %v", exp, err)
	}
	// The creation event names the user and is included; no key material leaks.
	found := false
	for _, e := range exp.Audit {
		if e.Kind == "user.create" {
			found = true
		}
	}
	if !found {
		t.Fatalf("export audit missing user.create: %+v", exp.Audit)
	}
	raw, _ := json.Marshal(exp)
	if strings.Contains(string(raw), `"data"`) || strings.Contains(string(raw), `"Data"`) {
		t.Fatal("export leaked passkey data")
	}

	if err := u.Delete(ctx, svc.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Get(ctx, svc.ID, user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("deleted user: %v", err)
	}
	if _, err := u.Create(ctx, svc, "d@x.test", "D again"); err != nil {
		t.Fatalf("re-register after delete: %v", err)
	}
	if err := u.Delete(ctx, svc.ID, "usr_ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestClosedSignup(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	_ = mem.UpdateServiceLogin(ctx, svc.ID, svc.LoginURL, svc.RPID, svc.Origins, svc.DefaultRoles, false)
	svc, _ = mem.GetService(ctx, svc.ID)

	// The app cannot sign people up; Google first sign-in is refused.
	if _, err := u.Create(ctx, svc, "a@x.test", "A"); !errors.Is(err, ErrSignupClosed) {
		t.Fatalf("app sign-up on closed pool: %v", err)
	}
	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: true}, "ip"); !errors.Is(err, ErrSignupClosed) {
		t.Fatalf("unknown google identity on closed pool: %v", err)
	}
	if n := countAudit(t, mem, "user.signup_denied"); n != 2 {
		t.Fatalf("signup_denied audits: %d", n)
	}

	// The owner provisions accounts regardless.
	if _, err := u.Provision(ctx, svc, "magic-link", "a@x.test", ""); !errors.Is(err, ErrInvalidMethod) {
		t.Fatalf("bad method: %v", err)
	}
	pk, err := u.Provision(ctx, svc, MethodPasskey, "A@x.test", "A")
	if err != nil || pk.Method != MethodPasskey || pk.Identity != "email:a@x.test" || len(pk.Roles) != 1 {
		t.Fatalf("provision passkey: %+v %v", pk, err)
	}
	g, err := u.Provision(ctx, svc, MethodGoogle, "G@x.test", "G")
	if err != nil || g.Method != MethodGoogle || g.Identity != "google-pending:g@x.test" {
		t.Fatalf("provision google: %+v %v", g, err)
	}
	if _, err := u.Provision(ctx, svc, MethodGoogle, "g@x.test", ""); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("dup pending google: %v", err)
	}

	// First Google sign-in binds the pending account to the real subject, once.
	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "77", Email: "g@x.test", EmailVerified: false}, "ip"); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("unverified email must not bind: %v", err)
	}
	bound, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "77", Email: "G@x.test", EmailVerified: true, Name: "G"}, "ip")
	if err != nil || bound.ID != g.ID || bound.Identity != "google:77" {
		t.Fatalf("bind on first login: %+v %v", bound, err)
	}
	again, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "77", Email: "other@x.test", EmailVerified: true}, "ip")
	if err != nil || again.ID != g.ID {
		t.Fatalf("second login by subject: %+v %v", again, err)
	}
	// Same email, different Google subject: the pending slot is gone, so it is a stranger.
	if _, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "78", Email: "g@x.test", EmailVerified: true}, "ip"); !errors.Is(err, ErrSignupClosed) {
		t.Fatalf("second subject with the same email: %v", err)
	}
	if n := countAudit(t, mem, "user.google.bind"); n != 1 {
		t.Fatalf("bind audits: %d", n)
	}

	// Open pools bind pending accounts too, instead of creating a duplicate.
	_ = mem.UpdateServiceLogin(ctx, svc.ID, svc.LoginURL, svc.RPID, svc.Origins, svc.DefaultRoles, true)
	svc, _ = mem.GetService(ctx, svc.ID)
	p2, _ := u.Provision(ctx, svc, MethodGoogle, "p2@x.test", "")
	b2, err := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "99", Email: "p2@x.test", EmailVerified: true}, "ip")
	if err != nil || b2.ID != p2.ID {
		t.Fatalf("bind on open pool: %+v %v", b2, err)
	}
}

func countAudit(t *testing.T, mem *store.Memory, kind string) int {
	t.Helper()
	events, _, err := mem.ListAudit(context.Background(), "2026-10", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// fakeMail captures the last message and lets a test pull the code out of it.
type fakeMail struct {
	to, subject, text string
	sent              int
	err               error
}

func (f *fakeMail) Send(_ context.Context, to, subject, text string) error {
	f.sent++
	f.to, f.subject, f.text = to, subject, text
	return f.err
}

func (f *fakeMail) code(t *testing.T) string {
	t.Helper()
	for _, w := range strings.Fields(f.text) {
		if len(w) == 6 && strings.Trim(w, "0123456789") == "" {
			return w
		}
	}
	t.Fatalf("no 6-digit code in %q", f.text)
	return ""
}

func TestEmailCodeLogin(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()

	if _, err := u.BeginLoginEmail(ctx, svc, "authz-1", "a@x.test", "ip"); !errors.Is(err, ErrEmailDisabled) {
		t.Fatalf("no mailer: %v", err)
	}
	fm := &fakeMail{}
	u.Mail = fm
	if _, err := u.BeginLoginEmail(ctx, svc, "authz-1", "not-an-email", "ip"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("bad email: %v", err)
	}

	// Open pool: a stranger gets a code; the account appears only once the code is right.
	ch, err := u.BeginLoginEmail(ctx, svc, "authz-1", " New@X.test ", "ip")
	if err != nil || fm.sent != 1 || fm.to != "new@x.test" || !strings.Contains(fm.subject, "FinForge") {
		t.Fatalf("begin: %v sent=%d to=%q subj=%q", err, fm.sent, fm.to, fm.subject)
	}
	if _, _, err := u.FinishLoginEmail(ctx, svc, ch, "000000", "ip"); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, _, err := mem.ListUsers(ctx, svc.ID, 10, ""); err != nil {
		t.Fatal(err)
	} else if list, _, _ := mem.ListUsers(ctx, svc.ID, 10, ""); len(list) != 0 {
		t.Fatalf("no account before the code is right: %+v", list)
	}
	user, authz, err := u.FinishLoginEmail(ctx, svc, ch, " "+fm.code(t)+" ", "ip")
	if err != nil || authz != "authz-1" || user.Method != MethodEmail || user.Identity != "emailcode:new@x.test" || !user.EmailVerified || len(user.Roles) != 1 {
		t.Fatalf("finish: %+v %q %v", user, authz, err)
	}
	// Single use.
	if _, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("replayed code: %v", err)
	}
	// Second sign-in finds the same account.
	ch, _ = u.BeginLoginEmail(ctx, svc, "authz-2", "new@x.test", "ip")
	again, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip")
	if err != nil || again.ID != user.ID {
		t.Fatalf("second login: %+v %v", again, err)
	}
	// Five wrong guesses burn the code.
	ch, _ = u.BeginLoginEmail(ctx, svc, "authz-3", "new@x.test", "ip")
	for i := 0; i < CodeAttempts-1; i++ {
		if _, _, err := u.FinishLoginEmail(ctx, svc, ch, "111111", "ip"); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if _, _, err := u.FinishLoginEmail(ctx, svc, ch, "111111", "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("last guess must burn the code: %v", err)
	}
	if _, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("right code after burn: %v", err)
	}
	// Wrong kind of challenge: a verification code cannot log in.
	pk, _ := u.Create(ctx, svc, "pk@x.test", "")
	vch, err := u.BeginVerifyEmail(ctx, svc, pk.ID, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.FinishLoginEmail(ctx, svc, vch, fm.code(t), "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("verify code used for login: %v", err)
	}
	// Expired code.
	ch, _ = u.BeginLoginEmail(ctx, svc, "authz-4", "new@x.test", "ip")
	code := fm.code(t)
	later := u.Now().Add(CodeTTL + time.Second)
	u.Now = func() time.Time { return later }
	if _, _, err := u.FinishLoginEmail(ctx, svc, ch, code, "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("expired code: %v", err)
	}
	// Mailer failure surfaces and leaves no half state the caller could use.
	fm.err = errors.New("smtp down")
	if _, err := u.BeginLoginEmail(ctx, svc, "authz-5", "new@x.test", "ip"); err == nil {
		t.Fatal("mailer error must surface")
	}
	fm.err = nil

	// Disabled account: no code is sent.
	disabled := "disabled"
	_, _ = u.Update(ctx, svc, user.ID, nil, &disabled, nil)
	sent := fm.sent
	if _, err := u.BeginLoginEmail(ctx, svc, "authz-6", "new@x.test", "ip"); !errors.Is(err, ErrDisabled) || fm.sent != sent {
		t.Fatalf("disabled: %v sent=%d", err, fm.sent-sent)
	}

	// Closed pool: strangers are refused before any mail goes out; provisioned
	// email accounts work.
	_ = mem.UpdateServiceLogin(ctx, svc.ID, svc.LoginURL, svc.RPID, svc.Origins, svc.DefaultRoles, false)
	svc, _ = mem.GetService(ctx, svc.ID)
	if _, err := u.BeginLoginEmail(ctx, svc, "authz-7", "stranger@x.test", "ip"); !errors.Is(err, ErrSignupClosed) || fm.sent != sent {
		t.Fatalf("closed pool stranger: %v sent=%d", err, fm.sent-sent)
	}
	prov, err := u.Provision(ctx, svc, MethodEmail, "me@x.test", "Me")
	if err != nil || prov.Identity != "emailcode:me@x.test" || !prov.EmailVerified {
		t.Fatalf("provision email: %+v %v", prov, err)
	}
	ch, err = u.BeginLoginEmail(ctx, svc, "authz-8", "me@x.test", "ip")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), "ip")
	if err != nil || got.ID != prov.ID {
		t.Fatalf("closed pool provisioned login: %+v %v", got, err)
	}
	if n := countAudit(t, mem, "user.email_code.sent"); n < 6 {
		t.Fatalf("sent audits: %d", n)
	}
}

func TestEmailVerification(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	fm := &fakeMail{}
	u.Mail = fm

	// App-created passkey accounts start unverified and cannot sign in.
	pk, err := u.Create(ctx, svc, "pk@x.test", "P")
	if err != nil || pk.EmailVerified {
		t.Fatalf("create: %+v %v", pk, err)
	}
	if err := u.loginAllowed(ctx, svc, pk, "passkey", "ip"); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("unverified login: %v", err)
	}
	if _, err := u.FinishVerifyEmail(ctx, svc, pk.ID, "nope", "000000", "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("bogus challenge: %v", err)
	}
	ch, err := u.BeginVerifyEmail(ctx, svc, pk.ID, "ip")
	if err != nil || fm.to != "pk@x.test" || !strings.Contains(fm.subject, "Verify") {
		t.Fatalf("begin verify: %v to=%q subj=%q", err, fm.to, fm.subject)
	}
	// Another user cannot consume this code.
	other, _ := u.Create(ctx, svc, "other@x.test", "")
	if _, err := u.FinishVerifyEmail(ctx, svc, other.ID, ch, fm.code(t), "ip"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("code bound to another user: %v", err)
	}
	// The code was consumed by that attempt, so start over.
	ch, _ = u.BeginVerifyEmail(ctx, svc, pk.ID, "ip")
	if _, err := u.FinishVerifyEmail(ctx, svc, pk.ID, ch, "999999", "ip"); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("wrong code: %v", err)
	}
	got, err := u.FinishVerifyEmail(ctx, svc, pk.ID, ch, fm.code(t), "ip")
	if err != nil || !got.EmailVerified {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if err := u.loginAllowed(ctx, svc, got, "passkey", "ip"); err != nil {
		t.Fatalf("verified login: %v", err)
	}
	if _, err := u.BeginVerifyEmail(ctx, svc, pk.ID, "ip"); !errors.Is(err, ErrAlreadyVerified) {
		t.Fatalf("verify twice: %v", err)
	}
	if _, err := u.BeginVerifyEmail(ctx, svc, "usr_missing", "ip"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	// Google and provisioned accounts are born verified.
	g, _ := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "1", Email: "g@x.test", EmailVerified: true}, "ip")
	p, _ := u.Provision(ctx, svc, MethodPasskey, "prov@x.test", "")
	if !g.EmailVerified || !p.EmailVerified {
		t.Fatalf("born verified: google=%v provisioned=%v", g.EmailVerified, p.EmailVerified)
	}
	if n := countAudit(t, mem, "user.email.verified"); n != 1 {
		t.Fatalf("verified audits: %d", n)
	}
	u.Mail = nil
	if _, err := u.BeginVerifyEmail(ctx, svc, other.ID, "ip"); !errors.Is(err, ErrEmailDisabled) {
		t.Fatalf("no mailer: %v", err)
	}
}

func TestRandomDigits(t *testing.T) {
	seen := map[byte]bool{}
	for i := 0; i < 200; i++ {
		d := randomDigits(6)
		if len(d) != 6 || strings.Trim(d, "0123456789") != "" {
			t.Fatalf("bad code %q", d)
		}
		for j := 0; j < len(d); j++ {
			seen[d[j]] = true
		}
	}
	if len(seen) != 10 {
		t.Fatalf("digits seen: %v", seen)
	}
}

func TestPasskeyActivation(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	fm := &fakeMail{}
	u.Mail = fm

	// Open pool: no such passkey account → not found (the app signs them up first).
	if _, err := u.BeginActivatePasskey(ctx, svc, "authz-1", "nobody@x.test", "ip"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown on open pool: %v", err)
	}
	// An email-method account is not a passkey account.
	_, _ = u.Provision(ctx, svc, MethodEmail, "code@x.test", "")
	if _, err := u.BeginActivatePasskey(ctx, svc, "authz-1", "code@x.test", "ip"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("email-method account: %v", err)
	}
	// Provisioned passkey account, unverified app-created one too: both activate.
	prov, _ := u.Provision(ctx, svc, MethodPasskey, "prov@x.test", "P")
	ch, err := u.BeginActivatePasskey(ctx, svc, "authz-1", "Prov@x.test", "ip")
	if err != nil || fm.to != "prov@x.test" || !strings.Contains(fm.subject, "passkey") {
		t.Fatalf("begin activate: %v to=%q subj=%q", err, fm.to, fm.subject)
	}
	if _, _, _, err := u.FinishActivatePasskey(ctx, svc, ch, "000000", "ip"); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("wrong code: %v", err)
	}
	opts, regID, user, err := u.FinishActivatePasskey(ctx, svc, ch, fm.code(t), "ip")
	if err != nil || opts == nil || regID == "" || user.ID != prov.ID {
		t.Fatalf("finish activate: %+v %q %v", opts, regID, err)
	}
	// The registration challenge carries the authz: a junk attestation fails the ceremony but
	// proves the challenge is a registration one bound to this service.
	req, _ := http.NewRequest("POST", "/", strings.NewReader(`{"id":"junk"}`))
	if _, _, err := u.FinishRegisterPasskey(ctx, svc, regID, "Phone", req); !errors.Is(err, ErrCeremony) {
		t.Fatalf("junk attestation: %v", err)
	}
	// An app-created (unverified) passkey account becomes verified by activating.
	fresh, _ := u.Create(ctx, svc, "fresh@x.test", "")
	ch, _ = u.BeginActivatePasskey(ctx, svc, "authz-2", "fresh@x.test", "ip")
	_, _, got, err := u.FinishActivatePasskey(ctx, svc, ch, fm.code(t), "ip")
	if err != nil || got.ID != fresh.ID || !got.EmailVerified {
		t.Fatalf("activation verifies: %+v %v", got, err)
	}
	if n := countAudit(t, mem, "user.email.verified"); n != 1 {
		t.Fatalf("verified audits: %d", n)
	}
	// Closed pool: strangers get signup_closed, nothing sent.
	_ = mem.UpdateServiceLogin(ctx, svc.ID, svc.LoginURL, svc.RPID, svc.Origins, svc.DefaultRoles, false)
	svc, _ = mem.GetService(ctx, svc.ID)
	sent := fm.sent
	if _, err := u.BeginActivatePasskey(ctx, svc, "authz-3", "stranger@x.test", "ip"); !errors.Is(err, ErrSignupClosed) || fm.sent != sent {
		t.Fatalf("closed pool stranger: %v", err)
	}
	if _, err := u.BeginActivatePasskey(ctx, svc, "authz-3", "prov@x.test", "ip"); err != nil {
		t.Fatalf("closed pool provisioned: %v", err)
	}
	u.Mail = nil
	if _, err := u.BeginActivatePasskey(ctx, svc, "authz-3", "prov@x.test", "ip"); !errors.Is(err, ErrEmailDisabled) {
		t.Fatalf("no mailer: %v", err)
	}
}

func TestNewLoginAlerts(t *testing.T) {
	u, mem, svc := newUsers(t)
	ctx := context.Background()
	fm := &fakeMail{}
	u.Mail = fm
	login := func(ip string) store.User {
		t.Helper()
		ch, err := u.BeginLoginEmail(ctx, svc, "authz", "p@x.test", ip)
		if err != nil {
			t.Fatal(err)
		}
		user, _, err := u.FinishLoginEmail(ctx, svc, ch, fm.code(t), ip)
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	alerts := func() int { return countAudit(t, mem, "user.login.alerted") }

	// First ever sign-in (the sign-up) is not an alert; it records the ip.
	user := login("1.1.1.1")
	if got, _ := u.Get(ctx, svc.ID, user.ID); got.LastLoginAt.IsZero() {
		t.Fatal("last_login_at not stamped")
	}
	if alerts() != 0 || strings.Contains(fm.subject, "New sign-in") {
		t.Fatalf("first login alerted: %q", fm.subject)
	}
	// Same address again: quiet.
	login("1.1.1.1")
	if alerts() != 0 {
		t.Fatal("known ip alerted")
	}
	// New address: one alert naming the method and the ip.
	login("2.2.2.2")
	if alerts() != 1 || !strings.Contains(fm.subject, "New sign-in to FinForge") || !strings.Contains(fm.text, "2.2.2.2") || !strings.Contains(fm.text, "email code") || !strings.Contains(fm.text, "https://finforge.test") {
		t.Fatalf("alert: n=%d subj=%q text=%q", alerts(), fm.subject, fm.text)
	}
	// Now both addresses are known.
	login("2.2.2.2")
	login("1.1.1.1")
	if alerts() != 1 {
		t.Fatalf("known ips alerted again: %d", alerts())
	}
	// Per-account cap: the limiter says no → suppressed and audited.
	u.AlertAllowed = func(context.Context, string) bool { return false }
	login("3.3.3.3")
	if alerts() != 1 || countAudit(t, mem, "user.login.alert_suppressed") != 1 {
		t.Fatalf("suppression: alerts=%d", alerts())
	}
	// No ip (e.g. a test harness) → nothing recorded, no alert, no error.
	u.AlertAllowed = nil
	login("")
	if alerts() != 1 {
		t.Fatal("empty ip alerted")
	}
	// Google logins are covered too.
	g, _ := u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "7", Email: "g@x.test", EmailVerified: true}, "5.5.5.5")
	_, _ = u.LoginGoogle(ctx, svc, GoogleIdentity{Sub: "7", Email: "g@x.test", EmailVerified: true}, "6.6.6.6")
	if alerts() != 2 || fm.to != g.Email || !strings.Contains(fm.text, "Google") {
		t.Fatalf("google alert: n=%d to=%q", alerts(), fm.to)
	}
	// After the window the old address is new again (the audit lands in a
	// later month, so judge by the mail itself).
	later := u.Now().Add(SeenIPTTL + time.Hour)
	u.Now = func() time.Time { return later }
	fm.subject = ""
	login("1.1.1.1")
	if !strings.Contains(fm.subject, "New sign-in") {
		t.Fatalf("expired sighting must alert: %q", fm.subject)
	}
}
