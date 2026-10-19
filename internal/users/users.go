// Package users is slice 3: end users of a product. A user belongs to one
// service, has exactly one login method for life (passkey, Google or email code), and
// signs in through the product's own screens; this package owns the
// ceremonies and the account records.
package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nathanblatter/squawk/internal/store"
)

const (
	MethodPasskey = "passkey"
	MethodGoogle  = "google"
	MethodEmail   = "email"

	// CodeTTL is how long a sign-in / verification code stays valid.
	CodeTTL = 10 * time.Minute
	// CodeAttempts is how many wrong guesses one code survives.
	CodeAttempts = 5
	// SeenIPTTL is how long a sign-in address stays "known" for new-login alerts.
	SeenIPTTL = 90 * 24 * time.Hour

	// ChallengeTTL bounds a WebAuthn ceremony.
	ChallengeTTL = 5 * time.Minute
)

var (
	ErrNotUserPool     = errors.New("users: service has no login_url (owner-only)")
	ErrNoWebAuthn      = errors.New("users: service has no rp_id/origins configured")
	ErrInvalidEmail    = errors.New("users: invalid email")
	ErrInvalidMethod   = errors.New("users: method must be passkey or google")
	ErrIdentityTaken   = errors.New("users: an account with this identity already exists")
	ErrUserNotFound    = errors.New("users: user not found")
	ErrCeremony        = errors.New("users: ceremony failed")
	ErrWrongMethod     = errors.New("users: this account uses a different login method")
	ErrDisabled        = errors.New("users: account disabled")
	ErrEmailUnverified = errors.New("users: provider did not verify the email")
	ErrInvalidRole     = errors.New("users: role is not defined on the service")
	ErrSignupClosed    = errors.New("users: sign-up is closed; accounts are created by the owner")
	ErrEmailDisabled   = errors.New("users: email is not configured on this server")
	ErrCodeRejected    = errors.New("users: wrong code")
	ErrAlreadyVerified = errors.New("users: email already verified")
)

// Mailer delivers one plain-text message. nil on Users disables every email feature.
type Mailer interface {
	Send(ctx context.Context, to, subject, text string) error
}

// Users wires the store with per-service WebAuthn instances.
type Users struct {
	Store store.Store
	Now   func() time.Time
	Log   *slog.Logger
	// Mail sends sign-in and verification codes; nil = email features off.
	Mail Mailer
	// AlertAllowed, when set, caps new-login alerts per account (the HTTP
	// layer wires the rate limiter in); nil = no cap.
	AlertAllowed func(ctx context.Context, userID string) bool

	mu sync.Mutex
	wa map[string]*webauthn.WebAuthn // keyed by service id + config fingerprint
}

// New builds the users component.
func New(st store.Store) *Users {
	return &Users{Store: st, Now: time.Now, Log: slog.Default(), wa: map[string]*webauthn.WebAuthn{}}
}

// webauthnFor returns the RP for a service, built from its rp_id/origins.
func (u *Users) webauthnFor(svc store.Service) (*webauthn.WebAuthn, error) {
	if svc.RPID == "" || len(svc.Origins) == 0 {
		return nil, ErrNoWebAuthn
	}
	key := svc.ID + "|" + svc.RPID + "|" + strings.Join(svc.Origins, ",")
	u.mu.Lock()
	defer u.mu.Unlock()
	if wa, ok := u.wa[key]; ok {
		return wa, nil
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: svc.RPID, RPDisplayName: svc.Name, RPOrigins: svc.Origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ChallengeTTL, TimeoutUVD: ChallengeTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("users: webauthn config for %s: %w", svc.Slug, err)
	}
	u.wa[key] = wa
	return wa, nil
}

// ── accounts ───────────────────────────────────────────────────────────────

// Create registers a passkey account on behalf of the app (self sign-up).
// Passkey accounts are keyed on email (lowercased); Google accounts are
// created by the Google flow, not here. Refused on a closed pool.
func (u *Users) Create(ctx context.Context, svc store.Service, email, name string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	if !svc.OpenSignup {
		u.audit(ctx, "user.signup_denied", svc.ID, "", "method=passkey email="+strings.ToLower(strings.TrimSpace(email)), "")
		return store.User{}, ErrSignupClosed
	}
	// The app only told us the address; the person proves it with a code.
	return u.newUser(ctx, svc, MethodPasskey, email, name, false, "user.create")
}

// Provision is the owner's path: it creates an account whatever the pool's
// sign-up setting. A Google account is parked on google-pending:<email> and
// bound to the real Google subject the first time that person signs in.
func (u *Users) Provision(ctx context.Context, svc store.Service, method, email, name string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	if method != MethodPasskey && method != MethodGoogle && method != MethodEmail {
		return store.User{}, ErrInvalidMethod
	}
	// The owner vouches for the address.
	return u.newUser(ctx, svc, method, email, name, true, "user.provision")
}

func (u *Users) newUser(ctx context.Context, svc store.Service, method, email, name string, verified bool, auditKind string) (store.User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return store.User{}, err
	}
	identity := "email:" + email
	switch method {
	case MethodGoogle:
		identity = pendingGoogle + email
	case MethodEmail:
		identity = emailCode + email
	}
	user := store.User{
		ID: "usr_" + randomBase32(16), ServiceID: svc.ID, Method: method, Identity: identity,
		Email: email, Name: strings.TrimSpace(name), Roles: append([]string(nil), svc.DefaultRoles...), Status: "active", CreatedAt: u.Now(),
		EmailVerified: verified,
	}
	if err := u.Store.CreateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.User{}, ErrIdentityTaken
		}
		return store.User{}, err
	}
	u.audit(ctx, auditKind, svc.ID, user.ID, "method="+method, "")
	return user, nil
}

// Get fetches a user of a service.
func (u *Users) Get(ctx context.Context, serviceID, id string) (store.User, error) {
	user, err := u.Store.GetUser(ctx, serviceID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrUserNotFound
	}
	return user, err
}

// List pages a service's users.
func (u *Users) List(ctx context.Context, serviceID string, limit int, cursor string) ([]store.User, string, error) {
	return u.Store.ListUsers(ctx, serviceID, limit, cursor)
}

// Update changes roles, status, name. Roles must exist on the service.
func (u *Users) Update(ctx context.Context, svc store.Service, id string, roles *[]string, status, name *string) (store.User, error) {
	user, err := u.Get(ctx, svc.ID, id)
	if err != nil {
		return store.User{}, err
	}
	if roles != nil {
		for _, r := range *roles {
			if _, ok := svc.Roles[r]; !ok {
				return store.User{}, ErrInvalidRole
			}
		}
		user.Roles = append([]string(nil), *roles...)
	}
	if status != nil {
		if *status != "active" && *status != "disabled" {
			return store.User{}, errors.New("users: status must be active or disabled")
		}
		user.Status = *status
	}
	if name != nil {
		user.Name = strings.TrimSpace(*name)
	}
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return store.User{}, err
	}
	u.audit(ctx, "user.update", svc.ID, user.ID, fmt.Sprintf("roles=%v status=%s", user.Roles, user.Status), "")
	return user, nil
}

// LogoutEverywhere invalidates the user's refresh tokens (auth-service-11).
func (u *Users) LogoutEverywhere(ctx context.Context, serviceID, id string) error {
	user, err := u.Get(ctx, serviceID, id)
	if err != nil {
		return err
	}
	user.NotBefore = u.Now()
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return err
	}
	u.audit(ctx, "user.logout_everywhere", serviceID, id, "", "")
	return nil
}

// Delete removes the account, its identity, passkeys and org memberships
// (auth-service-13). An org whose only admin is deleted keeps its other
// members; the product promotes one with SetMember.
// Refresh tokens die with it: the token endpoint refuses subjects whose user
// row is gone. Already-issued access tokens run out within the hour.
func (u *Users) Delete(ctx context.Context, serviceID, id string) error {
	user, err := u.Get(ctx, serviceID, id)
	if err != nil {
		return err
	}
	if err := u.Store.DeleteUser(ctx, serviceID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	u.audit(ctx, "user.delete", serviceID, id, "method="+user.Method, "")
	return nil
}

// Export is everything this service holds about a user, for a data-portability
// request: the account record and passkey metadata (never key material) plus
// the audit events that name the user this month and last.
type Export struct {
	ExportedAt time.Time          `json:"exported_at"`
	User       store.User         `json:"user"`
	Passkeys   []PasskeyMeta      `json:"passkeys"`
	Orgs       []Membership       `json:"orgs"`
	Audit      []store.AuditEvent `json:"audit"`
}

// PasskeyMeta is a passkey without its public key.
type PasskeyMeta struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Export assembles the user's data.
func (u *Users) Export(ctx context.Context, serviceID, id string) (Export, error) {
	user, err := u.Get(ctx, serviceID, id)
	if err != nil {
		return Export{}, err
	}
	keys, err := u.Store.ListUserPasskeys(ctx, serviceID, id)
	if err != nil {
		return Export{}, err
	}
	out := Export{ExportedAt: u.Now(), User: user, Passkeys: make([]PasskeyMeta, 0, len(keys)), Audit: []store.AuditEvent{}}
	for _, k := range keys {
		out.Passkeys = append(out.Passkeys, PasskeyMeta{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt})
	}
	if out.Orgs, err = u.memberships(ctx, serviceID, id); err != nil {
		return Export{}, err
	}
	actor := "usr:" + id
	for _, month := range []string{u.Now().UTC().Format("2006-01"), u.Now().UTC().AddDate(0, -1, 0).Format("2006-01")} {
		cursor := ""
		for page := 0; page < 20; page++ { // bounded: at most 20 × 200 rows per month
			events, next, err := u.Store.ListAudit(ctx, month, 200, cursor)
			if err != nil {
				return Export{}, err
			}
			for _, e := range events {
				if e.Actor == actor && e.ServiceID == serviceID {
					out.Audit = append(out.Audit, e)
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	u.audit(ctx, "user.export", serviceID, id, "", "")
	return out, nil
}

// AllowedScopes is the union of the scopes of the user's roles, in catalog order.
func AllowedScopes(svc store.Service, user store.User) []string {
	have := map[string]bool{}
	for _, r := range user.Roles {
		for _, sc := range svc.Roles[r] {
			have[sc] = true
		}
	}
	out := make([]string, 0, len(have))
	for _, sc := range svc.Scopes {
		if have[sc] {
			out = append(out, sc)
		}
	}
	return out
}

// ── passkeys ───────────────────────────────────────────────────────────────

type waUser struct {
	user  store.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(w.user.ID) }
func (w waUser) WebAuthnName() string                       { return w.user.Email }
func (w waUser) WebAuthnDisplayName() string                { return nameOr(w.user) }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func nameOr(u store.User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

func (u *Users) loadWAUser(ctx context.Context, user store.User) (waUser, []store.UserPasskey, error) {
	keys, err := u.Store.ListUserPasskeys(ctx, user.ServiceID, user.ID)
	if err != nil {
		return waUser{}, nil, err
	}
	w := waUser{user: user, creds: make([]webauthn.Credential, 0, len(keys))}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Data, &c); err != nil {
			return waUser{}, nil, fmt.Errorf("users: corrupt passkey %s: %w", k.ID, err)
		}
		w.creds = append(w.creds, c)
	}
	return w, keys, nil
}

// BeginRegisterPasskey starts adding a passkey to a passkey-method user.
func (u *Users) BeginRegisterPasskey(ctx context.Context, svc store.Service, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := u.Get(ctx, svc.ID, userID)
	if err != nil {
		return nil, "", err
	}
	return u.beginRegister(ctx, svc, user, "")
}

// beginRegister builds registration options. authzID, when set, rides on the
// challenge so a successful registration also completes that sign-in.
func (u *Users) beginRegister(ctx context.Context, svc store.Service, user store.User, authzID string) (*protocol.CredentialCreation, string, error) {
	if user.Method != MethodPasskey {
		return nil, "", ErrWrongMethod
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return nil, "", err
	}
	w, _, err := u.loadWAUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(w.creds))
	for _, c := range w.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sess, err := wa.BeginRegistration(w,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, "", err
	}
	id, err := u.saveChallenge(ctx, challengeData{Session: sess, ServiceID: svc.ID, UserID: user.ID, AuthzID: authzID})
	return opts, id, err
}

// FinishRegisterPasskey verifies the attestation and stores the credential.
// The returned authz id is non-empty when the registration came from a
// passkey activation and should complete that sign-in.
func (u *Users) FinishRegisterPasskey(ctx context.Context, svc store.Service, challengeID, name string, r *http.Request) (store.UserPasskey, string, error) {
	ch, err := u.loadChallenge(ctx, challengeID)
	if err != nil || ch.ServiceID != svc.ID || ch.UserID == "" || ch.Session == nil {
		return store.UserPasskey{}, "", ErrCeremony
	}
	user, err := u.Get(ctx, svc.ID, ch.UserID)
	if err != nil {
		return store.UserPasskey{}, "", err
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return store.UserPasskey{}, "", err
	}
	w, _, err := u.loadWAUser(ctx, user)
	if err != nil {
		return store.UserPasskey{}, "", err
	}
	cred, err := wa.FinishRegistration(w, *ch.Session, r)
	if err != nil {
		u.Log.Warn("user passkey registration failed", "service", svc.Slug, "err", err)
		return store.UserPasskey{}, "", ErrCeremony
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.UserPasskey{}, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	pk := store.UserPasskey{ServiceID: svc.ID, UserID: user.ID, ID: b64(cred.ID), Name: name, CreatedAt: u.Now(), Data: data}
	if err := u.Store.PutUserPasskey(ctx, pk); err != nil {
		return store.UserPasskey{}, "", err
	}
	u.audit(ctx, "user.passkey.register", svc.ID, user.ID, "pk="+pk.ID, clientIP(r))
	if ch.AuthzID != "" {
		u.audit(ctx, "user.login", svc.ID, user.ID, "passkey activation", clientIP(r))
		u.noteLogin(ctx, svc, user, "new passkey", clientIP(r))
	}
	pk.Data = nil
	return pk, ch.AuthzID, nil
}

// BeginLoginPasskey starts a usernameless passkey sign-in for a pending
// authorization (login_challenge). The challenge row remembers the authz id.
func (u *Users) BeginLoginPasskey(ctx context.Context, svc store.Service, authzID string) (*protocol.CredentialAssertion, string, error) {
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return nil, "", err
	}
	opts, sess, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	id, err := u.saveChallenge(ctx, challengeData{Session: sess, ServiceID: svc.ID, AuthzID: authzID})
	return opts, id, err
}

// FinishLoginPasskey verifies the assertion and returns the user plus the
// authz id the ceremony was started for.
func (u *Users) FinishLoginPasskey(ctx context.Context, svc store.Service, challengeID string, r *http.Request) (store.User, string, error) {
	ip := clientIP(r)
	ch, err := u.loadChallenge(ctx, challengeID)
	if err != nil || ch.ServiceID != svc.ID {
		return store.User{}, "", ErrCeremony
	}
	wa, err := u.webauthnFor(svc)
	if err != nil {
		return store.User{}, "", err
	}
	var matched store.User
	var matchedKey store.UserPasskey
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		pk, err := u.Store.GetUserPasskeyByCred(ctx, svc.ID, b64(rawID))
		if err != nil {
			return nil, errors.New("unknown credential")
		}
		if string(userHandle) != pk.UserID {
			return nil, errors.New("user handle mismatch")
		}
		user, err := u.Store.GetUser(ctx, svc.ID, pk.UserID)
		if err != nil {
			return nil, errors.New("unknown user")
		}
		w, _, err := u.loadWAUser(ctx, user)
		if err != nil {
			return nil, err
		}
		matched, matchedKey = user, pk
		return w, nil
	}
	cred, err := wa.FinishDiscoverableLogin(handler, *ch.Session, r)
	if err != nil || cred.Authenticator.CloneWarning {
		u.audit(ctx, "user.login_denied", svc.ID, matched.ID, "passkey", ip)
		return store.User{}, "", ErrCeremony
	}
	if matched.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, matched.ID, "disabled", ip)
		return store.User{}, "", ErrDisabled
	}
	if err := u.loginAllowed(ctx, svc, matched, "passkey", ip); err != nil {
		return store.User{}, "", err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return store.User{}, "", err
	}
	matchedKey.Data = data
	if err := u.Store.UpdateUserPasskey(ctx, matchedKey); err != nil {
		return store.User{}, "", err
	}
	u.audit(ctx, "user.login", svc.ID, matched.ID, "passkey", ip)
	u.noteLogin(ctx, svc, matched, "passkey", ip)
	return matched, ch.AuthzID, nil
}

// ── Google ─────────────────────────────────────────────────────────────────

// GoogleIdentity is what the provider tells us about the signed-in person.
type GoogleIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// pendingGoogle prefixes the identity of an owner-provisioned Google account
// that has not signed in yet; LoginGoogle rebinds it to google:<sub>.
const pendingGoogle = "google-pending:"

// LoginGoogle finds the user for a verified Google identity. An unknown
// subject is bound to a pre-provisioned account with that verified email, or
// created on an open pool; on a closed pool it is refused.
func (u *Users) LoginGoogle(ctx context.Context, svc store.Service, g GoogleIdentity, ip string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	if g.Sub == "" || !g.EmailVerified {
		return store.User{}, ErrEmailUnverified
	}
	identity := "google:" + g.Sub
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, identity)
	switch {
	case errors.Is(err, store.ErrNotFound):
		email, _ := normalizeEmail(g.Email)
		if email != "" {
			pending, perr := u.Store.GetUserByIdentity(ctx, svc.ID, pendingGoogle+email)
			switch {
			case perr == nil:
				if err := u.Store.RebindUserIdentity(ctx, svc.ID, pending.ID, pendingGoogle+email, identity); err != nil {
					return store.User{}, err
				}
				pending.Identity = identity
				u.audit(ctx, "user.google.bind", svc.ID, pending.ID, "", ip)
				return u.finishGoogle(ctx, svc, pending, ip)
			case !errors.Is(perr, store.ErrNotFound):
				return store.User{}, perr
			}
		}
		if !svc.OpenSignup {
			u.audit(ctx, "user.signup_denied", svc.ID, "", "method=google email="+email, ip)
			return store.User{}, ErrSignupClosed
		}
		user = store.User{
			ID: "usr_" + randomBase32(16), ServiceID: svc.ID, Method: MethodGoogle, Identity: identity,
			Email: email, Name: strings.TrimSpace(g.Name), Roles: append([]string(nil), svc.DefaultRoles...), Status: "active", CreatedAt: u.Now(),
			EmailVerified: true, // Google asserted email_verified
		}
		if err := u.Store.CreateUser(ctx, user); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return store.User{}, ErrIdentityTaken
			}
			return store.User{}, err
		}
		u.audit(ctx, "user.create", svc.ID, user.ID, "method=google", ip)
	case err != nil:
		return store.User{}, err
	}
	return u.finishGoogle(ctx, svc, user, ip)
}

func (u *Users) finishGoogle(ctx context.Context, svc store.Service, user store.User, ip string) (store.User, error) {
	if user.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return store.User{}, ErrDisabled
	}
	u.audit(ctx, "user.login", svc.ID, user.ID, "google", ip)
	u.noteLogin(ctx, svc, user, "Google", ip)
	return user, nil
}

// ── new-login alerts ───────────────────────────────────────────────────────

// noteLogin stamps the account's last sign-in and, when the address has not
// been seen on this account within SeenIPTTL, emails the person. The very
// first sign-in of an account is never alerted (it is the sign-up). Alerts
// are best effort: nothing here can fail the sign-in.
func (u *Users) noteLogin(ctx context.Context, svc store.Service, user store.User, how, ip string) {
	u.claimInvites(ctx, svc, user, ip)
	now := u.Now()
	firstEver := user.LastLoginAt.IsZero()
	user.LastLoginAt = now
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		u.Log.Error("last_login_at update failed", "user", user.ID, "err", err)
	}
	if ip == "" {
		return
	}
	known, err := u.Store.TouchSeenIP(ctx, svc.ID, user.ID, ip, now, SeenIPTTL)
	if err != nil {
		u.Log.Error("seen ip update failed", "user", user.ID, "err", err)
		return
	}
	if known || firstEver || u.Mail == nil || user.Email == "" {
		return
	}
	if u.AlertAllowed != nil && !u.AlertAllowed(ctx, user.ID) {
		u.audit(ctx, "user.login.alert_suppressed", svc.ID, user.ID, "rate limit", ip)
		return
	}
	app := svc.Name
	if o, err := url.Parse(svc.LoginURL); err == nil && o.Host != "" {
		app = o.Scheme + "://" + o.Host
	}
	text := fmt.Sprintf("Someone just signed in to your %s account.\n\nWhen:   %s\nHow:    %s\nFrom:   %s\n\nIf this was you, there is nothing to do.\nIf it wasn't, sign in at %s, sign out everywhere from your account settings, and change how you sign in.",
		svc.Name, now.UTC().Format("2006-01-02 15:04 UTC"), how, ip, app)
	if err := u.Mail.Send(ctx, user.Email, fmt.Sprintf("New sign-in to %s", svc.Name), text); err != nil {
		u.Log.Error("login alert email failed", "user", user.ID, "err", err)
		return
	}
	u.audit(ctx, "user.login.alerted", svc.ID, user.ID, how+" ip="+ip, ip)
}

// ── passkey activation ─────────────────────────────────────────────────────

// BeginActivatePasskey lets a passkey-method account that cannot sign in yet
// (owner-provisioned, or on a new device) prove its address with an emailed
// code and then register a passkey. Found by the address the account was
// created with.
func (u *Users) BeginActivatePasskey(ctx context.Context, svc store.Service, authzID, email, ip string) (string, error) {
	if svc.LoginURL == "" {
		return "", ErrNotUserPool
	}
	if u.Mail == nil {
		return "", ErrEmailDisabled
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return "", err
	}
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, "email:"+email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !svc.OpenSignup {
			u.audit(ctx, "user.signup_denied", svc.ID, "", "method=passkey-activate email="+email, ip)
			return "", ErrSignupClosed
		}
		return "", ErrUserNotFound // open pool: the app's sign-up creates the account first
	case err != nil:
		return "", err
	case user.Status != "active":
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return "", ErrDisabled
	}
	chID, err := u.sendCode(ctx, svc, challengeData{Kind: "activate_passkey", ServiceID: svc.ID, AuthzID: authzID, UserID: user.ID, Email: email},
		fmt.Sprintf("Set up your %s passkey", svc.Name),
		fmt.Sprintf("Enter this code to add a passkey to your %s account:\n\n    %%s\n\nIt expires in %d minutes. If you didn't request it, ignore this email.", svc.Name, int(CodeTTL.Minutes())))
	if err != nil {
		return "", err
	}
	u.audit(ctx, "user.email_code.sent", svc.ID, user.ID, "activate email="+email, ip)
	return chID, nil
}

// FinishActivatePasskey checks the code, marks the address verified (the code
// proved it) and returns registration options whose challenge carries the
// parked authorization, so FinishRegisterPasskey completes the sign-in.
func (u *Users) FinishActivatePasskey(ctx context.Context, svc store.Service, challengeID, code, ip string) (*protocol.CredentialCreation, string, store.User, error) {
	ch, err := u.checkCode(ctx, svc, challengeID, "activate_passkey", code)
	if err != nil {
		return nil, "", store.User{}, err
	}
	user, err := u.Get(ctx, svc.ID, ch.UserID)
	if err != nil {
		return nil, "", store.User{}, err
	}
	if user.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return nil, "", store.User{}, ErrDisabled
	}
	if !user.EmailVerified {
		user.EmailVerified = true
		if err := u.Store.UpdateUser(ctx, user); err != nil {
			return nil, "", store.User{}, err
		}
		u.audit(ctx, "user.email.verified", svc.ID, user.ID, "passkey activation", ip)
	}
	opts, regID, err := u.beginRegister(ctx, svc, user, ch.AuthzID)
	if err != nil {
		return nil, "", store.User{}, err
	}
	return opts, regID, user, nil
}

// ── email codes ────────────────────────────────────────────────────────────

// emailCode prefixes the identity of an email-code account. It is distinct
// from a passkey account's "email:" lock on purpose: one method for life, no
// linking (DECIDED), so the same address may own one account per method.
const emailCode = "emailcode:"

// loginAllowed is the last gate before a sign-in succeeds: the address must
// be proven. Google, email-code and owner-provisioned accounts are born
// verified; app-created passkey accounts verify with a code first.
func (u *Users) loginAllowed(ctx context.Context, svc store.Service, user store.User, how, ip string) error {
	if !user.EmailVerified {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, how+" email_unverified", ip)
		return ErrEmailUnverified
	}
	return nil
}

// BeginLoginEmail emails a sign-in code for a parked authorization. The
// account need not exist yet on an open pool; on a closed pool it must.
func (u *Users) BeginLoginEmail(ctx context.Context, svc store.Service, authzID, email, ip string) (string, error) {
	if svc.LoginURL == "" {
		return "", ErrNotUserPool
	}
	if u.Mail == nil {
		return "", ErrEmailDisabled
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return "", err
	}
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, emailCode+email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !svc.OpenSignup {
			u.audit(ctx, "user.signup_denied", svc.ID, "", "method=email email="+email, ip)
			return "", ErrSignupClosed
		}
	case err != nil:
		return "", err
	case user.Status != "active":
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return "", ErrDisabled
	}
	chID, err := u.sendCode(ctx, svc, challengeData{Kind: "login_email", ServiceID: svc.ID, AuthzID: authzID, Email: email, UserID: user.ID},
		fmt.Sprintf("Your %s sign-in code", svc.Name),
		fmt.Sprintf("Enter this code to sign in to %s:\n\n    %%s\n\nIt expires in %d minutes. If you didn't request it, ignore this email.", svc.Name, int(CodeTTL.Minutes())))
	if err != nil {
		return "", err
	}
	u.audit(ctx, "user.email_code.sent", svc.ID, user.ID, "login email="+email, ip)
	return chID, nil
}

// FinishLoginEmail checks the code. On success the account is created if it
// does not exist yet (the code proved the address), and the parked
// authorization id is returned so the caller can complete it.
func (u *Users) FinishLoginEmail(ctx context.Context, svc store.Service, challengeID, code, ip string) (store.User, string, error) {
	ch, err := u.checkCode(ctx, svc, challengeID, "login_email", code)
	if err != nil {
		return store.User{}, "", err
	}
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, emailCode+ch.Email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !svc.OpenSignup {
			// The pool closed between begin and finish.
			u.audit(ctx, "user.signup_denied", svc.ID, "", "method=email email="+ch.Email, ip)
			return store.User{}, "", ErrSignupClosed
		}
		user, err = u.newUser(ctx, svc, MethodEmail, ch.Email, "", true, "user.create")
		if err != nil {
			return store.User{}, "", err
		}
	case err != nil:
		return store.User{}, "", err
	}
	if user.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return store.User{}, "", ErrDisabled
	}
	u.audit(ctx, "user.login", svc.ID, user.ID, "email", ip)
	u.noteLogin(ctx, svc, user, "email code", ip)
	return user, ch.AuthzID, nil
}

// BeginVerifyEmail emails a verification code to an unverified account
// (an app-created passkey sign-up).
func (u *Users) BeginVerifyEmail(ctx context.Context, svc store.Service, userID, ip string) (string, error) {
	if u.Mail == nil {
		return "", ErrEmailDisabled
	}
	user, err := u.Get(ctx, svc.ID, userID)
	if err != nil {
		return "", err
	}
	if user.EmailVerified {
		return "", ErrAlreadyVerified
	}
	chID, err := u.sendCode(ctx, svc, challengeData{Kind: "verify_email", ServiceID: svc.ID, UserID: user.ID, Email: user.Email},
		fmt.Sprintf("Verify your email for %s", svc.Name),
		fmt.Sprintf("Enter this code to verify your email address for %s:\n\n    %%s\n\nIt expires in %d minutes. If you didn't request it, ignore this email.", svc.Name, int(CodeTTL.Minutes())))
	if err != nil {
		return "", err
	}
	u.audit(ctx, "user.email_code.sent", svc.ID, user.ID, "verify email="+user.Email, ip)
	return chID, nil
}

// FinishVerifyEmail checks the code and marks the account verified.
func (u *Users) FinishVerifyEmail(ctx context.Context, svc store.Service, userID, challengeID, code, ip string) (store.User, error) {
	ch, err := u.checkCode(ctx, svc, challengeID, "verify_email", code)
	if err != nil {
		return store.User{}, err
	}
	if ch.UserID != userID {
		return store.User{}, ErrCeremony
	}
	user, err := u.Get(ctx, svc.ID, userID)
	if err != nil {
		return store.User{}, err
	}
	user.EmailVerified = true
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return store.User{}, err
	}
	u.audit(ctx, "user.email.verified", svc.ID, user.ID, "", ip)
	u.claimInvites(ctx, svc, user, ip)
	return user, nil
}

// sendCode mints a 6-digit code, stores its hash in a challenge row and mails
// it. bodyFmt has one %s for the code.
func (u *Users) sendCode(ctx context.Context, svc store.Service, c challengeData, subject, bodyFmt string) (string, error) {
	code := randomDigits(6)
	id := "u" + randomToken()
	c.CodeHash = hashCode(id, code)
	c.Expires = u.Now().Add(CodeTTL)
	if err := u.putChallenge(ctx, id, c, c.Expires); err != nil {
		return "", err
	}
	if err := u.Mail.Send(ctx, c.Email, subject, fmt.Sprintf(bodyFmt, code)); err != nil {
		u.Log.Error("code email failed", "service", svc.Slug, "err", err)
		return "", err
	}
	return id, nil
}

// checkCode consumes the challenge and compares. A wrong guess puts the row
// back with attempts+1 and the original expiry, until CodeAttempts is spent.
func (u *Users) checkCode(ctx context.Context, svc store.Service, challengeID, kind, code string) (challengeData, error) {
	ch, err := u.loadChallenge(ctx, challengeID)
	if err != nil || ch.Kind != kind || ch.ServiceID != svc.ID {
		return challengeData{}, ErrCeremony
	}
	if subtle.ConstantTimeCompare([]byte(hashCode(challengeID, strings.TrimSpace(code))), []byte(ch.CodeHash)) == 1 {
		return ch, nil
	}
	ch.Attempts++
	if ch.Attempts < CodeAttempts {
		if err := u.putChallenge(ctx, challengeID, ch, ch.Expires); err != nil {
			return challengeData{}, err
		}
		return challengeData{}, ErrCodeRejected
	}
	u.audit(ctx, "user.login_denied", svc.ID, ch.UserID, kind+" code attempts exhausted email="+ch.Email, "")
	return challengeData{}, ErrCeremony
}

func hashCode(challengeID, code string) string {
	sum := sha256.Sum256([]byte(challengeID + ":" + code))
	return b64(sum[:])
}

// randomDigits returns n uniformly random decimal digits.
func randomDigits(n int) string {
	var out strings.Builder
	for out.Len() < n {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("users: crypto/rand failed: %v", err))
		}
		if b[0] < 250 { // 250 = 25*10, so each digit is equally likely
			out.WriteByte('0' + b[0]%10)
		}
	}
	return out.String()
}

// ── challenges ─────────────────────────────────────────────────────────────

type challengeData struct {
	Session   *webauthn.SessionData `json:"session,omitempty"`
	ServiceID string                `json:"service_id"`
	UserID    string                `json:"user_id,omitempty"`
	AuthzID   string                `json:"authz_id,omitempty"`
	Nonce     string                `json:"nonce,omitempty"`
	// Email codes: what the code is for, who it went to, its hash, how many
	// wrong guesses so far, and when the row dies (kept so a re-put after a
	// wrong guess does not extend the life of the code).
	Kind     string    `json:"kind,omitempty"` // login_email | verify_email
	Email    string    `json:"email,omitempty"`
	CodeHash string    `json:"code_hash,omitempty"`
	Attempts int       `json:"attempts,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
}

func (u *Users) saveChallenge(ctx context.Context, c challengeData) (string, error) {
	id := "u" + randomToken()
	return id, u.putChallenge(ctx, id, c, u.Now().Add(ChallengeTTL))
}

func (u *Users) putChallenge(ctx context.Context, id string, c challengeData, expires time.Time) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return u.Store.PutChallenge(ctx, id, data, expires)
}

func (u *Users) loadChallenge(ctx context.Context, id string) (challengeData, error) {
	if id == "" {
		return challengeData{}, ErrCeremony
	}
	data, err := u.Store.ConsumeChallenge(ctx, id, u.Now())
	if errors.Is(err, store.ErrNotFound) {
		return challengeData{}, ErrCeremony
	}
	if err != nil {
		return challengeData{}, err
	}
	var c challengeData
	if err := json.Unmarshal(data, &c); err != nil {
		return challengeData{}, ErrCeremony
	}
	return c, nil
}

// SaveGoogleState parks the authz id behind a random state for the Google
// round trip; LoadGoogleState consumes it.
func (u *Users) SaveGoogleState(ctx context.Context, serviceID, authzID string) (string, error) {
	return u.saveChallenge(ctx, challengeData{ServiceID: serviceID, AuthzID: authzID})
}

// LoadGoogleState resolves a state parameter to (service id, authz id).
func (u *Users) LoadGoogleState(ctx context.Context, state string) (serviceID, authzID string, err error) {
	c, err := u.loadChallenge(ctx, state)
	if err != nil {
		return "", "", err
	}
	return c.ServiceID, c.AuthzID, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func (u *Users) audit(ctx context.Context, kind, serviceID, userID, detail, ip string) {
	actor := "anonymous"
	if userID != "" {
		actor = "usr:" + userID
	}
	e := store.AuditEvent{At: u.Now(), Kind: kind, Actor: actor, ServiceID: serviceID, Detail: detail, IP: ip}
	if err := u.Store.AppendAudit(ctx, e); err != nil {
		u.Log.Error("audit write failed", "kind", kind, "err", err)
	}
}

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", ErrInvalidEmail
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || len(s) > 254 {
		return "", ErrInvalidEmail
	}
	return s, nil
}

// ValidLoginURL accepts absolute https URLs (http for localhost dev).
func ValidLoginURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && u.Hostname() == "localhost")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("users: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomBase32(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("users: crypto/rand failed: %v", err))
	}
	return strings.ToLower(b32.EncodeToString(buf))[:n]
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// Hash is exported for tests that need the identity key format.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
