package users

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/nathanblatter/squawk/internal/store"
)

// Password accounts (auth-service-33). DECIDED (Nathan, 2026-10-19): a
// fourth method, password, so a product's existing users (AI Therapist:
// bcrypt hashes, pseudonymous usernames, no email) can move onto Squawk
// without a reset. Identity is username:<lower-cased name>; the account may
// have no email at all, so nothing here mails anyone. Registering a passkey
// CONVERTS the account (method becomes passkey, the hash is deleted); the
// owner or the product setting a new password converts it back and drops the
// passkeys. One method for life, just a different one over time.

const (
	// DefaultBcryptCost is used for passwords Squawk hashes itself (Users.Cost
	// overrides it; tests use bcrypt.MinCost). Imported hashes keep their own.
	DefaultBcryptCost = 12
	// PasswordMin / PasswordMax bound a new password (72 is bcrypt's input limit).
	PasswordMin = 8
	PasswordMax = 72
	// UsernameMax bounds a username.
	UsernameMax = 64
)

const usernameIdentity = "username:"

var (
	ErrInvalidUsername  = errors.New("users: username must be 1-64 visible characters without spaces")
	ErrWeakPassword     = errors.New("users: password must be 8-72 characters")
	ErrInvalidHash      = errors.New("users: password_hash must be a bcrypt hash")
	ErrPasswordRejected = errors.New("users: wrong username or password")
	ErrNoPassword       = errors.New("users: password or password_hash required")
)

// PasswordAccount is what the owner (or an import) provides for a password
// user. Exactly one of Password / PasswordHash is required; Email is optional
// and vouched for by the owner when present.
type PasswordAccount struct {
	Username     string
	Name         string
	Email        string
	Roles        []string // nil = the service's default roles
	Password     string
	PasswordHash string
}

func normalizeUsername(s string) (display, key string, err error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > UsernameMax {
		return "", "", ErrInvalidUsername
	}
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return "", "", ErrInvalidUsername
		}
	}
	return s, strings.ToLower(s), nil
}

func (u *Users) bcryptCost() int {
	if u.Cost > 0 {
		return u.Cost
	}
	return DefaultBcryptCost
}

// dummyHash is compared against when the username is unknown, so a missing
// account costs the same time as a wrong password.
func (u *Users) dummyHash() []byte {
	u.dummyOnce.Do(func() {
		h, err := bcrypt.GenerateFromPassword([]byte("squawk-no-such-user"), u.bcryptCost())
		if err != nil {
			panic(err)
		}
		u.dummy = h
	})
	return u.dummy
}

// resolveHash turns a plaintext password or a supplied bcrypt hash into the
// hash to store.
func (u *Users) resolveHash(password, hash string) (string, error) {
	switch {
	case password != "" && hash != "":
		return "", ErrNoPassword
	case hash != "":
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return "", ErrInvalidHash
		}
		return hash, nil
	case password != "":
		if len(password) < PasswordMin || len(password) > PasswordMax {
			return "", ErrWeakPassword
		}
		out, err := bcrypt.GenerateFromPassword([]byte(password), u.bcryptCost())
		if err != nil {
			return "", err
		}
		return string(out), nil
	default:
		return "", ErrNoPassword
	}
}

// ProvisionPassword is the owner's path for a password account (also what a
// migration import calls, one user at a time). Works whatever open_signup
// says, like Provision.
func (u *Users) ProvisionPassword(ctx context.Context, svc store.Service, in PasswordAccount) (store.User, error) {
	return u.newPasswordUser(ctx, svc, in, "user.provision")
}

// CreatePassword is the app's path: a product whose sign-up form takes a
// username and password (study participants joining by invite link) creates
// the account under its service token. Refused on a closed pool, like
// Create. Roles are the service's defaults unless given.
func (u *Users) CreatePassword(ctx context.Context, svc store.Service, in PasswordAccount) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	if !svc.OpenSignup {
		u.audit(ctx, "user.signup_denied", svc.ID, "", "method=password username="+strings.TrimSpace(in.Username), "")
		return store.User{}, ErrSignupClosed
	}
	return u.newPasswordUser(ctx, svc, in, "user.create")
}

func (u *Users) newPasswordUser(ctx context.Context, svc store.Service, in PasswordAccount, auditKind string) (store.User, error) {
	if svc.LoginURL == "" {
		return store.User{}, ErrNotUserPool
	}
	display, key, err := normalizeUsername(in.Username)
	if err != nil {
		return store.User{}, err
	}
	hash, err := u.resolveHash(in.Password, in.PasswordHash)
	if err != nil {
		return store.User{}, err
	}
	email := ""
	if strings.TrimSpace(in.Email) != "" {
		if email, err = normalizeEmail(in.Email); err != nil {
			return store.User{}, err
		}
	}
	roles := append([]string(nil), svc.DefaultRoles...)
	if in.Roles != nil {
		for _, r := range in.Roles {
			if _, ok := svc.Roles[r]; !ok {
				return store.User{}, ErrInvalidRole
			}
		}
		roles = append([]string(nil), in.Roles...)
	}
	user := store.User{
		ID: "usr_" + randomBase32(16), ServiceID: svc.ID, Method: MethodPassword, Identity: usernameIdentity + key,
		Username: display, PasswordHash: hash, Email: email, Name: strings.TrimSpace(in.Name), Roles: roles, Status: "active", CreatedAt: u.Now(),
		EmailVerified: true, // the owner vouches; a name-only account has nothing to verify
	}
	if err := u.Store.CreateUser(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.User{}, ErrIdentityTaken
		}
		return store.User{}, err
	}
	u.audit(ctx, auditKind, svc.ID, user.ID, "method=password username="+display, "")
	return user, nil
}

// LoginPassword checks a username + password for a parked authorization.
// Every refusal is the same error (no account enumeration) and is audited.
func (u *Users) LoginPassword(ctx context.Context, svc store.Service, authzID, username, password, ip string) (store.User, string, error) {
	_, key, err := normalizeUsername(username)
	if err != nil {
		return store.User{}, "", ErrPasswordRejected
	}
	user, err := u.Store.GetUserByIdentity(ctx, svc.ID, usernameIdentity+key)
	if errors.Is(err, store.ErrNotFound) {
		// Burn comparable time so a missing name is not faster than a wrong password.
		_ = bcrypt.CompareHashAndPassword(u.dummyHash(), []byte(password))
		u.audit(ctx, "user.login_denied", svc.ID, "", "password unknown username", ip)
		return store.User{}, "", ErrPasswordRejected
	}
	if err != nil {
		return store.User{}, "", err
	}
	if user.Method != MethodPassword || user.PasswordHash == "" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "password wrong method", ip)
		return store.User{}, "", ErrWrongMethod
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "password", ip)
		return store.User{}, "", ErrPasswordRejected
	}
	if user.Status != "active" {
		u.audit(ctx, "user.login_denied", svc.ID, user.ID, "disabled", ip)
		return store.User{}, "", ErrDisabled
	}
	if err := u.loginAllowed(ctx, svc, user, "password", ip); err != nil {
		return store.User{}, "", err
	}
	u.audit(ctx, "user.login", svc.ID, user.ID, "password", ip)
	u.noteLogin(ctx, svc, user, "password", ip)
	return user, authzID, nil
}

// SetPassword gives an account a (new) password. On a passkey account that
// was converted from a password one, or any account with a username, this
// converts it back: method password, passkeys removed, sessions kept. Used
// by the owner (lost passkey) and by the product (its own reset flow).
func (u *Users) SetPassword(ctx context.Context, svc store.Service, userID, password, hash, ip string) (store.User, error) {
	user, err := u.Get(ctx, svc.ID, userID)
	if err != nil {
		return store.User{}, err
	}
	if user.Username == "" {
		return store.User{}, ErrWrongMethod
	}
	if user.PasswordHash, err = u.resolveHash(password, hash); err != nil {
		return store.User{}, err
	}
	converted := user.Method != MethodPassword
	user.Method = MethodPassword
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return store.User{}, err
	}
	if converted {
		keys, err := u.Store.ListUserPasskeys(ctx, svc.ID, user.ID)
		if err != nil {
			return store.User{}, err
		}
		for _, k := range keys {
			if err := u.Store.DeleteUserPasskey(ctx, svc.ID, user.ID, k.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return store.User{}, err
			}
		}
		u.audit(ctx, "user.method.converted", svc.ID, user.ID, "to=password passkeys_removed="+itoa(len(keys)), ip)
	}
	u.audit(ctx, "user.password.set", svc.ID, user.ID, "", ip)
	return user, nil
}

// convertToPasskey finishes the upgrade of a password account: the first
// registered passkey becomes the method and the hash is deleted.
func (u *Users) convertToPasskey(ctx context.Context, svc store.Service, user store.User, ip string) (store.User, error) {
	user.Method = MethodPasskey
	user.PasswordHash = ""
	if err := u.Store.UpdateUser(ctx, user); err != nil {
		return store.User{}, err
	}
	u.audit(ctx, "user.method.converted", svc.ID, user.ID, "to=passkey", ip)
	return user, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
