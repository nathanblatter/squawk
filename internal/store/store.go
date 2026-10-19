// Package store is the persistence boundary. One interface, two
// implementations: DynamoDB for real and an in-memory map for tests and
// `make dev` without Docker.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Service is a registered product. It is also the tenant for its users.
type Service struct {
	ID        string
	Slug      string
	Name      string
	Status    string // active | disabled
	CreatedAt time.Time
	// Resources are the RFC 8707 resource identifiers (e.g. an MCP URL) that
	// map an OAuth authorization request to this service.
	Resources []string
	// Scopes is the service's permission catalog; tokens may only carry
	// scopes from it. Roles are named bundles of those scopes.
	Scopes []string
	Roles  map[string][]string
	// User-pool configuration (slice 3). LoginURL empty = owner-only service.
	LoginURL     string
	RPID         string
	Origins      []string
	DefaultRoles []string
	// OpenSignup lets anyone create an account (Google first sign-in, the
	// app's POST /v1/users). False = invite-only: accounts come from the owner.
	OpenSignup bool
}

// User is an end user of one service. Method is fixed for life (no linking).
type User struct {
	ID        string
	ServiceID string
	Method    string // passkey | google
	Identity  string // "google:<sub>" or "email:<email>"; unique per service
	Email     string
	Name      string
	Roles     []string
	Status    string // active | disabled
	CreatedAt time.Time
	NotBefore time.Time // sessions/refresh tokens issued before this are dead
	// EmailVerified: the address was proven (Google, email code, or the owner).
	// App-created passkey accounts start false and cannot sign in until verified.
	EmailVerified bool
	// LastLoginAt is the most recent successful sign-in; zero until the first.
	LastLoginAt time.Time
}

// Org is a team / organisation inside one service (auth-service-15): a
// customer account with several members. Orgs never span services.
type Org struct {
	ID        string
	ServiceID string
	Name      string
	Status    string // active | disabled
	CreatedAt time.Time
}

// OrgMember is one user's membership of one org, with an org-level role
// (admin | member) layered on the user's service roles.
type OrgMember struct {
	ServiceID string
	OrgID     string
	UserID    string
	Role      string
	CreatedAt time.Time
}

// OrgInvite is a pending, emailed invitation into an org (auth-service-32).
// Keyed by (org, address): re-inviting the same address replaces the row.
// Claimed (deleted) when a user with that verified address signs in.
type OrgInvite struct {
	ServiceID string
	OrgID     string
	Email     string // normalised (lower-case)
	Role      string // admin | member
	InvitedBy string // user id of the inviter, may be empty
	CreatedAt time.Time
	ExpiresAt time.Time
}

// UserPasskey is a WebAuthn credential of an end user (Data = webauthn.Credential JSON).
type UserPasskey struct {
	ServiceID string
	UserID    string
	ID        string // base64url credential id
	Name      string
	CreatedAt time.Time
	Data      []byte
}

// Credential is a hashed service credential.
type Credential struct {
	ID        string
	ServiceID string
	Hash      string // hex SHA-256 of the full raw credential
	Last4     string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// Revoked reports whether the credential is no longer usable.
func (c Credential) Revoked() bool { return c.RevokedAt != nil }

// AuditEvent is one security-relevant action.
type AuditEvent struct {
	At        time.Time
	Kind      string // service.create | credential.mint | credential.revoke | token.issue | token.denied
	Actor     string // admin | svc:<id> | anonymous
	ServiceID string
	Detail    string
	IP        string
}

// Passkey is one WebAuthn credential belonging to the owner. Data is the
// JSON-encoded webauthn.Credential; the store treats it as opaque.
type Passkey struct {
	ID        string // base64url credential id
	Name      string
	CreatedAt time.Time
	Data      []byte
}

// Session is an owner console session. Only the SHA-256 of the cookie value
// is stored.
type Session struct {
	Hash      string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	// Method is how the session was opened: "passkey" (default) or "recovery".
	Method string
	// VerifiedAt is the last passkey assertion on this session (login or
	// step-up). Sensitive actions require it to be recent.
	VerifiedAt time.Time
}

// RecoveryCode is one offline recovery code, stored hashed.
type RecoveryCode struct {
	Hash      string
	CreatedAt time.Time
	UsedAt    *time.Time
}

// OAuthClient is a dynamically registered OAuth client (RFC 7591).
type OAuthClient struct {
	ID           string
	Name         string
	SecretHash   string // empty for public clients
	AuthMethod   string // none | client_secret_post | client_secret_basic
	RedirectURIs []string
	CreatedAt    time.Time
}

// AuthzRequest is a pending authorization awaiting the owner's approval.
type AuthzRequest struct {
	ID          string
	ClientID    string
	RedirectURI string
	State       string
	Scope       string
	Challenge   string // PKCE S256
	Resource    string
	ServiceID   string
	// Org is the org context the app asked for (optional); membership is
	// checked when the user signs in.
	Org       string
	ExpiresAt time.Time
}

// Code is a one-time authorization code (stored under its hash).
type Code struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Scope       string
	Subject     string
	ServiceID   string
	Org         string // org context carried into the tokens (optional)
	OrgRole     string
	ExpiresAt   time.Time
}

// RefreshToken is one member of a rotating family (stored under its hash).
type RefreshToken struct {
	Hash      string
	Family    string
	ClientID  string
	ServiceID string
	Subject   string
	Scope     string
	Org       string // org context; re-resolved against the membership on refresh
	OrgRole   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Used      bool
}

// Store is everything the core needs from persistence.
type Store interface {
	CreateService(ctx context.Context, s Service) error // ErrConflict when the slug is taken
	GetService(ctx context.Context, id string) (Service, error)
	ListServices(ctx context.Context) ([]Service, error)

	AddServiceResource(ctx context.Context, serviceID, resource string) error                                                        // ErrConflict when taken
	UpdateServicePermissions(ctx context.Context, serviceID string, scopes []string, roles map[string][]string) error                // ErrNotFound
	UpdateServiceLogin(ctx context.Context, serviceID, loginURL, rpID string, origins, defaultRoles []string, openSignup bool) error // ErrNotFound

	// End users (slice 3).
	CreateUser(ctx context.Context, u User) error // ErrConflict when the identity is taken
	GetUser(ctx context.Context, serviceID, id string) (User, error)
	GetUserByIdentity(ctx context.Context, serviceID, identity string) (User, error)
	ListUsers(ctx context.Context, serviceID string, limit int, cursor string) (users []User, next string, err error)
	UpdateUser(ctx context.Context, u User) error // ErrNotFound; replaces Email, Name, Roles, Status, NotBefore, EmailVerified, LastLoginAt
	// TouchSeenIP records that the user signed in from ip and reports whether
	// that ip was already on record (within ttl of its last sighting).
	TouchSeenIP(ctx context.Context, serviceID, userID, ip string, now time.Time, ttl time.Duration) (known bool, err error)
	// RebindUserIdentity moves a user's identity lock (e.g. a pre-provisioned
	// google-pending:<email> onto the real google:<sub>). ErrNotFound when the
	// user or old lock is missing; ErrConflict when the new identity is taken.
	RebindUserIdentity(ctx context.Context, serviceID, userID, oldIdentity, newIdentity string) error
	DeleteUser(ctx context.Context, serviceID, id string) error // removes the user, its identity lock, passkeys and org memberships; ErrNotFound

	// Orgs (auth-service-15). Members are keyed by (org, user); PutOrgMember
	// upserts (changing the role keeps created_at).
	CreateOrg(ctx context.Context, o Org) error // ErrConflict when the id exists
	GetOrg(ctx context.Context, serviceID, id string) (Org, error)
	ListOrgs(ctx context.Context, serviceID string, limit int, cursor string) (orgs []Org, next string, err error)
	UpdateOrg(ctx context.Context, o Org) error                // ErrNotFound; replaces Name, Status
	DeleteOrg(ctx context.Context, serviceID, id string) error // removes the org, its memberships and invites; ErrNotFound
	PutOrgMember(ctx context.Context, m OrgMember) error
	GetOrgMember(ctx context.Context, serviceID, orgID, userID string) (OrgMember, error)
	ListOrgMembers(ctx context.Context, serviceID, orgID string) ([]OrgMember, error) // oldest first
	ListUserOrgs(ctx context.Context, serviceID, userID string) ([]OrgMember, error)  // the user's memberships
	DeleteOrgMember(ctx context.Context, serviceID, orgID, userID string) error       // ErrNotFound
	// Org invites (auth-service-32). Stores may hand back expired rows
	// (DynamoDB reaps them through the table TTL within ~48h); callers
	// check ExpiresAt.
	PutOrgInvite(ctx context.Context, inv OrgInvite) error // upsert by (org, email)
	GetOrgInvite(ctx context.Context, serviceID, orgID, email string) (OrgInvite, error)
	ListOrgInvites(ctx context.Context, serviceID, orgID string) ([]OrgInvite, error)   // oldest first
	ListEmailInvites(ctx context.Context, serviceID, email string) ([]OrgInvite, error) // pending for one address
	DeleteOrgInvite(ctx context.Context, serviceID, orgID, email string) error          // ErrNotFound
	PutUserPasskey(ctx context.Context, p UserPasskey) error
	UpdateUserPasskey(ctx context.Context, p UserPasskey) error
	ListUserPasskeys(ctx context.Context, serviceID, userID string) ([]UserPasskey, error)
	GetUserPasskeyByCred(ctx context.Context, serviceID, credID string) (UserPasskey, error)
	GetServiceByResource(ctx context.Context, resource string) (Service, error)

	PutCredential(ctx context.Context, c Credential) error
	GetCredential(ctx context.Context, credID string) (Credential, error)
	ListCredentials(ctx context.Context, serviceID string) ([]Credential, error)
	RevokeCredential(ctx context.Context, serviceID, credID string, at time.Time) error

	AppendAudit(ctx context.Context, e AuditEvent) error
	// ListAudit returns one month's events, newest first. cursor is the SK to
	// continue after ("" starts at the newest); next is "" when exhausted.
	ListAudit(ctx context.Context, month string, limit int, cursor string) (events []AuditEvent, next string, err error)

	// Owner passkeys (single owner; see docs/DESIGN.md).
	PutPasskey(ctx context.Context, p Passkey) error // ErrConflict when the id exists
	UpdatePasskey(ctx context.Context, p Passkey) error
	ListPasskeys(ctx context.Context) ([]Passkey, error)

	// WebAuthn ceremony state, keyed by a random id, single use, short lived.
	PutChallenge(ctx context.Context, id string, data []byte, expires time.Time) error
	ConsumeChallenge(ctx context.Context, id string, now time.Time) ([]byte, error) // ErrNotFound when missing or expired

	// Failure counters for brute-force protection. A counter is a key plus a
	// window; failures outside the current window are forgotten.
	FailureCount(ctx context.Context, key string, now time.Time) (int, error)
	RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration) (int, error)

	PutSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, hash string, now time.Time) (Session, error) // ErrNotFound when missing or expired
	DeleteSession(ctx context.Context, hash string) error
	TouchSessionVerified(ctx context.Context, hash string, at time.Time) error // ErrNotFound when missing

	// Owner "log out everywhere": sessions and refresh tokens created before
	// this instant are dead. Zero time means never set.
	GetOwnerNotBefore(ctx context.Context) (time.Time, error)
	SetOwnerNotBefore(ctx context.Context, t time.Time) error

	// Recovery codes: ReplaceRecoveryCodes wipes any existing set.
	ReplaceRecoveryCodes(ctx context.Context, hashes []string, created time.Time) error
	ListRecoveryCodes(ctx context.Context) ([]RecoveryCode, error)
	ConsumeRecoveryCode(ctx context.Context, hash string, now time.Time) error // ErrNotFound when missing or used

	// OAuth 2.1 for connectors.
	CreateOAuthClient(ctx context.Context, c OAuthClient) error
	GetOAuthClient(ctx context.Context, id string) (OAuthClient, error)
	PutAuthzRequest(ctx context.Context, a AuthzRequest) error
	GetAuthzRequest(ctx context.Context, id string, now time.Time) (AuthzRequest, error) // ErrNotFound when missing or expired
	DeleteAuthzRequest(ctx context.Context, id string) error
	CreateCode(ctx context.Context, hash string, c Code) error
	ConsumeCode(ctx context.Context, hash string, now time.Time) (Code, error) // single use; ErrNotFound when missing, used or expired
	CreateRefresh(ctx context.Context, t RefreshToken) error
	// ConsumeRefresh marks the token used. reused is true when it had already
	// been used (replay), in which case the token is still returned so the
	// caller can revoke its family.
	ConsumeRefresh(ctx context.Context, hash string, now time.Time) (t RefreshToken, reused bool, err error)
	RevokeRefreshFamily(ctx context.Context, family string) error
}
