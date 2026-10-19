package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory is a goroutine-safe in-memory Store.
type Memory struct {
	mu        sync.Mutex
	services  map[string]Service
	slugs     map[string]string
	creds     map[string]Credential
	passkeys  map[string]Passkey
	chals     map[string]challenge
	sessions  map[string]Session
	fails     map[string]failCounter
	resources map[string]string // resource -> service id
	clients   map[string]OAuthClient
	authz     map[string]AuthzRequest
	codes     map[string]Code
	refresh   map[string]RefreshToken
	recovery  map[string]RecoveryCode
	users     map[string]User        // svc#id
	idents    map[string]string      // svc#identity -> user id
	upks      map[string]UserPasskey // svc#cred
	seen      map[string]time.Time   // svc#user#ip → expires
	orgs      map[string]Org         // svc#id
	members   map[string]OrgMember   // svc#org#user
	invites   map[string]OrgInvite   // svc#org#email
	notBefore time.Time
	Audit     []AuditEvent
}

type failCounter struct {
	count int
	until time.Time
}

type challenge struct {
	data    []byte
	expires time.Time
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		services: map[string]Service{}, slugs: map[string]string{}, creds: map[string]Credential{},
		passkeys: map[string]Passkey{}, chals: map[string]challenge{}, sessions: map[string]Session{},
		fails: map[string]failCounter{}, resources: map[string]string{}, clients: map[string]OAuthClient{},
		authz: map[string]AuthzRequest{}, codes: map[string]Code{}, refresh: map[string]RefreshToken{},
		recovery: map[string]RecoveryCode{}, users: map[string]User{}, idents: map[string]string{}, upks: map[string]UserPasskey{}, seen: map[string]time.Time{},
		orgs: map[string]Org{}, members: map[string]OrgMember{}, invites: map[string]OrgInvite{},
	}
}

func (m *Memory) CreateService(_ context.Context, s Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.slugs[s.Slug]; taken {
		return ErrConflict
	}
	if _, taken := m.services[s.ID]; taken {
		return ErrConflict
	}
	m.slugs[s.Slug] = s.ID
	m.services[s.ID] = s
	return nil
}

func (m *Memory) GetService(_ context.Context, id string) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return Service{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) ListServices(_ context.Context) ([]Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Service, 0, len(m.services))
	for _, s := range m.services {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (m *Memory) PutCredential(_ context.Context, c Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.creds[c.ID]; taken {
		return ErrConflict
	}
	m.creds[c.ID] = c
	return nil
}

func (m *Memory) GetCredential(_ context.Context, credID string) (Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) ListCredentials(_ context.Context, serviceID string) ([]Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Credential
	for _, c := range m.creds {
		if c.ServiceID == serviceID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) RevokeCredential(_ context.Context, serviceID, credID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[credID]
	if !ok || c.ServiceID != serviceID {
		return ErrNotFound
	}
	if c.RevokedAt == nil {
		c.RevokedAt = &at
		m.creds[credID] = c
	}
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, e AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Audit = append(m.Audit, e)
	return nil
}

func (m *Memory) PutPasskey(_ context.Context, p Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.passkeys[p.ID]; taken {
		return ErrConflict
	}
	m.passkeys[p.ID] = p
	return nil
}

func (m *Memory) UpdatePasskey(_ context.Context, p Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.passkeys[p.ID]; !ok {
		return ErrNotFound
	}
	m.passkeys[p.ID] = p
	return nil
}

func (m *Memory) ListPasskeys(_ context.Context) ([]Passkey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Passkey, 0, len(m.passkeys))
	for _, p := range m.passkeys {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) PutChallenge(_ context.Context, id string, data []byte, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chals[id] = challenge{data: data, expires: expires}
	return nil
}

func (m *Memory) ConsumeChallenge(_ context.Context, id string, now time.Time) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.chals[id]
	delete(m.chals, id)
	if !ok || !now.Before(c.expires) {
		return nil, ErrNotFound
	}
	return c.data, nil
}

func (m *Memory) PutSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.Hash] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, hash string, now time.Time) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok || !now.Before(s.ExpiresAt) {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteSession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}

func (m *Memory) FailureCount(_ context.Context, key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.fails[key]
	if !ok || !now.Before(c.until) {
		return 0, nil
	}
	return c.count, nil
}

func (m *Memory) RecordFailure(_ context.Context, key string, now time.Time, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.fails[key]
	if !ok || !now.Before(c.until) {
		c = failCounter{count: 0, until: now.Add(window)}
	}
	c.count++
	m.fails[key] = c
	return c.count, nil
}

func (m *Memory) AddServiceResource(_ context.Context, serviceID, resource string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceID]
	if !ok {
		return ErrNotFound
	}
	if _, taken := m.resources[resource]; taken {
		return ErrConflict
	}
	m.resources[resource] = serviceID
	svc.Resources = append(svc.Resources, resource)
	m.services[serviceID] = svc
	return nil
}

func (m *Memory) GetServiceByResource(_ context.Context, resource string) (Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.resources[resource]
	if !ok {
		return Service{}, ErrNotFound
	}
	return m.services[id], nil
}

func (m *Memory) CreateOAuthClient(_ context.Context, c OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.clients[c.ID]; taken {
		return ErrConflict
	}
	m.clients[c.ID] = c
	return nil
}

func (m *Memory) GetOAuthClient(_ context.Context, id string) (OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return OAuthClient{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) PutAuthzRequest(_ context.Context, a AuthzRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authz[a.ID] = a
	return nil
}

func (m *Memory) GetAuthzRequest(_ context.Context, id string, now time.Time) (AuthzRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authz[id]
	if !ok || !now.Before(a.ExpiresAt) {
		return AuthzRequest{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) DeleteAuthzRequest(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.authz, id)
	return nil
}

func (m *Memory) CreateCode(_ context.Context, hash string, c Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[hash] = c
	return nil
}

func (m *Memory) ConsumeCode(_ context.Context, hash string, now time.Time) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[hash]
	delete(m.codes, hash)
	if !ok || !now.Before(c.ExpiresAt) {
		return Code{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) CreateRefresh(_ context.Context, t RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[t.Hash] = t
	return nil
}

func (m *Memory) ConsumeRefresh(_ context.Context, hash string, now time.Time) (RefreshToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[hash]
	if !ok || !now.Before(t.ExpiresAt) {
		return RefreshToken{}, false, ErrNotFound
	}
	if t.Used {
		return t, true, nil
	}
	t.Used = true
	m.refresh[hash] = t
	return t, false, nil
}

func (m *Memory) RevokeRefreshFamily(_ context.Context, family string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, t := range m.refresh {
		if t.Family == family {
			delete(m.refresh, h)
		}
	}
	return nil
}

func (m *Memory) ReplaceRecoveryCodes(_ context.Context, hashes []string, created time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recovery = map[string]RecoveryCode{}
	for _, h := range hashes {
		m.recovery[h] = RecoveryCode{Hash: h, CreatedAt: created}
	}
	return nil
}

func (m *Memory) ListRecoveryCodes(_ context.Context) ([]RecoveryCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecoveryCode, 0, len(m.recovery))
	for _, c := range m.recovery {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

func (m *Memory) ConsumeRecoveryCode(_ context.Context, hash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.recovery[hash]
	if !ok || c.UsedAt != nil {
		return ErrNotFound
	}
	c.UsedAt = &now
	m.recovery[hash] = c
	return nil
}

func (m *Memory) ListAudit(_ context.Context, month string, limit int, cursor string) ([]AuditEvent, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []AuditEvent
	for _, e := range m.Audit {
		if e.At.UTC().Format("2006-01") == month {
			all = append(all, e)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].At.After(all[j].At) })
	// cursor is an index encoded as a string for the in-memory store.
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
	}
	if start >= len(all) {
		return []AuditEvent{}, "", nil
	}
	end := min(start+limit, len(all))
	next := ""
	if end < len(all) {
		next = fmt.Sprint(end)
	}
	return all[start:end], next, nil
}

func (m *Memory) GetOwnerNotBefore(_ context.Context) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.notBefore, nil
}

func (m *Memory) SetOwnerNotBefore(_ context.Context, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notBefore = t
	return nil
}

func (m *Memory) TouchSessionVerified(_ context.Context, hash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return ErrNotFound
	}
	s.VerifiedAt = at
	m.sessions[hash] = s
	return nil
}

func (m *Memory) UpdateServicePermissions(_ context.Context, serviceID string, scopes []string, roles map[string][]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceID]
	if !ok {
		return ErrNotFound
	}
	svc.Scopes = append([]string(nil), scopes...)
	svc.Roles = map[string][]string{}
	for k, v := range roles {
		svc.Roles[k] = append([]string(nil), v...)
	}
	m.services[serviceID] = svc
	return nil
}

func (m *Memory) UpdateServiceLogin(_ context.Context, serviceID, loginURL, rpID string, origins, defaultRoles []string, openSignup bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceID]
	if !ok {
		return ErrNotFound
	}
	svc.LoginURL, svc.RPID = loginURL, rpID
	svc.Origins = append([]string(nil), origins...)
	svc.DefaultRoles = append([]string(nil), defaultRoles...)
	svc.OpenSignup = openSignup
	m.services[serviceID] = svc
	return nil
}

func ukey(svc, id string) string { return svc + "#" + id }

func (m *Memory) CreateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.idents[ukey(u.ServiceID, u.Identity)]; taken {
		return ErrConflict
	}
	if _, taken := m.users[ukey(u.ServiceID, u.ID)]; taken {
		return ErrConflict
	}
	m.idents[ukey(u.ServiceID, u.Identity)] = u.ID
	m.users[ukey(u.ServiceID, u.ID)] = u
	return nil
}

func (m *Memory) GetUser(_ context.Context, serviceID, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[ukey(serviceID, id)]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) GetUserByIdentity(_ context.Context, serviceID, identity string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.idents[ukey(serviceID, identity)]
	if !ok {
		return User{}, ErrNotFound
	}
	return m.users[ukey(serviceID, id)], nil
}

func (m *Memory) ListUsers(_ context.Context, serviceID string, limit int, cursor string) ([]User, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []User
	for _, u := range m.users {
		if u.ServiceID == serviceID {
			all = append(all, u)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID < all[j].ID
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
	}
	if start >= len(all) {
		return []User{}, "", nil
	}
	end := min(start+limit, len(all))
	next := ""
	if end < len(all) {
		next = fmt.Sprint(end)
	}
	return all[start:end], next, nil
}

func (m *Memory) UpdateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.users[ukey(u.ServiceID, u.ID)]
	if !ok {
		return ErrNotFound
	}
	cur.Email, cur.Name, cur.Status, cur.NotBefore, cur.EmailVerified, cur.LastLoginAt = u.Email, u.Name, u.Status, u.NotBefore, u.EmailVerified, u.LastLoginAt
	cur.Method, cur.Username, cur.PasswordHash = u.Method, u.Username, u.PasswordHash
	cur.Roles = append([]string(nil), u.Roles...)
	m.users[ukey(u.ServiceID, u.ID)] = cur
	return nil
}

func (m *Memory) RebindUserIdentity(_ context.Context, serviceID, userID, oldIdentity, newIdentity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.users[ukey(serviceID, userID)]
	if !ok || cur.Identity != oldIdentity || m.idents[ukey(serviceID, oldIdentity)] != userID {
		return ErrNotFound
	}
	if _, taken := m.idents[ukey(serviceID, newIdentity)]; taken {
		return ErrConflict
	}
	delete(m.idents, ukey(serviceID, oldIdentity))
	m.idents[ukey(serviceID, newIdentity)] = userID
	cur.Identity = newIdentity
	m.users[ukey(serviceID, userID)] = cur
	return nil
}

func (m *Memory) TouchSeenIP(_ context.Context, serviceID, userID, ip string, now time.Time, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ukey(serviceID, userID) + "#" + ip
	exp, ok := m.seen[k]
	m.seen[k] = now.Add(ttl)
	return ok && now.Before(exp), nil
}

func (m *Memory) PutUserPasskey(_ context.Context, p UserPasskey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.upks[ukey(p.ServiceID, p.ID)]; taken {
		return ErrConflict
	}
	m.upks[ukey(p.ServiceID, p.ID)] = p
	return nil
}

func (m *Memory) UpdateUserPasskey(_ context.Context, p UserPasskey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.upks[ukey(p.ServiceID, p.ID)]; !ok {
		return ErrNotFound
	}
	m.upks[ukey(p.ServiceID, p.ID)] = p
	return nil
}

func (m *Memory) ListUserPasskeys(_ context.Context, serviceID, userID string) ([]UserPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []UserPasskey
	for _, p := range m.upks {
		if p.ServiceID == serviceID && p.UserID == userID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) GetUserPasskeyByCred(_ context.Context, serviceID, credID string) (UserPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.upks[ukey(serviceID, credID)]
	if !ok {
		return UserPasskey{}, ErrNotFound
	}
	return p, nil
}

func (m *Memory) DeleteUserPasskey(_ context.Context, serviceID, userID, credID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.upks[ukey(serviceID, credID)]
	if !ok || p.UserID != userID {
		return ErrNotFound
	}
	delete(m.upks, ukey(serviceID, credID))
	return nil
}

func (m *Memory) DeleteUser(_ context.Context, serviceID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[ukey(serviceID, id)]
	if !ok {
		return ErrNotFound
	}
	delete(m.users, ukey(serviceID, id))
	delete(m.idents, ukey(serviceID, u.Identity))
	for k, p := range m.upks {
		if p.ServiceID == serviceID && p.UserID == id {
			delete(m.upks, k)
		}
	}
	for k := range m.seen {
		if strings.HasPrefix(k, ukey(serviceID, id)+"#") {
			delete(m.seen, k)
		}
	}
	for k, mb := range m.members {
		if mb.ServiceID == serviceID && mb.UserID == id {
			delete(m.members, k)
		}
	}
	return nil
}

// ── orgs ───────────────────────────────────────────────────────────────────

func mkey(serviceID, orgID, userID string) string { return serviceID + "#" + orgID + "#" + userID }

func (m *Memory) CreateOrg(_ context.Context, o Org) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.orgs[ukey(o.ServiceID, o.ID)]; taken {
		return ErrConflict
	}
	m.orgs[ukey(o.ServiceID, o.ID)] = o
	return nil
}

func (m *Memory) GetOrg(_ context.Context, serviceID, id string) (Org, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.orgs[ukey(serviceID, id)]
	if !ok {
		return Org{}, ErrNotFound
	}
	return o, nil
}

func (m *Memory) ListOrgs(_ context.Context, serviceID string, limit int, cursor string) ([]Org, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Org
	for _, o := range m.orgs {
		if o.ServiceID == serviceID {
			all = append(all, o)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID < all[j].ID
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			return nil, "", fmt.Errorf("store: bad cursor %q", cursor)
		}
	}
	if start >= len(all) {
		return []Org{}, "", nil
	}
	end := min(start+limit, len(all))
	next := ""
	if end < len(all) {
		next = fmt.Sprint(end)
	}
	return all[start:end], next, nil
}

func (m *Memory) UpdateOrg(_ context.Context, o Org) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.orgs[ukey(o.ServiceID, o.ID)]
	if !ok {
		return ErrNotFound
	}
	cur.Name, cur.Status = o.Name, o.Status
	m.orgs[ukey(o.ServiceID, o.ID)] = cur
	return nil
}

func (m *Memory) DeleteOrg(_ context.Context, serviceID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orgs[ukey(serviceID, id)]; !ok {
		return ErrNotFound
	}
	delete(m.orgs, ukey(serviceID, id))
	for k, mb := range m.members {
		if mb.ServiceID == serviceID && mb.OrgID == id {
			delete(m.members, k)
		}
	}
	for k, inv := range m.invites {
		if inv.ServiceID == serviceID && inv.OrgID == id {
			delete(m.invites, k)
		}
	}
	return nil
}

func (m *Memory) PutOrgMember(_ context.Context, mb OrgMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mkey(mb.ServiceID, mb.OrgID, mb.UserID)
	if cur, ok := m.members[k]; ok {
		mb.CreatedAt = cur.CreatedAt
	}
	m.members[k] = mb
	return nil
}

func (m *Memory) GetOrgMember(_ context.Context, serviceID, orgID, userID string) (OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb, ok := m.members[mkey(serviceID, orgID, userID)]
	if !ok {
		return OrgMember{}, ErrNotFound
	}
	return mb, nil
}

func (m *Memory) ListOrgMembers(_ context.Context, serviceID, orgID string) ([]OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OrgMember{}
	for _, mb := range m.members {
		if mb.ServiceID == serviceID && mb.OrgID == orgID {
			out = append(out, mb)
		}
	}
	sortMembers(out)
	return out, nil
}

func (m *Memory) ListUserOrgs(_ context.Context, serviceID, userID string) ([]OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OrgMember{}
	for _, mb := range m.members {
		if mb.ServiceID == serviceID && mb.UserID == userID {
			out = append(out, mb)
		}
	}
	sortMembers(out)
	return out, nil
}

func sortMembers(out []OrgMember) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].OrgID+out[i].UserID < out[j].OrgID+out[j].UserID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
}

func (m *Memory) DeleteOrgMember(_ context.Context, serviceID, orgID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mkey(serviceID, orgID, userID)
	if _, ok := m.members[k]; !ok {
		return ErrNotFound
	}
	delete(m.members, k)
	return nil
}

// ── org invites ────────────────────────────────────────────────────────────

func (m *Memory) PutOrgInvite(_ context.Context, inv OrgInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[mkey(inv.ServiceID, inv.OrgID, inv.Email)] = inv
	return nil
}

func (m *Memory) GetOrgInvite(_ context.Context, serviceID, orgID, email string) (OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[mkey(serviceID, orgID, email)]
	if !ok {
		return OrgInvite{}, ErrNotFound
	}
	return inv, nil
}

func (m *Memory) ListOrgInvites(_ context.Context, serviceID, orgID string) ([]OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OrgInvite{}
	for _, inv := range m.invites {
		if inv.ServiceID == serviceID && inv.OrgID == orgID {
			out = append(out, inv)
		}
	}
	sortInvites(out)
	return out, nil
}

func (m *Memory) ListEmailInvites(_ context.Context, serviceID, email string) ([]OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OrgInvite{}
	for _, inv := range m.invites {
		if inv.ServiceID == serviceID && inv.Email == email {
			out = append(out, inv)
		}
	}
	sortInvites(out)
	return out, nil
}

func sortInvites(out []OrgInvite) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].OrgID+out[i].Email < out[j].OrgID+out[j].Email
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
}

func (m *Memory) DeleteOrgInvite(_ context.Context, serviceID, orgID, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mkey(serviceID, orgID, email)
	if _, ok := m.invites[k]; !ok {
		return ErrNotFound
	}
	delete(m.invites, k)
	return nil
}
