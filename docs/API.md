# Squawk API reference

Base URL: `https://squawk.nathanblatter.com`. All responses are JSON. Times are RFC 3339 UTC.
Every secret is shown exactly once at creation and stored only as a SHA-256 hash.

## Concepts

| Term | What it is |
|---|---|
| **Service** | A registered product (FinForge, Flightdeck, …). Has a `slug`, an `id` (`svc_…`), and zero or more **resources**: the URLs (RFC 8707 resource identifiers, e.g. an MCP endpoint) that connector tokens for this service are issued for. |
| **Service credential** | A long-lived secret (`nbk_<id>_<secret>`) a service's backend holds. Exchanged for **service tokens**. Minted and revoked in the admin console; listed by its last four characters. |
| **Service token** | 15-minute ES256 JWT with `sub=svc:<id>`, `aud=auth`. Authenticates a service to this API. |
| **Connector token** | 1-hour ES256 JWT issued through the OAuth 2.1 flow with `sub=owner`, `aud=<service id>`, plus a 30-day rotating refresh token. What Claude presents to your `/mcp`. |
| **Owner** | Nathan. Signs into the admin console with a passkey. Approves connectors. |

## Authentication models

| Model | Header | Used by |
|---|---|---|
| Service token | `Authorization: Bearer <jwt>` | service backends calling `/v1/*` |
| Connector token | `Authorization: Bearer <jwt>` | Claude (or any OAuth client) calling **your** API, verified by you via JWKS |
| Admin session | cookie `auth_admin_session` (HttpOnly, Secure, SameSite=Strict, `Path=/admin`) | the console. Writes also require `Origin: https://squawk.nathanblatter.com` |
| Admin bearer | `Authorization: Bearer <admin token>` | break-glass / bootstrap only |

Admin endpoints marked **fresh** additionally require that the passkey was used in the last
5 minutes; otherwise they return `401 {"error":"step_up_required"}` and the console re-runs
Face ID (`/admin/step-up/*`). Connector approval refuses the admin bearer outright.

## Errors

Admin and `/v1` endpoints: `{"error":"<code>","detail":"<optional>"}`.
OAuth endpoints: RFC 6749 shape `{"error":"<code>","error_description":"<optional>"}`.

| Status | Codes |
|---|---|
| 400 | `invalid_request`, `invalid_client_metadata`, `invalid_redirect_uri`, `unsupported_grant_type`, `invalid_grant`, `invalid_target` |
| 401 | `unauthorized`, `invalid_token`, `invalid_client`, `passkey_required`, `step_up_required`, `passkey_rejected`, `recovery_code_rejected` |
| 403 | `unauthorized_client` (service disabled) |
| 404 | `not_found` |
| 409 | `slug_taken`, `resource_taken`, `setup_required` |
| 429 | `too_many_attempts` with `Retry-After` seconds |
| 500 | `server_error` |

## Brute-force limits

Failures, never successes, are counted. 30 failed token exchanges per IP per 10 min; 10 per
service id per 15 min (locks that service's token endpoint); 20 failed passkey or recovery
attempts per IP per 10 min; 20 client registrations per IP per 10 min. API Gateway also caps
raw volume at 50 requests/s.

---

## Discovery and keys

### `GET /health`
`200 {"status":"ok","version":"<git sha>","keys":1}`

### `GET /.well-known/jwks.json`
Public signing keys. Cache by `kid`. Several keys appear during rotation; all are valid.
```json
{"keys":[{"kty":"EC","crv":"P-256","kid":"6be31935-…","use":"sig","alg":"ES256","x":"…","y":"…"}]}
```

### `GET /.well-known/openid-configuration`
### `GET /.well-known/oauth-authorization-server[/…]`
RFC 8414 metadata: `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`,
`jwks_uri`, `response_types_supported: ["code"]`, `grant_types_supported`,
`code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported`,
`resource_parameter_supported: true`.

---

## Tokens

### `POST /v1/token` (alias `POST /oauth/token`)
`Content-Type: application/x-www-form-urlencoded`. Client credentials go in the form
(`client_id`, `client_secret`) or in HTTP Basic auth.

**Service token** — `grant_type=client_credentials`
```
client_id=svc_…  client_secret=nbk_…
→ 200 {"access_token":"<jwt>","token_type":"Bearer","expires_in":900,"scope":"service"}
```

**Connector code exchange** — `grant_type=authorization_code`
```
client_id=nbc_…  [client_secret=nbcs_…]  code=nbac_…  code_verifier=<43-128 chars>  [redirect_uri=…]
→ 200 {"access_token":"<jwt>","token_type":"Bearer","expires_in":3600,"refresh_token":"nbrt_…","scope":"…"}
```

**Connector refresh** — `grant_type=refresh_token`
```
client_id=nbc_…  [client_secret=nbcs_…]  refresh_token=nbrt_…
→ 200 same shape, with a NEW refresh_token
```
Refresh tokens rotate on every use. Presenting an already-used one revokes the whole family
(`invalid_grant`). After the owner "signs out everywhere", refresh tokens issued earlier are
refused (`invalid_grant`, "reconnect").

### `GET /v1/me`
Service token required. `200 {"service_id":"svc_…","scope":"service","expires_at":<unix>}`.

### Token format
Header `{"alg":"ES256","typ":"at+jwt","kid":"<key id>"}`. Claims:

| Claim | Service token | Connector token |
|---|---|---|
| `iss` | `https://squawk.nathanblatter.com` | same |
| `sub` | `svc:<service id>` | `owner` |
| `aud` | `auth` | `<service id>` |
| `scope` | `service` | requested scopes, space-separated |
| `client_id` | — | `nbc_…` |
| `email`, `email_verified` | — | user tokens only |
| `preferred_username` | user tokens of password (or converted) accounts: the username; such accounts may have no `email` |
| `org`, `org_role` | — | only when an org context was requested: org id and `admin\|member` |
| `iat`, `exp`, `jti` | yes | yes |

### Verifying a token (what your service does)
1. Fetch JWKS once; pick the key by `kid`; refresh JWKS when you meet an unknown `kid`.
2. Verify the ES256 signature over `header.payload` (raw `r||s`, 64 bytes).
3. Check `exp > now`, `iss`, and `aud == your service id`.
4. Authorize on `scope`.
The Go client does all of this: `client.NewVerifier(issuer, serviceID)` + `client.RequireToken`.

---

## Connector OAuth 2.1 (how Claude connects to your product)

1. Your product serves `GET /.well-known/oauth-protected-resource/<path>` naming this issuer
   (`client.ProtectedResourceMetadata`), and answers unauthenticated requests with
   `WWW-Authenticate: Bearer resource_metadata="…"`.
2. The client registers: **`POST /oauth/register`** (RFC 7591), JSON body
   `redirect_uris` (1–10, https; http only for localhost), `client_name`,
   `token_endpoint_auth_method` (`none` | `client_secret_post` | `client_secret_basic`, default basic),
   `grant_types` ⊆ {`authorization_code`,`refresh_token`}, `response_types` ⊆ {`code`}.
   `201 {"client_id":"nbc_…","client_secret":"nbcs_…"?,"client_id_issued_at":…,"redirect_uris":[…],"token_endpoint_auth_method":"…","grant_types":[…],"response_types":["code"]}`
3. The client opens **`GET /oauth/authorize`** with
   `response_type=code`, `client_id`, `redirect_uri` (must be registered), `state`,
   `scope` (⊆ the service's scope catalog, else `invalid_scope`; empty = whole catalog),
   `code_challenge`, `code_challenge_method=S256`, and **`resource`** (required;
   must equal a resource registered on a service). Unknown client or unregistered redirect →
   `400`, no redirect. Other problems → `302` back to `redirect_uri` with `error`.
   Otherwise `302` to the console, where the owner approves with a passkey.
4. The console redirects the browser to `redirect_uri?code=nbac_…&state=…`
   (or `error=access_denied`). Codes live 5 minutes and are single use.
5. Exchange and refresh at `/oauth/token` as above.

---

## End users (slice 3)

A **user-pool** service (one with a `login_url`) has its own users. All `/v1/users*` and
`/v1/login/passkey/*` calls need the service's **service token**; users are always scoped to
the calling service. A user has one method for life: `passkey` (created via `POST /v1/users`),
`google` (created on first Google sign-in), `email` (a 6-digit code mailed on each sign-in,
account created on the first correct code) or `password` (owner-provisioned only: a username
and a bcrypt hash, made for moving an existing product's users over). No linking: the same
address may own one account per method.

**Password accounts** are keyed by `username` (case-insensitive, no spaces) and may have no
email at all (pseudonymous study participants). They are born `email_verified` (the owner
vouches), never receive codes or alerts, and their tokens carry `preferred_username` instead
of, or as well as, `email`. The owner creates them with a plaintext password (hashed here,
bcrypt cost 12) or an existing bcrypt `password_hash` copied from the old system; on an open
pool the app may create them too (`POST /v1/users`, method `password`). Registering a passkey **converts** the account: the method becomes `passkey` and the
hash is deleted. Setting a new password (`POST /v1/users/{id}/password`, or the admin call)
converts it back and removes the passkeys. Ten wrong passwords lock the username for 15
minutes, from any address.

**Email verification.** `user.email_verified` is true for Google, email-code and
owner-provisioned accounts. An app-created passkey account starts `false` and **cannot sign
in** (`403 email_unverified` from passkey finish) until the person enters the code from
`POST /v1/users/{id}/email/verify/begin`. User tokens carry `email_verified`.

**New-sign-in alerts.** When a user signs in from an address not seen on that account in the
last 90 days (and it is not the account's very first sign-in), Squawk emails them: service,
method, time, IP, and what to do if it wasn't them. At most 3 alerts per account per day
(`user.login.alerted` / `user.login.alert_suppressed` in the audit log). Nothing to configure;
it needs the mail outbox.

Email endpoints answer `404 email_disabled` on a server without a mail outbox
(`AUTH_MAIL_QUEUE_URL`). Codes: 6 digits, 10 minutes, 5 attempts, single use; sends are capped
at 5 per address and 20 per IP per 15 minutes (`429`).

**Who may create accounts** is the service's `open_signup` flag (default `false`):

| `open_signup` | `POST /v1/users` (the app) | Unknown Google identity | Owner (`POST /admin/services/{id}/users`) |
|---|---|---|---|
| `true` (public, e.g. the games) | creates the account | creates the account | always works |
| `false` (invite-only, e.g. the personal site) | `403 signup_closed` | sent back to `login_url?error=signup_closed` | always works |

An owner-provisioned `google` account is bound to the real Google subject the first time
that person signs in with a verified matching email; until then it cannot log in. Both
refusals are audited as `user.signup_denied`.

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/users` | `{"email","name"?}` → `201 user` (method `passkey`, roles = service `default_roles`). `409 identity_taken`, `403 signup_closed`. With `{"method":"password","username","password","name"?,"email"?,"roles"?}` the app creates a password account (its own sign-up form, e.g. a study participant joining by invite link); same `signup_closed` rule, roles must exist on the service |
| GET | `/v1/users?limit=50&cursor=` | `{"users":[user],"next"}` |
| GET | `/v1/users/{id}` | `user` |
| PATCH | `/v1/users/{id}` | any of `{"roles":[…],"status":"active|disabled","name"}`; roles must exist on the service |
| POST | `/v1/users/{id}/logout-everywhere` | `204`; refresh tokens issued earlier are refused |
| GET | `/v1/users/{id}/export` | data-portability JSON: `{"exported_at","user","passkeys":[meta],"audit":[events naming the user, this month and last]}` |
| DELETE | `/v1/users/{id}` | `204`; permanent. Removes the account, identity and passkeys; refresh tokens stop working. Your app owns the confirmation step |
| GET | `/v1/users/{id}/passkeys` | `{"passkeys":[{"id","name","created_at"}]}` |
| POST | `/v1/users/{id}/passkeys/begin` | `{"challenge_id","options"}` WebAuthn creation options bound to the service's `rp_id`/`origins` |
| POST | `/v1/users/{id}/passkeys/finish?challenge=&name=` | body: the browser's credential JSON → `201 {"id","name","user_id","created_at","redirect_to"?}` (`redirect_to` only after a passkey activation) |
| POST | `/v1/login/passkey/begin` | `{"login_challenge"}` → `{"challenge_id","options"}` (usernameless) |
| POST | `/v1/login/passkey/finish?challenge=` | body: credential JSON → `{"redirect_to","user"}`; send the browser to `redirect_to`. `403 email_unverified` until the account verified its email |
| POST | `/v1/login/owner/begin` | `{"login_challenge"}` → `{"challenge_id","options"}`: assertion options for the **owner's** passkeys (RP ID = the issuer's parent domain, accepted from the service's `origins`). `409 setup_required` when the owner has no passkey, `409 service_not_configured` without `origins` |
| POST | `/v1/login/owner/finish?challenge=` | body: credential JSON → `{"redirect_to","subject":"owner"}`. `401 passkey_rejected`. The token minted from the code has `sub=owner` and the request's full scope |
| POST | `/v1/login/passkey/activate/begin` | `{"login_challenge","email"}` → `{"challenge_id","expires_in"}`; mails a code to the **passkey** account created with that address (owner-provisioned, or an app sign-up on a new device). `404 not_found` on an open pool when no such account, `403 signup_closed` on an invite-only one |
| POST | `/v1/login/passkey/activate/finish?challenge=` | `{"code"}` → `{"challenge_id","options","user"}`: WebAuthn **creation** options (the code also marks the email verified). Run `navigator.credentials.create`, then `POST /v1/users/{user.id}/passkeys/finish?challenge=&name=`, whose `201` carries `redirect_to` because the challenge completes the parked sign-in |
| POST | `/v1/login/password` | `{"login_challenge","username","password"}` → `{"redirect_to","user"}`. `401 password_rejected` (unknown name or wrong password, deliberately the same), `400 invalid_request` for an account that uses another method, `403 account_disabled`, `429` after 10 wrong passwords on one username or 20 failures from one IP |
| POST | `/v1/users/{id}/password` | `{"password"}` or `{"password_hash"}` (bcrypt) → `200 user`; your app's own reset flow. Converts a passkey-upgraded account back to `password` and removes its passkeys. `400` without a username |
| POST | `/v1/login/email/begin` | `{"login_challenge","email"}` → `{"challenge_id","expires_in":600}`; a code is mailed. `403 signup_closed` for an unknown address on an invite-only pool, `403 account_disabled`, `429` |
| POST | `/v1/login/email/finish?challenge=` | `{"code":"123456"}` → `{"redirect_to","user"}`. `401 code_rejected` (wrong, expired, used, or out of attempts: request a new one) |
| POST | `/v1/users/{id}/email/verify/begin` | → `{"challenge_id","expires_in"}`; mails a verification code. `409 already_verified` |
| POST | `/v1/users/{id}/email/verify/finish?challenge=` | `{"code"}` → `200 user` with `email_verified: true`. `401 code_rejected` |
| GET | `/v1/login/google/start?login_challenge=` | browser endpoint, no auth; `302` to Google (404 `google_disabled` when not configured) |
| GET | `/v1/login/google/callback` | Google returns here; `302` to the app's `redirect_uri` with `code`, or back to `login_url?login_challenge=&error=` |

`user` = `{"id":"usr_…","service_id","method","email","email_verified","name","roles":[…],"status","created_at","last_login_at"?,"username"?}`.
The password hash is never returned.

### Teams and organisations

An **org** is a customer account inside one service with several members (a therapy
practice, a company). Orgs never span services. Any user may found one through the app and
becomes its first **admin**; members are added by user id with an org role, `admin` or
`member`, layered on their service roles. An org always keeps at least one admin
(`409 last_admin`); delete the org instead. These calls run under the service token, so the
app decides who may make them (normally: callers whose token says `org_role: admin`).

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/orgs` | `{"name","admin_user_id"}` → `201 org`; the user becomes the first admin. Name 1–80 chars |
| GET | `/v1/orgs?limit=50&cursor=` | `{"orgs":[org],"next"}` |
| GET | `/v1/orgs/{id}` | `org` |
| PATCH | `/v1/orgs/{id}` | any of `{"name","status":"active\|disabled"}` → `200 org`. A disabled org cannot be used as a login context |
| DELETE | `/v1/orgs/{id}` | `204`; removes every membership. Tokens already carrying the org run out within the hour; refreshes drop it |
| GET | `/v1/orgs/{id}/members` | `{"members":[{"user_id","role","joined_at","email","name","status"}]}` oldest first |
| PUT | `/v1/orgs/{id}/members/{user_id}` | `{"role":"admin\|member"}` adds or re-roles → `200 {"org_id","user_id","role","joined_at"}`. `409 last_admin` |
| DELETE | `/v1/orgs/{id}/members/{user_id}` | `204`. `404 not_a_member`, `409 last_admin` |
| GET | `/v1/users/{id}/orgs` | `{"orgs":[org + "role"]}`: what to show in an org picker |
| POST | `/v1/orgs/{id}/invites` | `{"email","role":"admin\|member","invited_by"?}` → `201 invite`; mails the address. `409 already_member`, `409 org_disabled`, `404 email_disabled` (no outbox), `429` after 5 sends to one address in 15 min |
| GET | `/v1/orgs/{id}/invites` | `{"invites":[invite]}` pending, oldest first |
| DELETE | `/v1/orgs/{id}/invites/{email}` | `204`; `404 invite_not_found` |

`org` = `{"id":"org_…","service_id","name","status","created_at"}`.
`invite` = `{"org_id","email","role","invited_by","created_at","expires_at"}`.

**Emailed invites.** An org admin (through the app) invites an address with a role. Squawk
mails the person (naming the inviter when `invited_by` is a user id) and asks them to sign
in to the app with that address. There is no link to click: the invite is claimed the moment
a user with that **verified** address signs in, or verifies the address, and becomes a
membership with the invited role (audited `org.invite.accepted`). Re-inviting the same
address replaces the pending invite (new role, fresh 14-day expiry) and mails again. Someone
who is already a member cannot be invited; their role is changed with the membership call.
An invite does not open a closed pool: with `open_signup=false` the owner still provisions
the account, and the invite waits for it.

**Org context in tokens.** Add `org=<org id>` to `/oauth/authorize` and the sign-in completes
only for a member (or the owner): the login finish calls answer `403 not_a_member` and leave
the `login_challenge` valid for another account; the Google callback returns to
`login_url?error=not_a_member`. An unknown org bounces to the client with `invalid_request`, a
disabled one with `access_denied`. The tokens then carry `org` and `org_role` (`admin` for the
owner). To pick or switch an org after signing in, refresh with `org=<org id>`
(`POST /oauth/token`, `grant_type=refresh_token`): the new tokens carry it, or the exchange
fails with `invalid_grant` for a non-member. A plain refresh re-resolves the current org: the
role follows the membership, and a membership that no longer exists (or a disabled or deleted
org) drops the context instead of failing, so the app shows its picker again.

**Login flow:** the app sends the browser to `/oauth/authorize` (its own client, PKCE,
`resource`); because the service has a `login_url` the browser lands on
`login_url?login_challenge=<id>`. The page offers passkey (backend drives
`/v1/login/passkey/*`), an emailed code, Google (link to `/v1/login/google/start`) or
"Sign in as owner" (`/v1/login/owner/*`). Every path ends with a redirect to the app's
`redirect_uri` carrying `code`, exchanged at `/oauth/token`. User tokens: `sub=usr:<id>`,
`aud=<service id>`, `email`, `scope` = requested ∩ union of the user's roles' scopes. Owner
tokens: `sub=owner`, no `email`, the requested scope. Consumers that gate on `sub` must accept
both forms. First-party apps get no consent screen. With `org=` on the authorize request the
tokens also carry `org` and `org_role` (see "Teams and organisations").

## Admin API

All under `/admin`. Auth: admin session cookie or admin bearer. **fresh** = step-up required.

### Console and sessions
| Method | Path | Notes |
|---|---|---|
| GET | `/admin` | the console (HTML) |
| GET | `/admin/session` | `{"authenticated":bool,"method":"passkey\|recovery\|token\|","setup_required":bool,"expires_at"?,"fresh"?}` |
| POST | `/admin/login/begin` | `{"challenge_id","options"}` (WebAuthn assertion options); `409 setup_required` when no passkey exists |
| POST | `/admin/login/finish?challenge=` | body: the browser's credential JSON → sets the cookie, `{"authenticated":true,"method":"passkey","expires_at"}` |
| POST | `/admin/logout` | `204`, clears the cookie |
| POST | `/admin/logout-everywhere` | `204`; kills every session and every connector refresh token |
| POST | `/admin/step-up/begin` / `…/finish?challenge=` | re-verify the current passkey session |

### Passkeys and recovery
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/passkeys` | `{"passkeys":[{"id","name","created_at"}]}` |
| POST | `/admin/passkeys/begin` | `{"challenge_id","options"}` (creation options, resident key + UV required) |
| POST | `/admin/passkeys/finish?challenge=&name=` | body: credential JSON → `201 {"id","name","created_at"}` |
| GET | `/admin/recovery-codes` | `{"total","remaining","created_at"?}` |
| POST | `/admin/recovery-codes` | **fresh**. `201 {"codes":[10 × "xxxx-xxxx-xxxx-xxxx"]}`; replaces the old set |
| POST | `/admin/recover` | no auth. `{"code":"…"}` → sets a **recovery** session cookie (can manage passkeys, cannot mint or approve) |

### Services, credentials, resources
| Method | Path | Notes |
|---|---|---|
| POST | `/admin/services` | `{"name":"FinForge","slug":"finforge"}` → `201 service`. Slug: 2–40 chars `[a-z0-9-]`, unique |
| GET | `/admin/services` | `{"services":[service]}` |
| GET | `/admin/services/{id}` | `service` |
| POST | `/admin/services/{id}/resources` | `{"resource":"https://finforge.nathanblatter.com/mcp"}` → `200 service`. Absolute https URL, unique across services |
| PUT | `/admin/services/{id}/login` | `{"login_url","rp_id","origins":[…],"default_roles":[…],"open_signup":false}` → `200 service`. Empty `login_url` = owner-only (and `open_signup` is forced off). `rp_id` must be a registrable suffix of every origin; default roles must exist |
| POST | `/admin/services/{id}/users` | `{"email","name"?,"method":"passkey|google|email"}` (default `passkey`) → `201 user` (born `email_verified`), whatever `open_signup` says. `409 identity_taken`, `409 service_not_configured` on an owner-only service. Method `password`: `{"method":"password","username","password"\|"password_hash","name"?,"email"?,"roles"?}` (roles default to the service's `default_roles`) |
| POST | `/admin/services/{id}/users/{user}/password` | `{"password"}` or `{"password_hash"}` → `200 user`; the owner's reset for a password (or passkey-converted) account |
| GET | `/admin/services/{id}/users?limit=50&cursor=` | `{"users":[user],"next"}` |
| GET | `/admin/services/{id}/orgs?limit=50&cursor=` | `{"orgs":[org],"next"}` (read-only view of the service's teams) |
| GET | `/admin/services/{id}/orgs/{org}/members` | `{"members":[…]}` as the service-token call |
| GET | `/admin/services/{id}/orgs/{org}/invites` | `{"invites":[invite]}` pending invites (read-only) |
| PUT | `/admin/services/{id}/permissions` | `{"scopes":["read","write"],"roles":{"admin":["read","write"],"viewer":["read"]}}` → `200 service`. Scopes `^[a-z][a-z0-9:._-]{0,39}$` (≤50); role names `^[a-z][a-z0-9-]{0,39}$` (≤20) bundling catalog scopes only. Replaces the whole catalog |
| POST | `/admin/services/{id}/credentials` | **fresh**. `201 {"credential":"nbk_…", "id","service_id","last4","created_at","revoked":false}` |
| GET | `/admin/services/{id}/credentials` | `{"credentials":[{"id","service_id","last4","created_at","revoked","revoked_at"?}]}` (never the secret or its hash) |
| DELETE | `/admin/services/{id}/credentials/{cred}` | `204`; idempotent. Already-issued 15-minute service tokens finish their lifetime |

`service` = `{"id","slug","name","status":"active|disabled","created_at","resources":[…],"scopes":[…],"roles":{name:[…]},"login_url","rp_id","origins":[…],"default_roles":[…],"open_signup":bool}`.

### Connector approvals
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/authorize/{id}` | `{"id","client_name","client_id","scope","resource","service":service,"expires_at"}`; `404` once answered or after 10 min |
| POST | `/admin/authorize/{id}/approve` | **fresh passkey only** (bearer refused). `{"redirect_to":"https://…?code=…&state=…"}` |
| POST | `/admin/authorize/{id}/deny` | `{"redirect_to":"https://…?error=access_denied&state=…"}` |

### Audit log
| Method | Path | Notes |
|---|---|---|
| GET | `/admin/audit?month=YYYY-MM&limit=50&cursor=` | `{"month","events":[{"at","kind","actor","service_id","detail","ip"}],"next"}` newest first; pass `next` back as `cursor` |

Event kinds: `service.create`, `service.resource.add`, `service.permissions.set`, `service.login.set`,
`user.create`, `user.provision`, `user.signup_denied`, `user.google.bind`, `user.email_code.sent`, `user.email.verified`, `user.passkey.register`, `user.login.alerted`, `user.login.alert_suppressed`, `user.update`, `user.login`, `user.login_denied`, `user.logout_everywhere`,
`user.passkey.register`, `user.password.set`, `user.method.converted`, `user.export`, `user.delete`, `org.create`, `org.update`, `org.delete`,
`org.member.set`, `org.member.remove`, `org.invite.create`, `org.invite.revoke`,
`org.invite.accepted`, `credential.mint`, `credential.revoke`,
`token.issue`, `token.denied`, `passkey.register`, `owner.login`, `owner.login_denied`,
`owner.stepup`, `owner.stepup_denied`, `owner.logout_everywhere`, `recovery.generate`,
`recovery.login`, `recovery.denied`, `oauth.client.register`, `oauth.authorize.request`,
`oauth.approve`, `oauth.deny`, `oauth.token`, `oauth.token.denied`, `oauth.refresh`,
`oauth.refresh.reuse`, `oauth.refresh.denied`, `oauth.org.denied`, `oauth.org.dropped`.

---

## Quick start for a new product

```sh
AUTH=https://squawk.nathanblatter.com
# 1. In the console: create the service, add its resource URL, mint a credential.
# 2. Backend: exchange the credential when you need to call the auth API.
curl -s -X POST $AUTH/v1/token -d grant_type=client_credentials -d client_id=svc_… -d client_secret=nbk_…
# 3. Protect your endpoints with the Go client (verifies connector tokens via JWKS):
#    v := client.NewVerifier(AUTH, "svc_…", client.WithResource("https://you/mcp"))
#    mux.Handle("/mcp", client.RequireToken(v)(h))
```
