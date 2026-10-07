# Authentication & Role-Based Access Control (RBAC)

## Overview

Correlic supports multiple authentication methods: session-based email/password login, Google OAuth, API keys (service and agent types), and mutual TLS (mTLS) client certificates. All authenticated requests carry an org ID, actor type, actor ID, and (optionally) an actor role through the request context.

---

## Authentication Methods

### 1. Session-Based Login (Email/Password)

**Endpoint:** `POST /auth/sessions`

Users authenticate with email and password. On success, the server returns a raw session token. The client sends this token in subsequent requests via the `Authorization` header (`Bearer <token>` or `ApiKey <token>` or bare token).

**Flow:**

1. Client sends `{ "email": "...", "password": "..." }`.
2. Server looks up the user by email, verifies the bcrypt password hash.
3. Server creates a session row in the `sessions` table (token stored as SHA-256 hash).
4. Server returns the raw token, session metadata, and user object.
5. Client sends the raw token in `Authorization: Bearer <token>` on future requests.
6. `AuthMiddleware` hashes the token and looks it up in `sessions`; checks expiry.

**Constraints:**

- Service accounts cannot log in with passwords.
- Email must be verified (`email_verified = true`) before login is allowed.
- Session TTL defaults to 24 hours, configurable up to 720 hours via `ttl_hours`.
- Context values set: `actor_type=user_session`, `actor_id=<user_id>`, `actor_role=<org_users.role>`.

### 2. Google OAuth

**Endpoint:** `POST /auth/google`

**Flow:**

1. Client sends `{ "id_token": "<Google ID token>" }`.
2. Server verifies the token against `https://oauth2.googleapis.com/tokeninfo`.
3. Server checks audience matches `GOOGLE_CLIENT_ID` (if configured).
4. If the Google account is already linked (`user_oauth_accounts` table), the existing user is loaded.
5. If the email matches an existing user, the Google account is linked to that user.
6. If no user exists, a new user is created (email auto-verified, random unusable password).
7. A session is created (same as email/password flow) with 24-hour TTL.

**Key detail:** Google-authenticated users are immediately marked as `email_verified = true`.

### 3. API Keys

**Endpoint (management):** `GET/POST/DELETE /api/v1/api-keys` (admin-only)

API keys are 256-bit random tokens (32 bytes, hex-encoded). Only the SHA-256 hash is stored in the `api_keys` table. The raw key is returned once at creation time and never stored.

**Two key types exist:**

| Type | `key_type` | Created by | Purpose |
|------|-----------|------------|---------|
| Service | `service` | Admin, via API keys handler | Backend integrations, service accounts |
| Agent | `agent` | Signed-in user, via agent tokens handler | Agent enrollment and telemetry ingestion |

**Auth flow:**

1. Client sends the raw key in `Authorization: Bearer <key>`.
2. `AuthMiddleware` hashes the key with SHA-256 and calls `LookupKeyInfo(hash)`.
3. The query joins `api_keys` with `org_users` to resolve org ID, user ID, and role.
4. Revoked keys (`revoked_at IS NOT NULL`) are rejected.
5. Context values set: `actor_type=api_key`, `actor_id=<user_id>` (or key hash if no user), `actor_role=<org_users.role>`.

### 4. Agent Tokens

**Endpoint:** `POST /api/v1/agent-tokens`

Agent tokens are API keys with `key_type = 'agent'`. They can only be created by signed-in users (`actor_type=user_session`). The token is tied to the creating user's org and user ID.

### 5. Mutual TLS (mTLS)

**How it works:**

1. `MTLSFingerprintMiddleware` extracts the SHA-256 fingerprint of the client's leaf certificate from `r.TLS.PeerCertificates[0]` and stores it in the request context.
2. `RequireMTLS` middleware rejects requests that have no TLS connection or no peer certificates.
3. `AuthMiddleware` looks up the fingerprint in the `client_certs` table to resolve the org ID.
4. If both an API key and a client cert are present, the middleware requires both to map to the same org.
5. If only mTLS is present (no API key), the org is resolved from the fingerprint alone.

**Context values set:** `actor_type=mtls`, `actor_id=<certificate_fingerprint>`.

**Environment:** mTLS CA is configured via `MTLS_CA_FILE`. API key auth can be disabled entirely with `ALLOW_API_KEY_AUTH=false`.

---

## RBAC

### Roles

Roles are stored in the `org_users` table as a `(org_id, user_id, role)` tuple. The default role when none is specified is `"member"`.

The codebase enforces role checks for `"admin"` via `RoleGuard.RequireRole("admin")` and `IsAdminRequest()`.

### Role Resolution Order

The `RoleGuard` middleware resolves the actor's role in this order:

1. **Context role** (from API key auth) -- `ActorRoleFromContext()` is checked first. If present, it must match the required role exactly.
2. **Legacy API key / mTLS** -- If `actor_type` is `api_key` or `mtls` and no role is in the context, the request is treated as admin (backward compatibility for keys created before the user/role migration).
3. **User session fallback** -- If the actor is a user session, the `X-User-Email` header is read, the user is looked up, and `GetOrgUserRole()` is called to check the role.

### `IsAdminRequest` Helper

Used by handlers that need to conditionally check admin status without blocking. Follows the same resolution order as `RoleGuard`.

---

## Middleware Chain

### Authenticated Endpoints

```
Request
  -> RateLimiter.Wrap()
    -> RequireMTLS()
      -> MTLSFingerprintMiddleware.Wrap()
        -> AuthMiddleware.Wrap()
          -> Audit()
            -> [Handler]
```

### Authenticated + Role-Guarded Endpoints

```
Request
  -> RateLimiter.Wrap()
    -> RequireMTLS()
      -> MTLSFingerprintMiddleware.Wrap()
        -> AuthMiddleware.Wrap()
          -> Audit()
            -> RoleGuard.RequireRole("admin")
              -> [Handler]
```

### Unauthenticated Endpoints (e.g., login, password reset)

```
Request
  -> RateLimiter.Wrap()
    -> [Handler]
```

**Ordering rationale:**

- Rate limiting runs first to drop abusive traffic before any crypto/DB work.
- mTLS fingerprint extraction happens before auth so the fingerprint is available in context.
- `RequireMTLS` enforces that a client cert is present (required for agent-facing routes).
- Auth resolves the org ID, actor type, actor ID, and role into the context.
- Audit wraps the handler to capture response status codes.
- Role guard runs after auth so the actor identity is available for role checks.

---

## Rate Limiting

**Implementation:** Fixed-window token bucket per caller, keyed by SHA-256 hash of the API key or mTLS fingerprint.

| Setting | Value |
|---------|-------|
| Default limit | Configured via `CORRELIC_RATE_LIMIT_PER_MIN` env var |
| Window | 1 minute |
| Bucket key | SHA-256 of API key or client cert fingerprint |
| Max tracked buckets | 10,000 |
| Cleanup interval | Every window duration (1 min) |
| Stale bucket TTL | 2x window (2 min) |
| Disabled when | `limit <= 0` or `RateLimiter` is nil |
| Response on limit | `429 Too Many Requests` with body `"rate limited"` |

Requests without any credential (no API key, no mTLS fingerprint) are rejected with `401 Unauthorized` by the rate limiter itself.

---

## Audit Logging

### HTTP Audit Middleware

The `Audit()` middleware wraps the response writer to track status codes. The actual log output is currently commented out but the `statusWriter` infrastructure is in place. When enabled, it logs: method, path, org ID, mTLS fingerprint, status code, duration, and remote address.

The `statusWriter` also implements `http.Flusher` for SSE streaming compatibility.

### Structured Audit Events

Handlers write structured audit events to the `audit_events` table via `AuditStore.InsertEvent()`. Each event records:

| Field | Description |
|-------|-------------|
| `org_id` | Organization the action belongs to |
| `actor_type` | `user_session`, `api_key`, or `mtls` |
| `actor_id` | User ID, key hash, or cert fingerprint |
| `action` | Action identifier (see below) |
| `target_type` | Type of object acted upon |
| `target_id` | ID of the object |
| `meta` | Arbitrary JSON metadata |
| `created_at` | Timestamp |

**Audited actions:**

| Action | Target Type | Triggered By |
|--------|-------------|--------------|
| `session.create` | `user` | Login (email/password) |
| `password.reset` | `user` | Password change |
| `user.add` | `user` | Admin adds user to org |
| `user.remove` | `user` | Admin removes user from org |
| `user.update` | `user` | Admin updates user role/name |
| `api_key.create` | `api_key` | Admin creates API key |
| `api_key.revoke` | `api_key` | Admin revokes API key |
| `agent_token.create` | `api_key` | User creates agent token |

---

## Password Security

- **Hashing:** bcrypt with `bcrypt.DefaultCost` (10 rounds).
- **Minimum length:** 8 characters (enforced in password reset handler).
- **Password reset flow:** User provides `old_password` and `new_password`. Old password is verified via `bcrypt.CompareHashAndPassword` before the new hash is stored.
- **Auto-generated passwords:** When an admin creates a user, a 24-character URL-safe random password is generated (`crypto/rand` + base64). The password is returned once in the response and marked `password_reset_required = true`.
- **Service accounts:** Created without passwords; they authenticate exclusively via API keys.
- **Google OAuth users:** Created with a random UUID password (unusable); they authenticate via Google tokens or linked sessions.

---

## Email Verification

- **Send:** `POST /auth/email/send-verification` -- generates a 32-byte random token, stores SHA-256 hash with 24-hour expiry in `email_verification_tokens`.
- **Verify:** `POST /auth/email/verify` -- hashes the provided token, looks up the unexpired/unused row, marks the user as verified.
- **Email delivery:** Via SMTP (configured with `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`). Falls back to logging the verification URL if SMTP is not configured.
- **Tokens are single-use:** Marked `used_at = now()` on successful verification.

---

## Key Files

| File | Purpose |
|------|---------|
| `internal/api/middleware/auth.go` | `AuthMiddleware` -- resolves API key, session, or mTLS to org/actor context |
| `internal/api/middleware/role_guard.go` | `RoleGuard` -- enforces role requirements on routes; `IsAdminRequest` helper |
| `internal/api/middleware/ratelimit.go` | Fixed-window token-bucket rate limiter per caller |
| `internal/api/middleware/audit.go` | HTTP-level audit middleware (status tracking, SSE flusher) |
| `internal/api/middleware/mtls_enroll.go` | mTLS fingerprint extraction middleware |
| `internal/api/middleware/require_mtls.go` | Rejects requests without a valid client certificate |
| `internal/api/auth_users.go` | `SessionsHandler` (login), `PasswordResetHandler`, `UsersHandler` (CRUD) |
| `internal/api/google_auth_handler.go` | Google OAuth sign-in handler |
| `internal/api/email_verification_handler.go` | Email verification send/verify handlers |
| `internal/api/api_keys.go` | API key list/create/revoke handler (admin) |
| `internal/api/agent_tokens.go` | Agent token creation handler (user) |
| `internal/storage/api_key_store.go` | `APIKeyStore` interface and `APIKeyInfo` struct |
| `internal/storage/postgres_api_key_store.go` | PostgreSQL implementation of `APIKeyStore` |
| `internal/storage/postgres_user_store.go` | User, session, OAuth, email verification persistence |
| `internal/storage/audit_store.go` | `AuditStore` interface and `AuditEvent` struct |
