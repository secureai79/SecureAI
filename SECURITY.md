# Security Notes

## Secure-by-default behavior
- Production requires a strong `JWT_SECRET`.
- Production requires explicit non-wildcard CORS origins.
- Local `file://` repositories are disabled in production.
- Production database must not be SQLite.
- Production GitHub access uses the GitHub App flow; legacy OAuth App access is disabled.
- GitHub credentials are encrypted at rest.
- Optional stored source snippets are encrypted at the application layer.
- External LLM refinement is disabled by default and requires explicit privacy acknowledgement.
- Authentication and scan endpoints have dependency-free per-process rate limits; deploy an equivalent WAF/API-gateway limit for multi-instance systems.
- Repository scans run in a child process with CPU/address-space/file-size limits where the host OS supports POSIX resource limits.
- Git cloning disables repository hooks and submodules and uses a blob-size filter.
- Symlinked repository files are skipped/rejected so a scan cannot follow a repository symlink outside its temporary workspace.
- Scan failures returned to customers are sanitized rather than exposing raw Git stderr or stack traces.

## Customer data minimization
The scanner does not intentionally store a full repository. Default persistence is structured metadata and redacted evidence. Set `STORE_SOURCE_SNIPPETS=true` only when the customer explicitly wants code excerpts in the dashboard/report.

## Important deployment boundary
The child-process isolation is an application-level defense. For a public multi-tenant service, run scan workers as a separate container/service with a read-only filesystem where possible, no access to the primary database credentials beyond the minimum required, outbound network restricted to required GitHub endpoints, and independent CPU/memory/disk quotas.

## Operational controls still required from the operator
- HTTPS reverse proxy/WAF.
- Managed PostgreSQL with encryption at rest and encrypted backups.
- Secret manager for JWT, GitHub App key, Fernet keys and database credentials.
- Centralized rate limiting for multiple instances.
- Monitoring, audit logs, alerting and incident response.
- Dependency and container image scanning.
- Regular key rotation and backup restore tests.


## Phase 1 hardening (added)
- Scan rate limit is keyed on the normalised route and the authenticated user, so creating many repositories does not multiply the allowance. `X-Forwarded-For` is trusted only when `TRUSTED_PROXY_COUNT` is set.
- Per-organization quotas: repositories, concurrent scans and scans per 24 h; a global concurrency guard returns 503 instead of exhausting the thread pool. Stuck "processing" scans are closed automatically.
- Accounts lock for `LOGIN_LOCKOUT_MINUTES` after `LOGIN_LOCKOUT_THRESHOLD` failures. Unknown-email logins take the same time as wrong-password logins. PBKDF2 uses 600,000 iterations and old hashes upgrade on login.
- Production requires a valid `GITHUB_TOKEN_ENCRYPTION_KEY` whenever any GitHub setting is present; there is no ephemeral-key fallback in production. Keys support rotation (comma-separated, first encrypts).
- Append-only audit trail (`audit_events`, owner-only `GET /auth/audit`) that survives organization deletion.
- Scheduled retention sweep; `/ready` checks the database; API docs and schema are disabled in production; the API sends a deny-all CSP and `Cache-Control: no-store` on authenticated responses.
- The scan debug log (which records repository file paths) is off unless `SCAN_DEBUG_LOG=true`.
- The container runs as an unprivileged user on a read-only root filesystem with all capabilities dropped.

## Still open (see roadmap)
Email verification, password reset and MFA; a real job queue and an isolated, network-restricted scan sandbox without database credentials; Alembic migrations; repo-ownership verification against the GitHub installation; frontend Content-Security-Policy and a move from sessionStorage tokens to httpOnly cookies.
