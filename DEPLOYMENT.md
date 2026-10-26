> **Going to production with Cloudflare Pages + a hosted API + Neon Postgres? Start with [`docs/GO_LIVE.md`](docs/GO_LIVE.md).**
> Starting a clean GitHub repository: [`docs/GITHUB_CLEAN_START.md`](docs/GITHUB_CLEAN_START.md).

﻿# Deployment guide

This package is a hardened product baseline for controlled startup and developer pilots. A production security review and operational controls are still required.

## Required production secrets

Set:

- `JWT_SECRET` — at least 32 random bytes.
- `POSTGRES_PASSWORD` — strong random database password.
- `CORS_ALLOWED_ORIGINS` — explicit allowed frontend origin(s); never `*`.
- `GITHUB_TOKEN_ENCRYPTION_KEY` — required when GitHub credential storage is enabled.
- `SOURCE_EVIDENCE_ENCRYPTION_KEY` — required only when `STORE_SOURCE_SNIPPETS=true`.

### GitHub App configuration

For GitHub repository scanning, configure:

- `GITHUB_APP_ID`
- `GITHUB_APP_SLUG`
- `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_FILE`

The GitHub App configuration is required only when GitHub App repository access is enabled.

Do not configure the legacy broad GitHub OAuth flow for production deployments.

## Privacy defaults

- `STORE_SOURCE_SNIPPETS=false`
- `ENABLE_EXTERNAL_LLM_REFINEMENT=false`
- `EXTERNAL_LLM_PRIVACY_ACK` unset
- `SCAN_RETENTION_DAYS=30`
- `ALLOW_LOCAL_REPOS=false`

These defaults minimize persistent customer-code exposure.

## Scan isolation

Production API calls use a child scan process with resource limits.

For a real multi-tenant deployment, place the scanner in a separate worker container/service and restrict its network, filesystem and database permissions. Do not run customer scans with host privileges.

## GitHub

Create a GitHub App with only the repository contents permissions needed for scanning. Users install the App on repositories they choose.

The application requests short-lived installation tokens when scanning and does not require broad write access to customer repositories.

## Database

Use managed PostgreSQL. Do not expose the database publicly.

Enable:

- encryption at rest
- encrypted backups
- least-privilege database users
- tested backup restoration

## Public API protection

Put the API behind HTTPS and a WAF/API gateway.

Apply distributed rate limits to:

- login
- signup
- scan creation
- GitHub integration endpoints

The application includes a local rate limiter as defense in depth, but it is not a replacement for distributed gateway-level limits in a multi-instance deployment.

For a local pilot using the supplied Docker Compose configuration, an explicit `localhost` origin such as `http://localhost:8001` may be used. Hosted production deployments should use the corresponding HTTPS frontend origin.

## Local smoke test

1. Copy `.env.example` to `.env`.
2. Set local-development values and `ALLOW_LOCAL_REPOS=true` only for local testing.
3. Run `docker compose up --build`.
4. Do not use local-repository mode on a hosted customer deployment.

## Production validation

Before exposing the service to customer traffic, verify:

- production configuration validation passes
- PostgreSQL is healthy
- HTTPS is enabled
- CORS contains only intended origins
- production secrets are supplied through a secret-management mechanism
- GitHub App permissions are limited to the required repositories and permissions
- scan workers have appropriate CPU, memory, disk and network restrictions
- backups and restoration have been tested
- monitoring, audit logging and incident-response procedures are in place

## E-mail, verification and password reset

The API sends three kinds of e-mail: account confirmation, password-reset links and a "your password was changed" notice.

1. **Pick a provider** and put its SMTP details in `.env` (see the presets in `.env.example`: Brevo, Resend, Gmail).
   Use a sender address on a domain you have verified with the provider (SPF/DKIM). A free-mail sender such as
   `@gmail.com` sent through another provider is usually rejected or lands in spam.
2. **Brevo**: SMTP login is the value shown under *SMTP & API* (like `xxxxxx@smtp-brevo.com`), the password is an
   *SMTP key*, not your account password. Add and verify the sender under *Senders & IP*.
3. Run `python scripts/init_env.py --check` before starting. It reports duplicate keys, a database URL that does not
   match `POSTGRES_PASSWORD`, a truncated SMTP login, a missing GitHub key file and similar mistakes.
4. In production the API **refuses to start** if verification is required but SMTP is not configured, if the
   `console`/`memory` backends are selected (they would write links to logs), or if `FRONTEND_URL` is plain http on a
   non-local host.

Behaviour worth knowing:

- Links look like `FRONTEND_URL/verify-email.html#token=...`. The token is in the URL fragment, so it never reaches
  servers, proxies or access logs. Tokens are 256-bit, single-use, stored only as SHA-256 hashes, and expire after
  24 hours (verification) or 30 minutes (reset).
- `REQUIRE_EMAIL_VERIFICATION=true` blocks adding repositories, starting scans and connecting GitHub until the address
  is confirmed. Everything else (login, viewing, settings) still works, and the dashboard shows a banner with a
  *Resend email* button.
- `POST /auth/forgot-password` answers identically for registered and unknown addresses. Per-account cooldown
  (`PASSWORD_RESET_COOLDOWN_SECONDS`) and hourly cap (`PASSWORD_RESET_MAX_PER_HOUR`) apply silently, plus a per-IP limit.
- Resetting or changing a password signs out every device (token version bump), clears any lockout and e-mails a notice.
  A successful reset also marks the address as verified, because the user proved they control the inbox.
- Existing accounts created before this release start unverified; they receive a link via *Resend email*.

## Running locally with Docker

```bash
python scripts/init_env.py        # creates .env, generates the secrets, checks everything
# edit .env: SMTP_USERNAME / SMTP_PASSWORD / EMAIL_FROM, GITHUB_APP_ID / GITHUB_APP_SLUG, key path
docker compose up --build -d
curl http://127.0.0.1:8001/ready  # {"status":"ready"}
```

Serve the `frontend/` folder on the origin listed in `FRONTEND_URL` and `CORS_ALLOWED_ORIGINS`
(for example VS Code Live Server on port 5500, or any static host / reverse proxy in production).

Changing `POSTGRES_PASSWORD` after the first start does not change the existing database user. Either recreate the
volume (`docker compose down -v`, **this deletes the data**) or run
`docker compose exec db psql -U aisafety -c "ALTER USER aisafety PASSWORD '<new>'"`.

## Two-factor authentication

Users turn it on in **Settings → Security → Two-Factor Authentication** (authenticator-app TOTP, RFC 6238, 6 digits / 30 s).

- Setup needs the account password; enabling needs a valid code, signs out every other device and shows 10 one-time
  recovery codes (stored only as SHA-256 digests).
- After the password step, sign-in returns a 5-minute challenge instead of a session; `POST /auth/login/2fa` completes it.
  The challenge is signed with a different key and cannot be used as an access token.
- A code can be used once (replay protection). Wrong codes count toward the same lockout as wrong passwords
  (`LOGIN_LOCKOUT_THRESHOLD` / `LOGIN_LOCKOUT_MINUTES`), and a password-only login never resets that counter for 2FA accounts.
- Seeds are encrypted at rest with `MFA_ENCRYPTION_KEY` (falls back to `GITHUB_TOKEN_ENCRYPTION_KEY`; comma-separated
  keys allow rotation). Turning it off or regenerating codes needs the password **and** a current code.
- Password reset does not turn 2FA off. A user who loses the phone and the recovery codes must contact support, who should
  verify identity out-of-band before an administrator clears `totp_*` for that user.

## Help & Support

The sidebar **Help & Support** button opens an FAQ plus a contact form. Messages are e-mailed to `SUPPORT_EMAIL`
(falls back to `EMAIL_REPLY_TO`, then the `EMAIL_FROM` address) with the user's e-mail, workspace and ticket id; replies
go straight to the user, who also receives a confirmation. Limited to 5 messages per 15 minutes per user.

## Hardening notes

- **Pinned dependencies:** the image installs `backend/requirements.lock` (audited with `pip-audit`, no known
  vulnerabilities at the time of writing). Re-generate it and re-audit periodically:
  `pip install -r requirements.txt && pip freeze > requirements.lock && pip-audit`.
- **Request size:** bodies over `MAX_REQUEST_BYTES` (1 MiB) get HTTP 413 before they are parsed.
- **`TRUSTED_PROXY_COUNT`:** keep it at `0` unless a real reverse proxy sits in front of the API. A non-zero value with
  no proxy lets anyone spoof `X-Forwarded-For` and dodge per-IP rate limits.
- **Rate limits are per process.** With more than one API instance, also enforce limits at the gateway or back them with Redis.
- **Serve the frontend with a Content-Security-Policy** at your static host / reverse proxy (the pages use inline scripts and
  Google Fonts, so start with `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' <API origin>; frame-ancestors 'none'`).
- Old `*.bak` / `*backup*` files are excluded from the image by `.dockerignore`; delete them from the repository too.

## Large repositories

Big repositories are scanned **as far as the limits allow instead of failing**, and every result states exactly what
was left out (shown on the dashboard and in the PDF as "Partial scan: X of Y source files analysed").

- **Clone:** shallow, blob-less, and an allow-list checkout: only the file types the analyzers read (`.py .js .ts .tsx .json .yaml` ...)
  are downloaded. Images, video, datasets, model weights, archives, `node_modules`, venvs and lock/minified files never are.
- **Order:** likely AI/agent code first (`agent`, `llm`, `tool`, `mcp`, `prompt`... in the path), then other runtime code, then tests/docs/examples.
- **Soft limits** (all in `.env`): `MAX_SCAN_FILES` (20000), `MAX_SCAN_BYTES` (200 MB), `MAX_SCAN_FILE_BYTES` (2 MB per file),
  `SCAN_TIME_BUDGET_SECONDS` (540: analysis stops and returns a partial result), `MAX_CLONE_MB` (1024).
  Only a repository with more than 20x `MAX_SCAN_FILES` files is refused.
- **Resources:** a scan holds the repository's source in memory. The defaults suit a host with about 4 GB free for the API
  (`mem_limit: 3g`, `SCAN_WORKER_MEMORY_MB=1536`). Clones go to the `scan_work` disk volume (`SCAN_WORKDIR=/work`), not RAM-backed `/tmp`.
  Existing `.env` files keep their old, smaller values: run `python scripts/init_env.py --check`, it lists them.
- **Not size related:** only Python, JavaScript/TypeScript, JSON and YAML are analysed today; Go, Java, Rust, C# etc. are not,
  however small the repository.
- **Plans (future subscriptions):** `organizations.plan` (default `pilot`) scales the limits and the seat count via `app/limits.py`
  (`team` = 2x, `business` = 5x). When billing exists, upgrading an organisation is `UPDATE organizations SET plan='team' WHERE id=...`.

## Team & Access

Owners and admins invite people from **Settings → Team & Access**. Roles: **owner** (one; everything), **admin** (people, GitHub, repositories),
**member** (add repositories, scan, read results). Only the owner can invite admins or change roles; the owner cannot be removed.

- Invitations are e-mailed links (`accept-invite.html#token=...`): 256-bit, single use, expire after `INVITE_TTL_DAYS` (7), stored as SHA-256 digests,
  revocable. The invitee chooses a password; the address counts as verified because the invitation reached the inbox.
- Limits: `MAX_MEMBERS_PER_ORG` (10, counting pending invitations, scaled by plan) and `INVITES_PER_DAY` (20) so the product cannot be used to spam strangers.
- **One account, several workspaces.** Someone who already has an account (their own workspace) can be invited to yours.
  They see the invitation as a banner on their dashboard (Accept / Decline) or open the e-mailed link and log in; the header
  workspace menu then lists every workspace and switches between them. Roles are per workspace (owner of one, member of another).
  Leaving or being removed from a workspace never deletes an account that belongs to another workspace; an account with no workspace left is deleted.
  The active workspace is stored on the account, so switching in one browser tab switches the account everywhere.
- Removing a member deletes the account, ends their session at once and e-mails them a notice. All data stays in the workspace.

## Sign-up and account discovery

With `PREVENT_ACCOUNT_ENUMERATION=true` (default in production) sign-up answers identically for new and already-registered addresses.
New users get a confirmation e-mail and then log in; owners of an existing address get an "you already have an account" e-mail
(at most one per 10 minutes). The rest of the sign-in surface (login, forgot-password) was already uniform.

## Upgrading an existing database

Start-up applies additive migrations and, on PostgreSQL, makes any **unmapped NOT NULL column without a default** nullable
(for example a leftover `users.mfa_enabled` from an older experiment) so inserts keep working. Nothing is dropped or rewritten;
the relaxed columns are listed in the API log (`Relaxed NOT NULL on legacy column(s)...`). To run the PostgreSQL regression test:
`TEST_POSTGRES_URL=postgresql+psycopg://user:pass@host:5432/scratch pytest backend/test_postgres_legacy_schema.py`.
