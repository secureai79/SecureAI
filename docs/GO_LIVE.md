# Go-live guide: Cloudflare Pages + API + Neon

```
 Browser ──► Cloudflare Pages  app.example.com   static pages (+ security headers, CSP)
    │
    └──────► API host           api.example.com   FastAPI in Docker (Caddy gives it HTTPS)
                    │
                    └────────► Neon PostgreSQL    users, workspaces, scans, findings
```

Do the steps in order. Anything marked **TEST** has a pass/fail check; do not move on until it passes.
Replace `example.com` with your domain throughout.

---

## 0. Before anything else

1. **Clean GitHub start**: follow [`GITHUB_CLEAN_START.md`](GITHUB_CLEAN_START.md). Rotate every secret that was ever pushed.
2. **Choose the two names**: `app.example.com` (frontend) and `api.example.com` (API). Keep them under one domain so cookies-free bearer auth and CORS stay simple.
3. **Accounts you need**: Cloudflare (domain DNS + Pages), Neon, an API host (see step 3), Brevo (or another SMTP provider) and the GitHub App you already have.
4. **Legal details** for the privacy policy and terms (step 5): company name, support e-mail, address, governing law, where data is hosted.

## 1. Neon database

1. Neon console → **Create project**. Choose the region **closest to your API host** (latency matters for every request).
2. Open **Connection details**. Copy the **direct** connection string (not the `-pooler` one) for the first start. It looks like
   `postgresql://user:password@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require`. Paste it **unchanged**: the app converts it for its driver and enforces SSL.
3. Switch to the pooled string later only if you see "too many connections"; the app detects `-pooler` hosts and adapts.
4. Check your plan's **history retention** (point-in-time restore window) and storage limits in the Neon console; they change, so read them rather than assuming.
5. Neon suspends idle databases. The first request after idle can take a few seconds; the API tolerates this (connection pre-ping, 15 s connect timeout).

## 2. Secrets and settings

```bash
cp .env.production.example .env.production
python scripts/init_env.py --production        # generates JWT_SECRET and the three encryption keys, then checks everything
```

Fill the blanks it reports: `DATABASE_URL`, `SMTP_USERNAME/PASSWORD`, `EMAIL_FROM`, `GITHUB_APP_ID/SLUG`, and set
`FRONTEND_URL=https://app.example.com`, `CORS_ALLOWED_ORIGINS=https://app.example.com`.
Re-run `python scripts/init_env.py --production --check` until it says **".env looks good"**.

`.env.production` must never be committed (it is git-ignored, and CI fails if it appears in a push).

## 3. Deploy the API

The API needs **at least 2 GB of RAM** (scans hold the source in memory) and 1 vCPU. Pick one:

### Option A: a VPS with Docker (full control, ~one small server)

1. Create a server (Ubuntu 22.04/24.04, 2 vCPU / 4 GB), point DNS `api.example.com` → its IP (Cloudflare DNS, **grey cloud / DNS only** to start).
2. `ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable`
3. Install Docker, then:
   ```bash
   git clone https://github.com/supdo79/SecureAI.git /opt/secureai && cd /opt/secureai
   # copy .env.production and secrets/github_app_private_key.pem to the server (scp), then:
   chmod 600 .env.production secrets/github_app_private_key.pem
   export API_DOMAIN=api.example.com
   docker compose -f docker-compose.prod.yml up -d --build
   docker compose -f docker-compose.prod.yml logs -f app      # wait for "Application startup complete"
   ```
4. Caddy obtains the HTTPS certificate automatically on first request (DNS must already point at the server).
5. Updates later: `git pull && docker compose -f docker-compose.prod.yml up -d --build`.

`TRUSTED_PROXY_COUNT=1` is correct here (Caddy is the single proxy). If you later turn on Cloudflare's orange-cloud proxy for `api.example.com`, set it to `2` and set SSL/TLS mode to *Full (strict)*.

### Option B: a managed container host (Render, Railway, Fly.io...)

1. New **Web Service from a Dockerfile** → connect the GitHub repo.
2. Instance: **≥ 2 GB RAM**, **1 instance only** (rate limits are kept in memory; see "Limits").
3. Health check path: `/ready`. The platform sets `PORT`; the image already listens on it.
4. Add every variable from `.env.production` as an environment variable. For the GitHub App key use `GITHUB_APP_PRIVATE_KEY` (paste the PEM, newlines as `\n`) instead of a file.
5. `TRUSTED_PROXY_COUNT=1` (the platform's router). Add a custom domain `api.example.com`.

### TEST 3

```bash
curl -s https://api.example.com/health      # {"status":"ok"}
curl -s https://api.example.com/ready       # {"status":"ready"}   (this one also touches the database)
```
First start creates the tables in Neon. If `/ready` fails, read the logs: the error names the problem (bad `DATABASE_URL`, missing key, validation message).

## 4. Deploy the frontend on Cloudflare Pages

1. Cloudflare → **Workers & Pages → Create → Pages → Connect to Git** → pick the repository.
2. Build settings:
   | Setting | Value |
   |---|---|
   | Framework preset | None |
   | Build command | `python scripts/build_frontend.py --strict` |
   | Build output directory | `dist` |
3. **Environment variables** (Production):
   ```
   PYTHON_VERSION=3.12
   SECUREAI_API_URL=https://api.example.com
   SECUREAI_COMPANY=Your Legal Name
   SECUREAI_SUPPORT_EMAIL=support@example.com
   SECUREAI_ADDRESS=Street, City, Country
   SECUREAI_JURISDICTION=India (courts of Bengaluru)
   SECUREAI_HOSTING_REGION=the EU (Frankfurt)
   SECUREAI_BACKEND_HOST=Hetzner
   SECUREAI_BACKUP_RETENTION=30 days
   SECUREAI_LIABILITY_CAP=USD 100
   ```
   `--strict` makes the build **fail** if any legal field is empty, so draft text cannot go live.
4. **Custom domain**: add `app.example.com` to the Pages project.
5. The build writes `_headers` with HSTS and a CSP that only allows your API origin. Preview it locally any time:
   `python scripts/build_frontend.py --api https://api.example.com --company X ... && python scripts/serve_dist.py dist 5500`

### TEST 4

```bash
curl -sI https://app.example.com/login.html | grep -i -E "content-security-policy|strict-transport|x-frame"
```
Open `https://app.example.com`, then the browser console on login/signup/dashboard: **no red errors, no "Refused to…"**.

## 5. Legal pages

`privacy.html` and `terms.html` are filled from step 4's variables. Before launch:
- Make the **sub-processor list** in the privacy page match reality (Cloudflare, your API host, Neon, Brevo, GitHub, Sentry if enabled).
- Have a lawyer review both documents for your country and customers (for India: the DPDP Act; for EU customers: GDPR). They are a sound starting draft, not legal advice.

## 6. E-mail that actually arrives

Verification, password reset, invitations and support all depend on it.
1. Brevo → **Senders, domains & dedicated IPs → Domains** → add `example.com` and create the **DKIM** and **SPF** DNS records it shows; add a **DMARC** record (`_dmarc` TXT `v=DMARC1; p=none; rua=mailto:you@example.com` to start).
2. Use `EMAIL_FROM=SecureAI <no-reply@example.com>` (an address on the verified domain; **not** gmail.com).
3. SMTP login is the value shown under *SMTP & API* (looks like `xxxxxx@smtp-brevo.com`); the password is an **SMTP key**.

## 7. GitHub App (production URLs)

In GitHub → Settings → Developer settings → your App:
- **Setup URL** and **Callback URL**: `https://api.example.com/integrations/github/app/callback`
- Permissions: **Repository → Contents: Read-only, Metadata: Read-only**. Nothing writable. Webhook: off.
- Set `GITHUB_APP_ID`, `GITHUB_APP_SLUG` and the private key in the API's environment.
After GitHub sends the user back to the API, the API redirects them to `FRONTEND_URL/dashboard.html?github=connected`.

## 8. Smoke test (do this on production, with a real second e-mail address)

1. Sign up → the **confirmation e-mail arrives in the inbox (not spam)** → click the link → "confirmed".
2. Log out → **Forgot password** → reset e-mail arrives → set a new password → old session is gone.
3. Settings → **Two-factor** → scan the QR → save recovery codes → log out and in with a code.
4. **Connect GitHub** → returns to the dashboard → add a small repository → scan → results appear → **Download PDF**.
5. Settings → **Team** → invite your second address → accept in another browser → switch workspaces from the header menu.
6. **Help & Support** → send a message → it arrives in `SUPPORT_EMAIL`.
7. Enter a wrong password 5 times → you are locked out for the configured minutes (`python scripts/admin.py unlock you@example.com` clears it).
8. **Is the client IP real?** The audit log must show *your* IP, not the proxy's, or per-IP rate limits are useless:
   `select ip from audit_events order by created_at desc limit 3;` (Neon SQL editor).
   If it shows an internal address, fix `TRUSTED_PROXY_COUNT`.
9. Trigger a test error to confirm Sentry receives it (if `SENTRY_DSN` is set).

## 9. Backups (before the first real customer)

- Neon's point-in-time restore is the first line of defence; **also keep an independent dump**:
  ```bash
  python scripts/backup_db.py --out /var/backups/secureai --keep 14       # needs `pg_dump` (apt install postgresql-client)
  ```
  Schedule it nightly: `0 3 * * * cd /opt/secureai && python3 scripts/backup_db.py --out /var/backups/secureai --keep 14`, then copy the folder to a **private, encrypted** bucket (Cloudflare R2 + `rclone`). Dumps contain customer data and password hashes: never put them on GitHub.
- **Restore drill** (do it once, now): create a Neon branch or empty database, then
  `pg_restore --no-owner --no-privileges --clean --if-exists -d "<target connection string>" backups/<file>.dump`
  and point a staging copy of the API at it. A backup you have never restored is not a backup.

## 10. Monitoring and on-call basics

- Free uptime monitor (UptimeRobot / Better Stack) on `https://api.example.com/ready` and `https://app.example.com`, alerting your phone.
- `SENTRY_DSN` for error reports (credentials, bodies and personal data are stripped before sending).
- Cloudflare → Notifications: certificate and Pages deployment failures.

## 11. Day-to-day operations

```bash
# inside the API container (VPS):
docker compose -f docker-compose.prod.yml exec app python /app/scripts/admin.py users
docker compose -f docker-compose.prod.yml exec app python /app/scripts/admin.py unlock user@example.com
docker compose -f docker-compose.prod.yml exec app python /app/scripts/admin.py reset-2fa user@example.com --yes   # verify identity first!
docker compose -f docker-compose.prod.yml exec app python /app/scripts/admin.py set-plan <organization_id> team
```
Every admin action is written to the audit log. Releases: push to `main` → CI must be green → Cloudflare Pages redeploys the frontend automatically → redeploy the API (`git pull && docker compose ... up -d --build`, or your host's deploy button).

## 12. Limits you should know about (honest list)

- **One API instance.** Rate limits and login lockouts live in memory; running two instances would give each its own counters. Scale up (bigger machine) before out; if you must scale out, move limits to Redis first.
- **Scans run inside the API machine** (sandboxed, with CPU/memory/time limits and per-workspace concurrency caps). A very busy period slows everyone; the next step is a separate worker service.
- **Analysis scope:** Python, JavaScript/TypeScript, JSON and YAML only. The score is a heuristic, not a guarantee; do not market it as one.
- **No billing yet.** Plans exist only as a limits multiplier (`admin.py set-plan`).
- **CSP still allows inline scripts** (`'unsafe-inline'`), because the pages use inline code. Moving scripts into files and using hashes is the next hardening step.
- **No external penetration test yet.** You hold customers' source code: commission one before you charge money or go public.

## Go / no-go checklist

- [ ] Old GitHub repository deleted, new one private, every old secret rotated
- [ ] `python scripts/check_repo_clean.py` says Clean; CI green on `main`
- [ ] `/ready` OK on the API; Pages deployed; no CSP errors in the browser console
- [ ] E-mail domain verified (SPF, DKIM, DMARC); confirmation mail lands in the inbox
- [ ] Privacy and Terms filled in, sub-processors correct, lawyer has seen them
- [ ] Smoke test (step 8) passed end to end, including the client-IP check
- [ ] Backup taken **and restored once**
- [ ] Uptime monitor and Sentry active
- [ ] You know how to reset a customer's 2FA and unlock a user (`admin.py`)
