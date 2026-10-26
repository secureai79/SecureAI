# SecureAI clean first-push notes

This archive excludes the old .git history, local virtual environments and caches, real .env files, private PEM/key files, local database files, SQL backups, and selected diagnostic artifacts. It retains .env.example and .env.production.example as templates.

## Before first push

1. Treat credentials in the original archive as exposed. Rotate/revoke them at their issuing providers; deleting files does not revoke credentials.
2. GitHub App: open GitHub Settings / Developer settings / GitHub Apps, select the SecureAI app, open Private keys, delete the old private keys, and generate a new key. Store the downloaded PEM outside this source tree and update the deployment secret or mounted secret file. If the old key belongs to an app that is no longer used, revoke/delete it there too.
3. SMTP: rotate the SMTP/API credential at the mail provider, then update SMTP_PASSWORD in your deployment secret store.
4. Database: change the database user's password at the database provider and update DATABASE_URL or POSTGRES_PASSWORD in the deployment secret store. If a database is initialized by Docker with a persistent volume, changing an environment variable alone may not change the existing database user's password.
5. Generate fresh application secrets locally; never put real values in this ZIP or commit them. From the project root, use the project's initializer if available: `python scripts/init_env.py --production`. Review its output and ensure it writes only to an ignored local file.
6. For manual generation in Python: `python -c "import secrets; print(secrets.token_urlsafe(48))"` for JWT_SECRET; and `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` for each Fernet encryption key. Generate distinct values for JWT_SECRET, GITHUB_TOKEN_ENCRYPTION_KEY, SOURCE_EVIDENCE_ENCRYPTION_KEY, and MFA_ENCRYPTION_KEY.
7. IMPORTANT: rotating encryption keys can make existing encrypted data unreadable unless you decrypt/re-encrypt it or retain a protected old-key migration path. Back up and plan migration before changing keys on any database containing data you need.
8. Set new values only in local ignored `.env` files or your hosting provider's secret manager. Do not share secrets in chat.
9. Run `git status --ignored`, review `git status`, and inspect the staged file list before committing. Never use `git add -f` for secrets.

## First Git repository

This is a source archive, not a Git repository. Extract it into a new folder, initialize a fresh repository with `git init`, verify `.gitignore`, run tests and secret scanning, then commit. Do not copy the old `.git` directory.

## Scope note

This cleanup filters known secret/artifact locations from the supplied ZIP. It is not proof that every possible hard-coded secret or vulnerability has been found. Review code and run a secret scanner before publishing.
