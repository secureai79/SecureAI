# Start a clean GitHub repository

Goal: nothing from the old pushes survives on GitHub, and nothing sensitive can be pushed again.

**Important:** anything that was ever pushed (secrets, database dumps, backups) must be treated as exposed even after the repository is deleted: it may have been cloned, forked or cached. Deleting fixes the *future*; **rotating the secrets** fixes the *past*. Do both.

## 1. Find out what was pushed (2 minutes)

Run in the project folder (PowerShell). These commands only read history:

```powershell
git log --all --oneline | Measure-Object -Line                       # how many commits exist
git log --all --name-only --pretty=format: | Sort-Object -Unique |
    Select-String -Pattern '\.env|\.pem|\.sql|\.db$|secrets/|backup|\.key$'   # sensitive file names ever committed
git log --all --oneline -S"BEGIN RSA PRIVATE KEY"                    # a private key ever committed?
git log --all --oneline -S"JWT_SECRET="                              # secrets assigned in committed files?
git log --all --oneline -S"neon.tech"                                # a database URL ever committed?
```

Any line of output from the last four commands means that item was public (or private-but-shared) history. **Rotate it** (step 5), even if the repository was private.

## 2. Keep a private copy of the old history (optional)

```powershell
Copy-Item .git D:\ai-saftey\old-git-history -Recurse        # outside the project folder; never push this
```

## 3. Delete the old repository on GitHub

1. GitHub → `supdo79/SecureAI` → **Settings** → scroll to **Danger Zone** → **Delete this repository**.
2. Check the repository's **Forks** count first. A fork keeps its own copy of the old history; if there are public forks, ask GitHub Support to remove them.
3. Create a new **private** repository (same name is fine), **empty**: do not add a README, `.gitignore` or licence.

*(If you must keep the repository, the alternative is an orphan branch force-push, but GitHub keeps old commits reachable by SHA, in forks and in pull-request refs until Support purges them. Deleting is the only clean option.)*

## 4. Create the new history from the cleaned project

First copy the new files from the zips over the project. Then:

```powershell
cd D:\ai-saftey\ai-safety-startup-pilot

# delete leftovers that must never be pushed (the new .gitignore hides them, this removes them from disk too)
# Preview first with -WhatIf, then run again without it:
Remove-Item -Recurse -Force -WhatIf _local_backups, backups, docker-compose.before-cleanup.yml, oauth-diff.txt, openapi-diagnostic.json
Get-ChildItem -Recurse -Include *.bak,*.step1-backup,*backup*.py -File | Remove-Item -WhatIf
# the SQL dump holds real user data and password hashes: move it somewhere private OUTSIDE the project
Move-Item ai_safety_backup_20261005.sql D:\ai-saftey\private-backups\

Remove-Item -Recurse -Force .git          # drops the old history locally
git init -b main
git config user.name  "Your Name"
git config user.email "your-github-noreply@users.noreply.github.com"   # keeps your real address out of commits

git add -A
python scripts/check_repo_clean.py        # must say "Clean"; if it lists files, fix them and run `git add -A` again
git status                                # read the list once: no .env, no .pem, no .sql
git commit -m "Initial commit"
git remote add origin https://github.com/supdo79/SecureAI.git
git push -u origin main
```

From now on `.github/workflows/ci.yml` re-runs the same secret check on every push.

## 5. Rotate everything that was ever exposed

| What | How |
|---|---|
| GitHub App private key | GitHub → Settings → Developer settings → your App → **Generate a new private key**, then delete the old one |
| JWT secret | new value in `.env.production` (this signs every user out once) |
| `GITHUB_TOKEN_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY`, `SOURCE_EVIDENCE_ENCRYPTION_KEY` | the app accepts `new,old` (comma separated, newest first) so existing data stays readable; remove `old` after a few weeks |
| Database password | Neon → Roles → reset password; update `DATABASE_URL` |
| SMTP / Brevo key | Brevo → SMTP & API → delete the old key, create a new one |
| GitHub personal access tokens | revoke any that were ever in a file |

Then look at the GitHub App's installations list and remove any you do not recognise.
