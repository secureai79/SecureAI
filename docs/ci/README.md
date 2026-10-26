# AI Safety Check in CI (policy-as-code)

Runs the same analysis as the hosted product **inside your runner**. No server, no database, no upload: source code
never leaves your infrastructure.

## Quick start
1. Add `.aisafety.yml` (see `examples/aisafety.example.yml`; check it with `python -m aisafety policy-check .aisafety.yml`).
2. Copy `docs/ci/ai-safety.yml` to `.github/workflows/` in the repo to protect.
3. Make the "AI Safety Check" job a **required status check** (branch protection) so it can block merges.

Try it locally first:
```
cd backend
python -m aisafety scan ../demo_repo                      # text report, exit 1 if the policy fails
python -m aisafety scan . --base-ref origin/main          # PR mode: only findings introduced since main can block
python -m aisafety scan . --sarif out.sarif --markdown out.md --json out.json
python -m aisafety scan . --write-baseline baseline.json  # adopt on an existing codebase, then --baseline baseline.json
```
Exit codes: 0 passed, 1 policy failed, 2 usage/policy error, 3 scan error.

## What it does on a pull request
- scans the PR head and the base branch, and compares findings by stable fingerprint;
- a finding that got **more severe** counts as new; findings that already existed do not block (`new_only`);
- posts one sticky comment (updated, not duplicated), writes the job summary, emits inline annotations, and uploads
  SARIF so findings appear in the repository's Security tab.

## Accepting a risk
Copy the finding's fingerprint (shown in the comment/report) into `suppressions` with a written reason and an expiry
date. Expired suppressions are enforced again automatically.

## Safety notes
- Output derived from scanned code is escaped (no HTML/links/@mentions in comments, workflow commands escaped).
- Action inputs are passed via environment variables, never interpolated into shell text.
- Fork PRs get a read-only token: the comment is skipped (never fails the check); annotations, summary and the exit
  code still work.
- Use `permissions: contents: read, pull-requests: write, security-events: write`, and `persist-credentials: false`.

## Limits
Full data-flow analysis is Python; JS/TS needs `javascript: "true"` (installs the TypeScript parser) and is otherwise
a low-confidence lead. Tools defined in other files are judged by name. It reports exposure; it does not prove
exploitability. To use `uses: your-org/repo@v1` the repository containing `action.yml` + `backend/` must be pushed to
GitHub; to try it inside this same repository use `uses: ./`.