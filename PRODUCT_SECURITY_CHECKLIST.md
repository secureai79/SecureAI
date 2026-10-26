# Product Security & Customer-Data Checklist

## Safe defaults shipped
- [x] Full repository not persisted as a blob
- [x] Temporary clone cleanup in `finally`
- [x] Source snippets disabled by default
- [x] Optional snippets encrypted at application layer
- [x] Secrets redacted before persistence
- [x] External LLM disabled by default
- [x] External LLM requires explicit privacy acknowledgement
- [x] Scan retention cleanup
- [x] Repository/scan/org deletion endpoints
- [x] GitHub OAuth state persisted, expiring and single-use
- [x] GitHub App production path
- [x] Legacy broad OAuth disabled in production
- [x] Sanitized customer-facing scan errors
- [x] Login/signup/scan rate limits
- [x] Short-lived JWT and logout revocation
- [x] Production config rejects weak/wildcard defaults
- [x] Child-process scan boundary with resource limits
- [x] Restricted child environment (no master application secrets)
- [x] Git hooks/submodules disabled
- [x] Blob-size filtering
- [x] Symlink escape protection
- [x] Fix generator path traversal protection
- [x] Conservative SQL-injection sink matching

## Operator controls required before broad commercial launch
- [ ] HTTPS termination and WAF/API gateway
- [ ] Distributed rate limiting (Redis/WAF) for multiple instances
- [ ] Managed PostgreSQL with encryption at rest
- [ ] Encrypted database backups and explicit backup retention
- [ ] Secret manager for all production secrets
- [ ] Separate scanner worker container/service with least-privilege DB role
- [ ] Worker outbound network allowlist
- [ ] Dependency/container vulnerability scanning
- [ ] Centralized audit logs and alerting
- [ ] Key rotation and backup-restore drills
- [ ] Final legal/privacy review, subprocessors, data residency and breach-notification process

## Product claim boundary
AI Safety Checkup is a static-analysis and security-triage product. It must not claim that a scan proves an application is secure or that an attacker has/has not compromised it.
