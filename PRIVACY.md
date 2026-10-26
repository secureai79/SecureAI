# Privacy & Customer Data

AI Safety Checkup is designed to scan customer repositories without retaining the full repository.

## What is processed
- Account and organization metadata.
- Repository metadata (provider, name and URL).
- Temporary repository contents during a scan.
- Structured scan findings, risk metadata and recommendations.

## Source-code retention
The scanner clones a repository into a temporary workspace and removes that workspace after the scan.
By default, `STORE_SOURCE_SNIPPETS=false`, so raw source snippets are not persisted in the findings database.
Structured evidence is redacted and limited to short explanatory messages.

If a customer explicitly enables `STORE_SOURCE_SNIPPETS=true`, snippets are encrypted at the application layer with `SOURCE_EVIDENCE_ENCRYPTION_KEY` before database storage. Never enable this without a stable production key managed by a secret manager.

## External AI processing
External LLM refinement is **disabled by default**. It is enabled only when both `ENABLE_EXTERNAL_LLM_REFINEMENT=true` and `EXTERNAL_LLM_PRIVACY_ACK=true` are set. Only flagged, redacted snippets are eligible for that optional processor; the full repository is never intentionally sent.

Customers who prohibit source-code processing by third-party AI providers should leave this feature disabled.

## Retention and deletion
Completed scan data is retained for `SCAN_RETENTION_DAYS` (default 30 days) and is cleaned up opportunistically at startup/scan time. Customers can delete an individual scan or repository, or permanently delete all organization data through the authenticated deletion endpoint.

Database backups must be covered by the deployment's own retention and encryption policy. The application cannot make a cloud provider's backup disappear instantly.

## GitHub access
Production GitHub integration uses a GitHub App with repository-scoped permissions. Short-lived installation access tokens are fetched when needed and are not intentionally persisted. The broad legacy GitHub OAuth App flow is disabled in production.

## Security boundary
AI Safety Checkup performs static analysis. It does not execute customer application code. Findings are evidence for review, not a guarantee that a vulnerability exists or that an attack has occurred.

This document describes the product's technical defaults and should be supplemented with the operator's legal/privacy terms, subprocessors, hosting regions, breach-notification process and contact details before commercial launch.
