# AI Safety Checkup

## AI-agent security and risk triage for engineering teams

AI Safety Checkup statically analyzes application repositories to identify AI-controlled actions, consequential capabilities, risky data flows, security weaknesses, and changes between scans.

It is designed for controlled startup and company pilots, including private repositories when GitHub App access is configured.

> **Important:** AI Safety Checkup is a static-analysis and risk-triage product. Its Safety Score is a heuristic signal, not a percentage of security and not a guarantee that a repository is secure.

---

## What it detects

The scanner focuses on the security boundary between AI-generated decisions and consequential application actions.

Examples include:

* AI-controlled financial operations
* AI-generated values reaching external APIs
* AI-controlled email or messaging actions
* destructive database operations
* command execution
* sensitive data sent to external services
* authentication and authorization weaknesses
* hardcoded credentials and API tokens
* potential SQL injection
* potential command injection
* missing or weak human-approval controls
* changes in risk between baseline and subsequent scans

The important distinction is not simply:

> "AI exists in this file."

The scanner attempts to determine:

> "Does a value produced or controlled by AI actually reach a consequential operation?"

---

## Core capabilities

### 1. AI-to-action data-flow analysis

The scanner traces AI-derived values toward dangerous or consequential calls.

Example:

```python
decision = ai_agent(message)

stripe.Refund.create(
    amount=decision["amount"]
)
```

The AI-derived value reaches the refund operation, so the operation can be identified as AI-controlled.

By contrast:

```python
decision = ai_agent(message)

stripe.Refund.create(amount=100)
```

does not establish the same AI-to-action relationship because the dangerous call receives a literal value.

The analysis is deliberately conservative and does not claim complete whole-program or points-to precision.

### 2. Capability graph

Detected AI-controlled capabilities are represented as relationships between:

```text
AI-generated value
        |
        v
Application capability
        |
        v
Consequential action
```

This helps engineering and security teams understand what an AI component can actually influence.

### 3. Risk scoring

Each finding can contribute to a heuristic Safety Score based on factors including:

* severity
* whether AI control was actually traced
* confidence
* approval/threshold controls
* finding category
* repeated findings within the same severity tier

The score is intended for comparison and regression tracking.

It must not be interpreted as:

> "85% secure"

There is no such security percentage.

### 4. Confidence and evidence

Findings include structured evidence and confidence information so reviewers can inspect why an issue was identified.

The scanner distinguishes between:

* confirmed/static evidence
* likely relationships
* possible heuristic matches
* unscored fallback detections

### 5. Baseline and regression analysis

Completed scans can be compared with previous scans.

The system tracks finding fingerprints so teams can identify:

* newly introduced risks
* resolved findings
* unchanged findings
* score changes
* regression signals

### 6. Fix suggestions

For supported findings, the product can generate a reviewable guard-clause patch.

Patch generation is intentionally conservative. Applying a generated patch is currently supported for local/file-based repositories; directly modifying a live GitHub repository requires a PR/write workflow that is outside the current MVP.

---

# Analysis architecture

```text
                         AI SAFETY CHECKUP
                                |
                                v
                         FastAPI Backend
                                |
              +-----------------+----------------+
              |                 |                |
              v                 v                v
           Scanner         Risk Engine       Database
              |                 |                |
              v                 v                v
       AST + data flow      Severity          PostgreSQL
       Capability graph     Confidence        / SQLite
                            Score
              |
              v
     Dashboard / PDF Report
              |
       +------+------+
       |             |
       v             v
    GitHub        Regression
     App           Analysis
```

## Scanner pipeline

```text
Repository
    |
    v
File selection
    |
    +--> Python AST + taint analysis
    |
    +--> JavaScript / TypeScript AST
    |
    v
AI provider / agent detection
    |
    v
AI-derived value propagation
    |
    v
Capability extraction
    |
    v
Risk + confidence analysis
    |
    v
Finding fingerprints
    |
    +--> Safety Score
    +--> Capability Graph
    +--> Regression Analysis
    +--> Customer PDF Report
```

---

# Python analysis

Python repositories use AST-based analysis rather than simple keyword matching.

The analyzer performs conservative taint propagation through:

* AI calls
* AI-returning local functions
* variables
* subscripts
* attributes
* derived expressions
* f-strings
* binary expressions
* limited local interprocedural calls

Guard conditions such as approval checks and relevant threshold checks can reduce the resulting severity.

The analysis is intentionally not a complete static verifier.

---

# JavaScript / TypeScript analysis

JavaScript and TypeScript are analyzed with the **TypeScript compiler API** when the Node.js and TypeScript runtime is available.

The AST bridge provides syntax-aware analysis of:

* JavaScript
* JSX
* TypeScript
* TSX

It can identify AI providers and trace supported local data-flow relationships toward consequential operations.

The analyzer is deliberately fail-closed.

If the required Node.js/TypeScript runtime is unavailable or parsing fails, the system does not promote the fallback result into a scored AST finding.

The implementation does **not** execute repository code and does not claim complete cross-file or whole-program points-to analysis.

For the production Docker image, TypeScript is installed as part of the image build.

---

# Security analysis

In addition to AI-to-action analysis, the scanner performs conservative checks for:

* exposed API keys and tokens
* hardcoded credentials
* sensitive data reaching outbound network requests
* potentially unauthenticated sensitive endpoints
* command injection patterns
* SQL injection patterns
* destructive database operations

These detections are evidence-based static-analysis heuristics.

They are not proof that an application is exploitable or that an attacker has compromised it.

Runtime compromise detection requires application telemetry, logs, and other runtime controls.

---

# Customer Safety Report

Every completed scan can produce a customer-facing PDF report.

```text
GET /scans/{scan_id}/report.pdf
```

The report can include:

* Safety Score
* risk level
* detected AI capabilities
* confidence information
* top risks
* evidence
* data-flow relationships
* recommendations
* scan-to-scan regression information

The report is generated from the selected scan and does not intentionally embed the entire repository.

---

# Privacy and customer-data handling

The release is designed around data minimization.

Default behavior includes:

* source code scanned in a temporary workspace
* temporary source workspace removed after scanning
* source snippets not persisted by default
* structured evidence kept short and redacted where applicable
* optional stored source snippets encrypted at the application layer
* external LLM refinement disabled by default
* configurable scan-data retention
* authenticated repository and scan deletion capabilities

Default privacy configuration:

```text
STORE_SOURCE_SNIPPETS=false
ENABLE_EXTERNAL_LLM_REFINEMENT=false
ALLOW_LOCAL_REPOS=false
```

Do not market the product as a guarantee of security or as a runtime intrusion detector.

See:

* `SECURITY.md`
* `DEPLOYMENT.md`

---

# Production security boundary

Production configuration requires:

* strong `JWT_SECRET`
* PostgreSQL or another supported server database
* explicit non-wildcard CORS origins
* local repository access disabled
* production GitHub access through the GitHub App flow
* external LLM refinement disabled unless explicitly acknowledged
* appropriate resource limits
* centralized infrastructure-level rate limiting

The application also provides defense-in-depth controls including:

* per-process rate limiting
* sanitized scan errors
* restricted repository cloning behavior
* disabled Git hooks/submodules during cloning
* symlink protections
* scan subprocess resource limits where supported

For a real multi-tenant deployment, scan workers should be moved into separate containers/services with restricted:

* CPU
* memory
* disk
* filesystem access
* network access
* database permissions

The child-process isolation in the current application is an application-level defense and should not be treated as the final tenant-isolation boundary for a large public SaaS deployment.

---

# GitHub integration

Production private-repository access uses a GitHub App.

The recommended model is:

```text
Company
   |
   v
GitHub App
   |
   v
Selected repositories
   |
   v
Short-lived installation access
   |
   v
Isolated scanner
```

The application does not require broad write access to customer repositories for scanning.

The legacy broad GitHub OAuth flow is disabled for production deployments.

---

# Deployment

The recommended pilot deployment uses Docker Compose with PostgreSQL.

See:

```text
DEPLOYMENT.md
SECURITY.md
.env.example
Dockerfile
docker-compose.yml
```

A production deployment should additionally use:

* HTTPS
* WAF/API gateway
* centralized rate limiting
* managed PostgreSQL
* encrypted backups
* secret management
* monitoring
* audit logging
* incident-response procedures
* dependency and container-image scanning

For a local pilot using the supplied Docker Compose configuration, an explicit localhost origin such as `http://localhost:8001` may be used.

Hosted production deployments should use the corresponding HTTPS frontend origin.

---

# Local development

From the repository root:

```powershell
cd backend
pip install -r requirements.txt
```

Run the local scanner demo:

```powershell
python scan_cli.py ../demo_repo
```

On Windows, use `python` rather than `python3`.

Run the API:

```powershell
uvicorn app.main:app --reload
```

The development API is then available at:

```text
http://localhost:8000
```

Local repository scanning requires:

```text
ALLOW_LOCAL_REPOS=true
```

This setting must remain disabled for hosted production deployments.

---

# Docker pilot

From the repository root:

```powershell
docker compose up --build
```

The supplied pilot configuration exposes the application on the configured host port.

Verify the application:

```powershell
Invoke-RestMethod http://localhost:8001/health
```

A healthy deployment should return:

```text
status
------
ok
```

For production configuration, use real secrets through the deployment environment or a secret-management system.

Do not commit secrets to `.env`, source control, Dockerfiles, or the repository.

---

# Testing

The hardened release includes automated tests covering areas such as:

* API behavior
* authentication
* scanning
* Python AST analysis
* JavaScript/TypeScript AST analysis
* taint analysis
* capability graphs
* regression detection
* GitHub integration behavior
* PDF reporting
* fix generation
* security controls

The validated development test suite currently passes:

```text
82 passed
```

Warnings from third-party dependencies may still appear during the test run.

---

# API surface

Core endpoints include:

```text
POST  /auth/signup
POST  /auth/login

POST  /repositories
GET   /repositories

POST  /repositories/{id}/scan
GET   /repositories/{id}/scans

GET   /scans/{id}
GET   /scans/{id}/findings
GET   /scans/{id}/potential-score
GET   /scans/{id}/regression
GET   /scans/{id}/graph
GET   /scans/{id}/report.pdf

GET   /findings/{id}/fix
POST  /findings/{id}/apply-fix
PATCH /findings/{id}

GET   /organizations/{id}/score
```

Authentication and authorization apply to protected endpoints.

---

# Repository layout

```text
backend/
  app/
    main.py
    models.py
    schemas.py
    auth.py
    database.py

    scanner/
      file_selector.py
      ast_detector.py
      detectors.py
      capability_extractor.py
      risk_engine.py
      llm_analyzer.py
      scan_service.py

    routers/
      auth.py
      repositories.py
      scans.py
      github_oauth.py

  scan_cli.py
  github_pr_check.py

frontend/
  dashboard.html

demo_repo/

Dockerfile
docker-compose.yml
.env.example
DEPLOYMENT.md
SECURITY.md
README.md
```

---

# Known limitations

AI Safety Checkup is intentionally a static-analysis system.

Current limitations include:

* incomplete whole-program analysis
* limited cross-file/interprocedural reasoning
* no runtime compromise detection
* no guarantee of exploitability detection
* no complete points-to analysis
* supported-language coverage is not equivalent to full language semantics
* heuristic risk scoring can produce false positives and false negatives
* large repositories may require stronger asynchronous worker infrastructure
* production multi-tenancy requires infrastructure-level isolation beyond the current subprocess boundary

These limitations should be communicated during customer pilots.

---

# Pilot architecture

```text
                  Company Repository
                          |
                          v
                    GitHub App
                          |
                          v
                 AI Safety Checkup API
                          |
                          v
                 Isolated Scan Worker
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
             AST      Data Flow    Security
           Analysis    Analysis     Checks
              |           |           |
              +-----------+-----------+
                          |
                          v
                  Risk + Confidence
                          |
              +-----------+-----------+
              |                       |
              v                       v
        Dashboard / API          PDF Report
              |
              v
       Regression Tracking
```

For a larger multi-tenant deployment, the scanner worker should be separated into its own service/container and granted only the permissions required to perform scans.

---

# Pilot readiness checklist

Before giving the system to a company pilot, verify:

* [ ] `ENVIRONMENT=production`
* [ ] `ALLOW_LOCAL_REPOS=false`
* [ ] `STORE_SOURCE_SNIPPETS=false`
* [ ] `ENABLE_EXTERNAL_LLM_REFINEMENT=false`
* [ ] explicit non-wildcard `CORS_ALLOWED_ORIGINS`
* [ ] strong `JWT_SECRET`
* [ ] PostgreSQL configured
* [ ] production secrets supplied outside source control
* [ ] Docker containers start successfully
* [ ] `/health` returns `ok`
* [ ] production startup validation passes
* [ ] scan worker resource limits are configured
* [ ] GitHub App permissions are limited to required access
* [ ] HTTPS/WAF is configured for hosted deployment
* [ ] centralized rate limiting is configured for multi-instance deployment
* [ ] monitoring and logging are available
* [ ] backup and restore procedures have been tested
* [ ] customer data-retention policy is documented
* [ ] security limitations have been communicated to the pilot customer

---

# Product positioning

AI Safety Checkup is intended to answer a practical engineering question:

> **What can our AI-enabled application actually cause the software to do?**

It combines static code analysis, AI-to-action data-flow tracing, capability modeling, security heuristics, confidence, risk scoring, and regression tracking into one engineering-oriented workflow.

It is a decision-support and risk-triage system—not a substitute for secure software development practices, penetration testing, runtime monitoring, code review, or a complete security program.
