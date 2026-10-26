# AI Safety Checkup — Validation Report

**Status as of this document: current.** This supersedes all earlier
validation write-ups (previously split across three separate files —
consolidated here on purpose, since a reviewer finding an old file
describing an outdated scoring model was a real, flagged problem). If
you're reviewing this project, this is the one file to read.

## Current state (read this first)

10 real open-source AI-agent repositories (AutoGPT, gpt-researcher,
agency-swarm, generative_agents, OpenAI's swarm, babyagi, crewAI, AgentGPT,
khoj, SuperAGI), scanned with the current scanner + scoring model:

| Repository | Score | Label | Critical | High | Medium | Low |
|---|---:|---|---:|---:|---:|---:|
| AutoGPT | 65 | HIGH RISK | 0 | 0 | 22 | 64 |
| gpt-researcher | 91 | LOW RISK | 0 | 0 | 1 | 1 |
| agency-swarm | 69 | HIGH RISK | 0 | 0 | 15 | 4 |
| generative_agents | 100 | LOW RISK | 0 | 0 | 0 | 0 |
| swarm (OpenAI) | 100 | LOW RISK | 0 | 0 | 0 | 0 |
| babyagi | 100 | LOW RISK | 0 | 0 | 0 | 0 |
| crewAI | 40 | CRITICAL RISK | 0 | 2 | 59 | 6 |
| AgentGPT | 100 | LOW RISK | 0 | 0 | 0 | 0 |
| khoj | 94 | LOW RISK | 0 | 0 | 0 | 4 |
| SuperAGI | 71 | HIGH RISK | 0 | 0 | 16 | 2 |

Zero false CRITICAL findings across all 10 repos. The only real HIGH
findings (crewAI, x2) are genuine `DELETE FROM ...` calls in crewAI's own
persistence layer. No repo with zero CRITICAL/HIGH findings scores below
65 (the old flat-deduction model would have put several of these at a
misleading 0/100 — see "History" below for why that changed).

**What's NOT yet validated:** all 10 repos above are open-source
benchmarks/frameworks the scanner was tuned against, directly or
indirectly, across several rounds of fixes. None of this is validation
against a repo the scanner has never seen, and none of it is validation
against real user reaction. That's the explicit next step (see bottom of
this document) — do not treat the table above as evidence the product is
ready for customers, only as evidence the engineering is no longer
actively misleading on this benchmark set.

## How the scanner and scoring model got here

### Round 1 (v7): first real-repo test — found it was badly broken on non-Python code

Before this round, the scanner had only ever been tested against a small
hand-written demo repo. First real-repo test used the same 10 repos above.
Result: the regex fallback used for non-Python (JS/TS) files was producing
massive false positives — e.g. AutoGPT alone had 826 non-Python findings
out of 1008 total, including a CRITICAL "AI may execute destructive
DELETE" on a React hook for a UI list, triggered by nothing more than the
word "delete" appearing somewhere in the file plus an AI SDK being
imported *anywhere in the repository*. 279 raw CRITICAL/HIGH findings
across the 10 repos were driven by this noise, plus test/tooling-directory
noise (CI scripts, benchmark harnesses) contaminating results even on the
Python/AST side.

The Python AST/taint-tracing engine itself held up well in this same test
— `generative_agents` correctly produced zero findings (genuinely nothing
dangerous wired to AI output), `khoj`'s few Python findings were accurate
and appropriately low-severity, `crewAI`'s real DELETE findings surfaced
correctly. The problem was specifically the regex fallback and lack of
path-based filtering, not the core detection logic.

### Round 2 (v7 → v8): scoring gate + narrower `deploy` keyword

Two fixes, then re-ran the same 10 repos to isolate the effect:

1. **Scoring gate.** Every finding now passes through a gate
   (`risk_engine._apply_scoring_gate`): findings from the regex fallback
   (non-Python) or a non-runtime path (tests/scripts/docs/examples/
   fixtures/mocks — deliberately *not* including a bare `tools/`, since
   testing that against agency-swarm showed it would hide real agent tool
   definitions like `PersistentShellTool.py`) get `scored=False`, severity
   capped at LOW, and are excluded entirely from the Safety Score. They're
   still returned as "Potential capability detected" leads, just not
   allowed to produce a misleading CRITICAL/HIGH.
2. **`deploy` keyword narrowed.** No longer a bare `\bdeploy\b` match
   (which had matched OpenAI's own `swarm.deploy()` — a method that just
   means "run the swarm," nothing to do with infrastructure). Now requires
   an actual infra-SDK name adjacent to `.deploy` or a `subprocess.run`
   whose command names a real deployment tool (docker/kubectl/terraform/...).

Result: scored CRITICAL findings across all 10 repos went from as many as
220 in a single repo to **zero**. Scored HIGH findings dropped to the 2
genuine crewAI DELETE findings. `swarm` went from 5 findings (100% false
positives, all the `.deploy()` pattern) to 0 — the cleanest single
before/after confirmation that a targeted fix worked exactly as intended,
with nothing left behind.

### Round 3 (v8 → v9): scoring model — volume was still zeroing scores

Even with zero false CRITICAL/HIGH, 4 of 10 repos still scored 0/100 --
AutoGPT, agency-swarm, crewAI, SuperAGI -- purely because the flat
deduction model (`score -= 25/15/7/2` per finding, unbounded) let sheer
MEDIUM-finding *volume* zero out the score. A founder seeing "0/100" with
no CRITICAL/HIGH findings listed underneath reads that as "the tool is
broken," not "you have some medium-priority items" -- a real trust
problem, not cosmetic.

**Fix:** `risk_engine.SEVERITY_SCHEDULE` — each severity tier uses
diminishing returns (1st, 2nd, 3rd finding in a tier cost close to the old
flat amount; each additional one costs less) plus a hard per-tier cap
(e.g. MEDIUM tier maxes out at -25 total, no matter how many MEDIUM
findings exist). A single genuine finding of any severity still costs
almost exactly what it did before verified by test
(`test_single_finding_per_tier_matches_old_flat_model`); volume alone
can no longer zero the score.

Re-ran the same 10 repos again (detection logic unchanged, only the
scoring formula) to isolate the effect:

| Repository | v8 score | v9 score |
|---|---:|---:|
| AutoGPT | 0 | 65 |
| agency-swarm | 0 | 69 |
| SuperAGI | 0 | 71 |
| crewAI | 0 | 40 (still worst-scoring — it has 2 *real* HIGH findings, appropriately) |
| (other 6 repos) | 91-100 | unchanged |

The three repos with zero CRITICAL/HIGH and only volume-driven noise
landed at HIGH RISK with a differentiated score instead of a floor of 0.
crewAI — which actually has genuine severity, not just volume — correctly
stayed the worst of the ten. One related fix in the same round: a single
unresolved CRITICAL finding was landing in the "MEDIUM RISK" label bucket
(75/100 fell just inside the old ≥70 threshold) — a smaller version of the
same trust problem. Tightened the threshold to ≥80.

### Round 4 (v9 → v10): frontend redesign + a real graph bug found along the way

No detection or scoring changes. Rebuilt `frontend/dashboard.html` for a
product-appropriate first-screen hierarchy (score hero → "what your AI can
do" capability chips → top 3 risks with click-to-expand code detail → fix
CTA), removed the prefilled demo password, added mobile/loading/empty
states.

Building the capability graph's narrative "aha moment" chains (e.g.
"Support Agent → OpenAI → Generated response → External email") exposed a
genuine pre-existing bug in `GET /scans/{id}/graph`: nodes are deduplicated
by label for a compact graph, so generic intermediate labels like
"AI-generated decision" are legitimately shared across unrelated
capabilities — but naive source→target traversal to reconstruct an
end-to-end path doesn't know that, and can stitch together fragments from
two different capabilities. Concretely, on the demo repo this produced a
false chain claiming a refund function could also send email. Fixed at the
source: every graph edge now carries a `capability_id`, and path
reconstruction groups by that instead of guessing from adjacency. Covered
by `test_capability_graph_endpoint`, which asserts no reconstructed path
mixes fragments from unrelated capabilities.

## What's next

Per explicit direction after the v9/v10 technical checkpoint: stop
engineering, get 5 real developers — not another open-source repo, not
another benchmark — to scan their actual AI applications. Record, per
person: did they scan successfully, did they understand the score, did a
result surprise them, were findings accurate, did they ask for a fix,
would they run it again, would they pay. The signal that matters is
"can I connect another repo" / "can this run on every PR" / "can you fix
this for me" — not "nice product."

This document should get a new dated section appended once that happens,
not a fourth separate file.
