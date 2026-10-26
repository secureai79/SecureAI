"""Policy-as-code: ``.aisafety.yml`` decides what blocks a merge.

Example::

    version: 1
    fail_on: high                 # critical | high | medium | low | none
    min_score: 70                 # optional: fail if the score drops below this
    max_findings: {critical: 0, high: 2}
    new_only: true                # in PR mode only findings introduced by the PR can block
    ignore_paths: ["tests/**", "examples/**"]
    rules:
      - id: no-ai-shell
        match: {category: INFRASTRUCTURE, capability: execute, ai_controlled: true}
        action: block             # block | warn | ignore
        message: "AI output must never reach a shell."
      - id: payments-need-approval
        match: {category: FINANCIAL, human_approval: false}
        action: block
        even_if_existing: true    # block even if it already existed on the base branch
    suppressions:
      - fingerprint: "ab12cd34..."
        reason: "Reviewed by security on 2026-10-01; sandboxed."
        expires: 2027-01-31       # required: suppressions must expire

Unknown keys are errors on purpose: a typo in a security policy must never silently do nothing.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
from dataclasses import dataclass, field

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ACTIONS = {"block", "warn", "ignore"}
DOMAINS = {"AI_SAFETY", "PROJECT_SECURITY"}
TOP_KEYS = {"version", "fail_on", "min_score", "max_findings", "new_only", "ignore_paths", "rules",
            "suppressions", "include_unscored"}
RULE_KEYS = {"id", "match", "action", "message", "even_if_existing"}
MATCH_KEYS = {"category", "capability", "severity", "domain", "path", "ai_controlled", "human_approval",
              "title_contains"}
SUPPRESSION_KEYS = {"fingerprint", "reason", "expires"}
MAX_SUPPRESSION_DAYS = 366
POLICY_FILES = (".aisafety.yml", ".aisafety.yaml", ".aisafety.json")


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    match: dict
    action: str
    message: str = ""
    even_if_existing: bool = False


@dataclass
class Suppression:
    fingerprint: str
    reason: str
    expires: dt.date


@dataclass
class Policy:
    fail_on: str | None = "HIGH"
    min_score: int | None = None
    max_findings: dict = field(default_factory=dict)
    new_only: bool = True
    include_unscored: bool = False
    ignore_paths: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    suppressions: list = field(default_factory=list)
    source: str = "built-in defaults"


@dataclass
class Evaluated:
    finding: dict
    status: str            # blocking | warning | suppressed | ignored | existing
    reason: str = ""
    rule_id: str | None = None


@dataclass
class Decision:
    passed: bool
    evaluated: list
    reasons: list
    score: int | None = None
    notes: list = field(default_factory=list)

    def by_status(self, status: str) -> list:
        return [e for e in self.evaluated if e.status == status]


# ----------------------------------------------------------------- loading
def _sev(value, where: str) -> str:
    v = str(value).strip().upper()
    if v not in SEVERITIES:
        raise PolicyError(f"{where}: '{value}' is not a severity (use one of {', '.join(s.lower() for s in SEVERITIES)})")
    return v


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def parse_policy(data, source: str = "policy") -> Policy:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: top level must be a mapping")
    unknown = set(data) - TOP_KEYS
    if unknown:
        raise PolicyError(f"{source}: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    if data.get("version", 1) != 1:
        raise PolicyError(f"{source}: unsupported version {data.get('version')!r} (this tool supports version 1)")

    p = Policy(source=source)
    if "fail_on" in data:
        v = data["fail_on"]
        p.fail_on = None if str(v).lower() in {"none", "never", "false"} or v is False else _sev(v, "fail_on")
    if "min_score" in data:
        ms = data["min_score"]
        if isinstance(ms, bool) or not isinstance(ms, int) or not 0 <= ms <= 100:
            raise PolicyError("min_score must be an integer from 0 to 100")
        p.min_score = ms
    if "max_findings" in data:
        mf = data["max_findings"]
        if not isinstance(mf, dict):
            raise PolicyError("max_findings must be a mapping like {critical: 0, high: 2}")
        for k, v in mf.items():
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise PolicyError(f"max_findings.{k} must be a non-negative integer")
            p.max_findings[_sev(k, "max_findings")] = v
    for key in ("new_only", "include_unscored"):
        if key in data:
            if not isinstance(data[key], bool):
                raise PolicyError(f"{key} must be true or false")
            setattr(p, key, data[key])
    if "ignore_paths" in data:
        ip = data["ignore_paths"]
        if not isinstance(ip, list) or not all(isinstance(x, str) and x for x in ip):
            raise PolicyError("ignore_paths must be a list of glob strings")
        p.ignore_paths = ip

    seen_ids = set()
    for i, raw in enumerate(data.get("rules") or []):
        where = f"rules[{i}]"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be a mapping")
        bad = set(raw) - RULE_KEYS
        if bad:
            raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(map(str, bad)))}")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise PolicyError(f"{where}: 'id' is required")
        if rid in seen_ids:
            raise PolicyError(f"{where}: duplicate rule id '{rid}'")
        seen_ids.add(rid)
        action = str(raw.get("action", "")).lower()
        if action not in ACTIONS:
            raise PolicyError(f"rule '{rid}': action must be one of block, warn, ignore")
        match = raw.get("match")
        if not isinstance(match, dict) or not match:
            raise PolicyError(f"rule '{rid}': 'match' must be a non-empty mapping")
        badm = set(match) - MATCH_KEYS
        if badm:
            raise PolicyError(f"rule '{rid}': unknown match key(s): {', '.join(sorted(map(str, badm)))}")
        norm = {}
        for k, v in match.items():
            if k == "severity":
                vals = [str(x).strip() for x in _as_list(v)]
                if len(vals) == 1 and vals[0].startswith(">="):
                    norm[k] = {"min": _sev(vals[0][2:], f"rule '{rid}' severity")}
                else:
                    norm[k] = {"in": [_sev(x, f"rule '{rid}' severity") for x in vals]}
            elif k == "domain":
                doms = [str(x).upper() for x in _as_list(v)]
                if not set(doms) <= DOMAINS:
                    raise PolicyError(f"rule '{rid}': domain must be AI_SAFETY or PROJECT_SECURITY")
                norm[k] = doms
            elif k in {"ai_controlled", "human_approval"}:
                if not isinstance(v, bool):
                    raise PolicyError(f"rule '{rid}': {k} must be true or false")
                norm[k] = v
            elif k == "title_contains":
                if not isinstance(v, str):
                    raise PolicyError(f"rule '{rid}': title_contains must be a string")
                norm[k] = v.lower()
            else:   # category, capability, path
                vals = _as_list(v)
                if not all(isinstance(x, str) and x for x in vals):
                    raise PolicyError(f"rule '{rid}': {k} must be a string or list of strings")
                norm[k] = [x if k == "path" else x.lower() for x in vals]
        eie = raw.get("even_if_existing", False)
        if not isinstance(eie, bool):
            raise PolicyError(f"rule '{rid}': even_if_existing must be true or false")
        p.rules.append(Rule(rid, norm, action, str(raw.get("message", "")), eie))

    for i, raw in enumerate(data.get("suppressions") or []):
        where = f"suppressions[{i}]"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be a mapping")
        bad = set(raw) - SUPPRESSION_KEYS
        if bad:
            raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(map(str, bad)))}")
        fp, reason, exp = raw.get("fingerprint"), raw.get("reason"), raw.get("expires")
        if not isinstance(fp, str) or not fp.strip():
            raise PolicyError(f"{where}: 'fingerprint' is required")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise PolicyError(f"{where}: 'reason' is required (at least 10 characters explaining why this is accepted)")
        if isinstance(exp, dt.datetime):
            exp = exp.date()
        if isinstance(exp, str):
            try:
                exp = dt.date.fromisoformat(exp)
            except ValueError:
                raise PolicyError(f"{where}: 'expires' must be a date like 2027-01-31")
        if not isinstance(exp, dt.date):
            raise PolicyError(f"{where}: 'expires' is required (suppressions must expire)")
        p.suppressions.append(Suppression(fp.strip(), reason.strip(), exp))
    return p


def find_policy_file(root: str) -> str | None:
    for name in POLICY_FILES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            return path
    return None


def load_policy(path: str | None) -> Policy:
    if path is None:
        return Policy()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}")
    if path.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{path}: invalid JSON: {exc}")
    else:
        try:
            import yaml
        except ImportError:
            raise PolicyError("PyYAML is required to read .yml policies (pip install pyyaml) or use .aisafety.json")
        try:
            data = yaml.safe_load(text)           # safe_load only: never construct arbitrary objects
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: invalid YAML: {exc}")
    return parse_policy(data, source=os.path.basename(path))


# -------------------------------------------------------------- evaluation
def _matches(rule: Rule, f: dict) -> bool:
    m = rule.match
    if "category" in m and str(f.get("category", "")).lower() not in m["category"]:
        return False
    if "capability" in m and str(f.get("capability", "")).lower() not in m["capability"]:
        return False
    if "domain" in m and f.get("finding_domain") not in m["domain"]:
        return False
    if "severity" in m:
        sev = f.get("severity")
        s = m["severity"]
        if "min" in s and SEVERITIES.index(sev) < SEVERITIES.index(s["min"]):
            return False
        if "in" in s and sev not in s["in"]:
            return False
    if "path" in m and not any(fnmatch.fnmatch(f.get("file_path", ""), g) for g in m["path"]):
        return False
    if "ai_controlled" in m and bool(f.get("ai_controlled")) != m["ai_controlled"]:
        return False
    if "human_approval" in m and bool(f.get("human_approval_detected")) != m["human_approval"]:
        return False
    if "title_contains" in m and m["title_contains"] not in str(f.get("title", "")).lower():
        return False
    return True


def evaluate(policy: Policy, findings: list[dict], score: int | None = None,
             base_fingerprints: set | None = None, today: dt.date | None = None) -> Decision:
    """Apply the policy. ``base_fingerprints`` (PR mode) marks which findings already existed."""
    today = today or dt.date.today()
    notes: list[str] = []
    active_suppr = {}
    for s in policy.suppressions:
        if s.expires < today:
            notes.append(f"Suppression {s.fingerprint[:12]}… expired on {s.expires} - the finding is enforced again.")
        elif (s.expires - today).days > MAX_SUPPRESSION_DAYS:
            notes.append(f"Suppression {s.fingerprint[:12]}… expires more than a year out ({s.expires}); review it.")
            active_suppr[s.fingerprint] = s
        else:
            active_suppr[s.fingerprint] = s

    evaluated: list[Evaluated] = []
    for f in findings:
        if not policy.include_unscored and f.get("scored") is False:
            continue
        fp = f.get("fingerprint", "")
        if fp in active_suppr:
            evaluated.append(Evaluated(f, "suppressed", active_suppr[fp].reason))
            continue
        if any(fnmatch.fnmatch(f.get("file_path", ""), g) for g in policy.ignore_paths):
            evaluated.append(Evaluated(f, "ignored", "path ignored by policy"))
            continue
        existing = base_fingerprints is not None and fp in base_fingerprints
        rule = next((r for r in policy.rules if _matches(r, f)), None)
        if rule is not None:
            if rule.action == "ignore":
                evaluated.append(Evaluated(f, "ignored", rule.message or f"rule {rule.id}", rule.id))
            elif rule.action == "warn":
                evaluated.append(Evaluated(f, "warning", rule.message or f"rule {rule.id}", rule.id))
            elif existing and policy.new_only and not rule.even_if_existing:
                evaluated.append(Evaluated(f, "existing", "already present on the base branch", rule.id))
            else:
                evaluated.append(Evaluated(f, "blocking", rule.message or f"blocked by rule {rule.id}", rule.id))
            continue
        over = policy.fail_on is not None and SEVERITIES.index(f["severity"]) >= SEVERITIES.index(policy.fail_on)
        if over and existing and policy.new_only:
            evaluated.append(Evaluated(f, "existing", "already present on the base branch"))
        elif over:
            evaluated.append(Evaluated(f, "blocking", f"{f['severity']} is at or above fail_on: {policy.fail_on.lower()}"))
        else:
            evaluated.append(Evaluated(f, "existing" if existing else "warning",
                                       "already present on the base branch" if existing else "below the fail_on threshold"))

    reasons: list[str] = []
    blocking = [e for e in evaluated if e.status == "blocking"]
    if blocking:
        reasons.append(f"{len(blocking)} blocking finding(s)")
    if policy.min_score is not None and score is not None and score < policy.min_score:
        reasons.append(f"score {score} is below min_score {policy.min_score}")
    if policy.max_findings:
        counted = [e for e in evaluated if e.status in {"blocking", "warning", "existing"}]
        for sev, limit in policy.max_findings.items():
            n = sum(1 for e in counted if e.finding["severity"] == sev)
            if n > limit:
                reasons.append(f"{n} {sev.lower()} finding(s) exceed max_findings.{sev.lower()}={limit}")
    return Decision(passed=not reasons, evaluated=evaluated, reasons=reasons, score=score, notes=notes)