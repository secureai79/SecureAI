# Central capability registry. Keep provider-specific aliases in the language
# adapters and normalize them to these stable operations.
CAPABILITIES = {
    "refund": {"category": "FINANCIAL", "severity": "HIGH"},
    "charge": {"category": "FINANCIAL", "severity": "HIGH"},
    "transfer": {"category": "FINANCIAL", "severity": "HIGH"},
    "payout": {"category": "FINANCIAL", "severity": "HIGH"},
    "delete": {"category": "DATA", "severity": "CRITICAL"},
    "drop": {"category": "DATA", "severity": "CRITICAL"},
    "truncate": {"category": "DATA", "severity": "CRITICAL"},
    "export": {"category": "DATA", "severity": "MEDIUM"},
    "update": {"category": "DATA", "severity": "MEDIUM"},
    "send": {"category": "COMMUNICATION", "severity": "MEDIUM"},
    "execute": {"category": "INFRASTRUCTURE", "severity": "HIGH"},
    "shell execution": {"category": "INFRASTRUCTURE", "severity": "HIGH"},
    "deploy": {"category": "INFRASTRUCTURE", "severity": "MEDIUM"},
    "terminate": {"category": "INFRASTRUCTURE", "severity": "HIGH"},
    "merge": {"category": "CODE", "severity": "LOW"},
    "push": {"category": "CODE", "severity": "LOW"},
}
