import re
NETWORK_SINK = re.compile(r"(?i)\b(?:requests\.(?:get|post)|fetch\s*\()")
SENSITIVE = re.compile(r"(?i)\b(?:password|secret|api[_-]?key)\b")
