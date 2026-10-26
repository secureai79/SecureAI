#!/usr/bin/env python3
"""Preview the built frontend locally WITH the headers from dist/_headers (Content-Security-Policy etc.),
so CSP problems show up on your machine instead of in production.

    python scripts/serve_dist.py dist 5500
"""
import http.server
import sys
from pathlib import Path


def load_rules(root: Path):
    rules, current = [], None
    path = root / "_headers"
    if not path.exists():
        return rules
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            current = {"pattern": line.strip(), "headers": []}
            rules.append(current)
        elif current is not None and ":" in line:
            k, v = line.strip().split(":", 1)
            current["headers"].append((k.strip(), v.strip()))
    return rules


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "dist").resolve()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5500
    rules = load_rules(root)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def end_headers(self):
            name = self.path.split("?")[0].split("#")[0]
            for rule in rules:
                pat = rule["pattern"]
                if pat == "/*" or (pat.startswith("/*.") and name.endswith(pat[2:])) or pat == name:
                    for k, v in rule["headers"]:
                        if k.lower() == "cache-control":
                            continue
                        self.send_header(k, v)
            super().end_headers()

        def log_message(self, *a):
            pass

    print(f"Serving {root} on http://127.0.0.1:{port} with {sum(len(r['headers']) for r in rules)} header rules")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
