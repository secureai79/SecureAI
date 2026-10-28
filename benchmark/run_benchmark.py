"""Measure scanner accuracy against the labeled cases. Usage: python3 -I benchmark/run_benchmark.py [--json out.json]"""
import json, os, sys, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))
from aisafety.scan import scan_directory

SEV = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
if not os.path.isdir(os.path.join(HERE, "cases")) or not os.path.exists(os.path.join(HERE, "manifest.json")):
    import runpy
    runpy.run_path(os.path.join(HERE, "build_cases.py"))     # cases are generated, not committed
man = json.load(open(os.path.join(HERE, "manifest.json")))
tp = fn = fp = tn = 0
per = collections.defaultdict(lambda: collections.Counter())
rows = []
for name, spec in sorted(man.items()):
    res = scan_directory(os.path.join(HERE, "cases", name))
    got = [(f.get("capability"), f["severity"]) for f in res.findings if f.get("scored", True)]
    caps = {c for c, _ in got}
    for cap in spec["expect"]:
        if cap in caps or (cap == "exposed_secret" and "hardcoded_credential" in caps):
            tp += 1; per[cap]["tp"] += 1; rows.append((name, "PASS", f"found {cap}"))
        else:
            fn += 1; per[cap]["fn"] += 1; rows.append((name, "MISS", f"expected {cap}, got {sorted(caps) or 'nothing'}"))
    for item in spec["forbid"]:
        cap, _, sev = item.partition(":")
        bad = [(c, s) for c, s in got if c == cap and (not sev or SEV.index(s) >= SEV.index(sev))]
        if bad:
            fp += 1; per[cap]["fp"] += 1; rows.append((name, "FALSE+", f"flagged {bad}"))
        else:
            tn += 1; rows.append((name, "PASS", f"correctly silent on {item}"))
for r in rows:
    print(f"{r[1]:7} {r[0]:28} {r[2]}")
prec = tp / (tp + fp) if tp + fp else 0
rec = tp / (tp + fn) if tp + fn else 0
print(f"\nTP={tp} FN={fn} FP={fp} TN={tn}")
print(f"precision={prec:.0%}  recall={rec:.0%}  clean-code pass rate={tn/(tn+fp):.0%}" if tn + fp else "")
print("\nper capability:", {k: dict(v) for k, v in per.items()})
if "--json" in sys.argv:
    json.dump(dict(tp=tp, fn=fn, fp=fp, tn=tn, precision=prec, recall=rec), open(sys.argv[sys.argv.index("--json") + 1], "w"))
