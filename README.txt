False-alarm fixes (apply AFTER secureai-guarded-label.zip)
  git apply --check false-alarm-fixes.patch
  git apply false-alarm-fixes.patch
  python benchmark/build_cases.py ; python benchmark/run_benchmark.py     (expect 32 TP, 0 FP, 66 TN)
Covers: fixed dependency/VCS tooling (uv, pip, git -C ... rev-parse), auth headers and OAuth token
endpoints, env-var names / placeholders as secrets, placeholder PEM keys, child-process terminate,
data-structure push, own-method send, LangGraph Send().
