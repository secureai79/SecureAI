Report-noise fixes (apply AFTER guarded-label and false-alarm-fixes)
  git apply --check report-noise-fixes.patch
  git apply report-noise-fixes.patch
  python benchmark/build_cases.py ; python benchmark/run_benchmark.py     (expect 32 TP, 0 FP, 70 TN)
1) Frontend UI files (.tsx/.jsx/.vue/.svelte, /frontend/, /components/) with no AI SDK no longer produce
   keyword findings (truncateText -> "TRUNCATE", removeToken -> "REMOVE", eraseCookie -> "ERASE").
2) An if/else that returns the same code executor twice is one finding, not two.
