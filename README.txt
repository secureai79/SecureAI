Guarded-label update
  git apply --check guarded-label.patch
  git apply guarded-label.patch
  cd backend; python -m pytest -q test_scanner_regressions.py
Adds a "Controls:" line to the PDF/markdown report for each action finding:
Guarded / Partly guarded / Not guarded (from approval + limit detection).
