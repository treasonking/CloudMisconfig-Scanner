# PR Summary Draft

## What changed
- Added dashboard enhancements:
  - `/dashboard` now supports `only_fail=true` filter
  - latest findings table added for quick triage
- Added documentation package for project presentation:
  - `docs/interview-notes.md`
- Existing architecture kept intact (provider -> checks -> reporters)

## Why
- Improve demo usability by letting reviewers focus on risky findings quickly.
- Prepare interview/portfolio narrative with concise technical talking points.

## Validation
- `python -m py_compile app/web.py`
- `python -m pytest -q` (all tests pass)
- FastAPI route import check includes `/dashboard`

## Impact
- Better web UX for security triage
- Better maintainability of presentation materials under version control
