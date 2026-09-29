# Contributing

## Development setup

Use Windows and Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\scripts\bootstrap.ps1
.\.venv\Scripts\python.exe -m pytest -q
```

## Rules

- Never commit `config/runtime.json`, `config/identities.json`, runtime databases, tokens or machine-specific paths.
- Keep built-in filesystem access project-scoped.
- Treat command execution as OS-account access, not as a filesystem sandbox.
- New mutation tools must define an authorization scope, idempotency/optimistic-concurrency behavior, bounded inputs/outputs and failure semantics.
- Third-party MCP backends must remain behind explicit allowlists.
- Add tests for every new public capability.

## Contribution license

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in this project are provided under the Apache License 2.0, consistent with Section 5 of that license.
