# Contributing to VPS-Guard

Thanks for your interest! Here's how to contribute effectively.

## Reporting Bugs

Open an issue with:
- Go version (`go version`)
- OS version
- Config (sanitize API keys)
- Logs from `/var/log/vps-guard/agent.log`

## Pull Requests

1. Fork and clone
2. Create a branch: `git checkout -b feat/description`
3. Run tests: `make check`
4. Keep changes focused on one concern
5. Write/update tests for new code
6. Rebase on main before submitting

## Code Style

- `go vet ./...` must pass
- Tests must pass: `make test`
- No external dependencies without discussion
- Unix line endings, no BOM

## Commit Messages

```
<type>: <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`

## Documentation

Update relevant docs in `docs/` when changing behaviour:
- `AGENT-ARCHITECTURE.md` for component changes
- `AGENT-API-CONTRACT.md` for API changes
- `AGENT-SCORING.md` for scoring changes
