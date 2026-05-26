# Tools: Lesson 15

## New Tools

### AGPLv3 License

The GNU Affero General Public License v3. Key points:
- You can use it for anything (personal, commercial, enterprise)
- If you modify it, you must release your modifications
- If you run it as a network service, you must offer source code
- It's **not** legal advice — consult a lawyer for your specific case

### GitHub Actions

Free CI/CD for public repositories.

```yaml
on:
  push:
    branches: [main]     # runs on every push to main
    tags: ['v*']         # runs on every version tag
  pull_request:
    branches: [main]     # runs on every PR to main
```

### GitHub Releases

Automated binary distribution:

```bash
# Download latest release
wget https://github.com/vpsik-lab/vpsGuard/releases/latest/download/vpsGuard-linux-amd64

# Download with checksum verification
wget https://github.com/vpsik-lab/vpsGuard/releases/latest/download/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

## Reference: Project Health

| Metric | Value |
|--------|-------|
| Test files | 20 |
| Test functions | 146 |
| Packages | 12 (all pass) |
| Build targets | linux/amd64, arm64, arm |
| License | AGPLv3 |
| CI | GitHub Actions (vet + test + race + build) |
