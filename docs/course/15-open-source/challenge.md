# Challenge: Open Source

---

## ⭐ Level 1: Make Your First Contribution

1. Star the repository: https://github.com/vpsik-lab/vpsGuard
2. Read `CONTRIBUTING.md`
3. Find a typo in the docs and submit a PR
4. Or: run the agent on your VPS and open an issue with your experience

**Task:** The easiest first contribution is documentation. Find one unclear sentence and fix it.

---

## ⭐⭐ Level 2: Write a Test for an Untested Edge Case

Look at `internal/engine/decision.go` — find a code path without test coverage:

```go
// Is there an edge case not covered?
// What if scores.FinalScore is exactly equal to blockThreshold?
```

Write a test for it.

**Hint:** Use `git checkout lesson-15-open-source` and then check `internal/engine/decision_test.go` for existing test coverage.

---

## ⭐⭐⭐ Level 3: Set Up Your Own Release Pipeline

Fork the repository and set up GitHub Actions to build and release your own fork:

1. Fork → fork's Actions tab → enable
2. Push a tag: `git tag v0.1.0-myfork && git push origin v0.1.0-myfork`
3. Watch the release workflow create binaries
4. Install from your fork: `curl -sSL https://raw.githubusercontent.com/YOUR_USER/vpsGuard/main/deploy/install.sh | bash`

**Hint:** The release workflow needs `contents: write` permission (already in `.github/workflows/release.yml`).

---

## Solution

<details>
<summary>Click for Level 2 solution idea</summary>

An edge case: what happens when `scores.FinalScore == blockThreshold`?

```go
case scores.FinalScore >= blockThreshold:
    // This handles the boundary correctly (>= not >)
    // But what about central feed override when score is below threshold?
    // The code checks CentralScore >= CentralBlockThreshold ONLY if
    // len(actions) == 0 — so it's a fallback, not an override.
    // Consider: should a high CentralScore override a low FinalScore?
```

This is a design question, not a bug. But documenting it in a test helps future maintainers.
</details>
