# Contributing to mallcop

Thanks for your interest in contributing to mallcop!

## How to contribute

1. **Open an issue first.** Before writing code, open an issue describing what
   you want to change and why. We'll discuss scope and approach before you
   invest time in a PR.

2. **Fork and branch.** Fork the repo, create a branch from `main`, and make
   your changes.

3. **Write tests.** All code changes require tests.

4. **Run the full suite.** `go test ./...` must pass before you submit.

5. **Submit a PR.** Reference the issue number. Keep PRs focused — one change
   per PR.

## What we're looking for

- Bug fixes with reproducing test cases
- New detectors for security patterns
- Performance improvements with benchmark evidence
- Documentation improvements

## What we're NOT looking for

- Large refactors without prior discussion
- Features that add heavy external dependencies
- Changes that break the "works offline" principle

## Development setup

Requires Go 1.22 or later.

```bash
git clone https://github.com/mallcop-app/mallcop
cd mallcop
go test ./...
```

Build all binaries:

```bash
go build ./cmd/...
```

Run a specific package's tests:

```bash
go test ./pkg/finding/...
go test ./internal/exam/...
```

## Branch conventions

- `main` — stable, always green
- Feature branches: `feat/<short-description>`
- Bug fixes: `fix/<short-description>`
- Chores: `chore/<short-description>`

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold this code.
