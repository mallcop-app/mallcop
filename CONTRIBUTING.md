# Contributing to Mallcop

Thanks for your interest in contributing to Mallcop!

## How to contribute

1. **Open an issue first.** Before writing code, open an issue describing what you want to change and why. We'll discuss scope and approach before you invest time in a PR.

2. **Fork and branch.** Fork the repo, create a branch from `main`, and make your changes.

3. **Write tests.** All code changes require tests. See the testing requirements in `CLAUDE.md`.

4. **Run the full suite.** `pytest` must pass before you submit.

5. **Submit a PR.** Reference the issue number. Keep PRs focused — one change per PR.

## What we're looking for

- Bug fixes with reproducing test cases
- New connectors for cloud platforms (Azure, AWS, GCP, GitHub, etc.)
- New detectors for security patterns
- Documentation improvements

## What we're NOT looking for

- Large refactors without prior discussion
- Features that add external service dependencies
- Changes that break the "works offline" principle

## Development setup

```bash
pip install -e ".[dev]"
pytest
```

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.
