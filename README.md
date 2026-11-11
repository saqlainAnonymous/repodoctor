# RepoDoctor

**Diagnose. Secure. Improve.** An evidence-based command-line auditor for repository hygiene, selected security patterns, documentation, tests, and CI readiness.

[![Tests](https://github.com/saqlainAnonymous/repodoctor/actions/workflows/tests.yml/badge.svg)](https://github.com/saqlainAnonymous/repodoctor/actions/workflows/tests.yml) [![CodeQL](https://github.com/saqlainAnonymous/repodoctor/actions/workflows/codeql.yml/badge.svg)](https://github.com/saqlainAnonymous/repodoctor/actions/workflows/codeql.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Early-stage static checker: not a penetration tester, dependency vulnerability database, or guarantee of repository safety.

## Features
- Local scanning; source code is not uploaded.
- Checks README, license, project manifest, tests, and GitHub Actions presence.
- Heuristic private-key and token pattern detection; matched values are never printed.
- Terminal, Markdown, JSON, and SARIF reports.
- Optional CI failure threshold.
- No runtime dependencies; Python 3.10+.

## Install from source
```bash
git clone https://github.com/saqlainAnonymous/repodoctor.git
cd repodoctor
python -m pip install .
```

When published to PyPI, install with `python -m pip install repodoctor-cli`.

## Quick start
```bash
repodoctor scan .
repodoctor scan ./project --format markdown --output report.md
repodoctor scan . --format json --output report.json
repodoctor scan . --format sarif --output results.sarif
repodoctor scan . --fail-on high
```

## GitHub Actions
```yaml
name: Repository audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install repodoctor-cli
      - run: repodoctor scan . --format sarif --output repodoctor.sarif
```

## Rule catalog
| Rule | Severity | Check |
|---|---|---|
| RD001 | Critical | Private key marker |
| RD002 | Critical | Assignment-style token/secret pattern |
| RD003 | Critical | GitHub token pattern |
| RD100 | High | README missing |
| RD101 | Medium | License missing |
| RD102 | Low | Project manifest missing |
| RD103 | Medium | GitHub Actions workflow missing |
| RD104 | Medium | Tests missing |

Secret checks are heuristic and may produce false positives or miss credentials. Rotate any credential suspected to be exposed. Never commit real secrets.

## Development
```bash
python -m pip install -e . pytest
python -m pytest -q
```

## Privacy
Scanning is local. Reports may contain file paths and finding details; inspect them before sharing.

## Roadmap
- [x] Local repository scanner and project hygiene checks
- [x] Heuristic secret-pattern checks with redaction
- [x] Markdown, JSON, and SARIF output
- [x] CLI, unit tests, GitHub Actions CI, and CodeQL workflow
- [ ] Dependency advisory integration
- [ ] Remote GitHub repository scanning
- [ ] Safe opt-in autofix proposals
- [ ] PyPI release

## License
MIT. See [LICENSE](LICENSE).
