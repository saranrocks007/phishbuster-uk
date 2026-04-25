# Contributing to PhishBuster UK

Thanks for considering a contribution. PhishBuster UK is an open-source SOC tool, and contributions of all sizes are welcome — from typo fixes to whole new detector modules.

## Quick start

```bash
git clone https://github.com/saranrocks007/phishbuster-uk.git
cd phishbuster-uk
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/train_model.py
python scripts/setup_db.py
pytest tests/ -v
```

You should see all tests pass before making changes.

## What to work on

Good first issues are tagged [`good first issue`](https://github.com/saranrocks007/phishbuster-uk/issues?q=is:issue+is:open+label:%22good+first+issue%22). Some specific areas that always need help:

- **Additional UK brands** in `config/uk_brands.yaml` (with verified legitimate domains)
- **YARA rules** in `config/yara/` for emerging campaign patterns
- **New threat-intel integrations** (CIRCL Hashlookup, MalwareBazaar, AlienVault OTX...)
- **New ticketing backends** in `src/response/__init__.py` (Zendesk, Freshdesk, Linear)
- **Documentation improvements** — runbook scenarios, deployment guides

## Adding a new detector

1. Drop a file in `src/analysis/` exposing a class with an `analyse(email: ParsedEmail) -> tuple[list[DetectionFinding], list[IOC]]` method.
2. Register it in `src/analysis/__init__.py` (`AnalysisEngine.__init__` + `analyse()`).
3. Add weight constants to `config/detection_rules.yaml` under `scoring.weights`.
4. Add `ENABLE_*` env var to `.env.example` if the detector should be opt-in.
5. Write tests in `tests/test_pipeline.py` — at minimum a positive case, a negative case, and a "disabled returns empty" case.

## Code style

- Python 3.11+ syntax permitted (pattern matching, union `X | Y` types).
- Run `ruff check src/ scripts/ tests/ --select E,F,W,I --ignore E501` before pushing.
- Type hints encouraged on public APIs.
- Docstrings: module-level explains the *why*, function-level explains the *what*.

## Pull request checklist

- [ ] All tests pass locally (`pytest tests/`)
- [ ] New tests added for new behaviour
- [ ] Updated `docs/` if user-facing
- [ ] Updated `.env.example` if new config introduced
- [ ] No secrets, API keys, or personal data in the diff

## Commit messages

Conventional Commits style preferred but not enforced:

```
feat(detector): add MalwareBazaar hash lookup
fix(dashboard): correct MTTR calculation for unresponded incidents
docs(runbook): add quishing campaign response procedure
```

## Reporting bugs / security issues

- General bugs: GitHub Issues (template provided)
- Security vulnerabilities: see `SECURITY.md` — **don't open public issues for these**

## Licensing

By contributing, you agree your contributions will be licensed under the project's Apache 2.0 license.
