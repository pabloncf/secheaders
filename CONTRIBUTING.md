# Contributing to secheaders

Thanks for your interest in improving secheaders! This is a security tool, so
contributions are held to a high bar for correctness and safety.

## Development setup

```bash
git clone https://github.com/pabloncf/secheaders
cd secheaders
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks

```bash
pytest                 # tests with coverage
ruff check .           # lint
ruff format .          # format (use --check in CI)
```

All of the above must pass before a change is merged. Tests never make real
network calls — HTTP is mocked with `respx`.

## Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`.

## Pull request checklist

- [ ] Tests added or updated for the change (happy path **and** error paths)
- [ ] `pytest`, `ruff check`, and `ruff format --check` pass
- [ ] Public functions have type hints and Google-style docstrings
- [ ] No secrets, tokens, or real network calls in code or tests
- [ ] README updated if the public CLI changed

## Security

If you find a security issue, please do not open a public issue. Email the
maintainer instead.
