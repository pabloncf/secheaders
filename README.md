# secheaders

> Scan URLs for HTTP security headers, score their posture (0–100 + letter
> grade), and get actionable fix recommendations.

`secheaders` is a fast, dependency-light CLI that inspects the HTTP response
headers of any website, grades how well it defends against common web attacks
(XSS, clickjacking, MIME sniffing, protocol downgrade…), and tells you exactly
what to fix.

## Status

🚧 **Early development.** Phase 1 (CLI skeleton) is in place; scanning,
analysis, scoring, and reporting land in the following phases.

## Installation

```bash
# from source (development)
pip install -e ".[dev]"
```

## Usage

```bash
secheaders https://example.com
```

Options:

| Flag | Description |
| --- | --- |
| `-f`, `--format` | Output format: `terminal` (default), `json`, `html`, `csv` |
| `-o`, `--output` | Write the report to a file instead of stdout |
| `-v`, `--verbose` | Show raw header values and detailed explanations |
| `--version` | Print version and exit |

You can also run it as a module:

```bash
python -m secheaders https://example.com
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT © Pablo
