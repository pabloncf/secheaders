# secheaders

[![PyPI version](https://img.shields.io/pypi/v/secheaders.svg)](https://pypi.org/project/secheaders/)
[![Python versions](https://img.shields.io/pypi/pyversions/secheaders.svg)](https://pypi.org/project/secheaders/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Scan URLs for HTTP security headers, score their posture (0–100 + letter
> grade), and get actionable fix recommendations.

`secheaders` is a fast, dependency-light CLI that inspects the HTTP response
headers of any website, grades how well it defends against common web attacks
(XSS, clickjacking, MIME sniffing, protocol downgrade…), and tells you exactly
what to fix.

## Demo

<!-- Record with `vhs` or `asciinema` and drop the GIF here:
     vhs < demo.tape  ->  demo.gif -->
![secheaders demo](docs/demo.gif)

## Installation

```bash
pip install secheaders
```

From source (development):

```bash
pip install -e ".[dev]"
```

## Usage

```bash
secheaders https://example.com
```

Options:

| Flag | Description |
| --- | --- |
| `-i`, `--input FILE` | Scan every URL in FILE (one per line; `#` comments allowed) |
| `--concurrency N` | Max simultaneous requests in batch mode (default: 10) |
| `-f`, `--format` | Output format: `terminal` (default), `json`, `html`, `csv` |
| `-o`, `--output` | Write the report to a file instead of stdout |
| `-v`, `--verbose` | Show raw header values and the score breakdown |
| `-q`, `--quiet` | Print only the score and grade (for scripting) |
| `--fail-under SCORE` | Exit with code 1 if any score is below SCORE (for CI/CD) |
| `--timeout SECONDS` | Per-request timeout (default: 10s) |
| `--follow-redirects` / `--no-follow-redirects` | Follow redirects (default: on) |
| `--max-redirects N` | Maximum redirects to follow (default: 5) |
| `--allow-private` | Allow scanning loopback/private/local hosts |
| `--version` | Print version and exit |

### CI/CD example

```bash
# Fail the pipeline if the site scores below 80.
secheaders https://example.com --fail-under 80 --quiet

# Export a JSON report for a batch of URLs.
secheaders --input urls.txt --format json --output report.json
```

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

## License

[MIT](LICENSE) © Pablo
