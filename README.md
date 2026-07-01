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

## License

MIT © Pablo
