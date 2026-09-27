# OSINT Recon Toolkit

A passive OSINT reconnaissance tool that aggregates public information about a
**domain or organization** into a single risk-scored report — the same kind
of recon a penetration tester or red teamer performs in the reconnaissance
phase of an engagement.

## What it does

| Module | Source | What it gathers | MITRE ATT&CK |
|---|---|---|---|
| WHOIS | WHOIS registries | Registrar, creation/expiry dates, org, name servers | T1596.002 |
| DNS recon | Public DNS | A/AAAA/MX/NS/TXT/SOA/CNAME records | T1590.002 |
| Subdomain enumeration | [crt.sh](https://crt.sh) certificate transparency logs | Subdomains seen in issued TLS certificates | T1596.003 |
| Security headers | Target's own homepage | Missing HSTS/CSP/X-Frame-Options/etc. | T1592.002 |
| Technology fingerprint | Target's own homepage | Server, CMS/framework signatures | T1592.002 |
| TLS certificate inspection | TLS handshake | Issuer, expiry, protocol version, SANs | T1596.003 |
| Wayback Machine history | [web.archive.org](https://web.archive.org) | Historical snapshots of the domain | T1593.002 |
| Shodan host lookup | [Shodan](https://www.shodan.io) API | Open ports, services, known CVEs on the resolved IP | T1596.005 |
| Breach exposure | [Have I Been Pwned](https://haveibeenpwned.com) API | Known breaches for a given email | T1589.001 |
| Metadata extraction | Local files you supply | EXIF (images) / document info (PDFs) | — |

Every finding is tagged with the [MITRE ATT&CK](https://attack.mitre.org/)
reconnaissance technique it maps to, and a **risk-scoring module**
(`osint_recon_toolkit/risk_scoring.py`) aggregates findings (expiring/broken
TLS, missing security headers, known CVEs, breach exposure, large subdomain
footprint) into a Low/Medium/High summary at the top of every report.

Everything is passive: it only reads public data sources and the target's
own publicly served homepage — no port scanning, no active probing.

## Engineering notes

- **Concurrent execution** — independent network-bound modules run in a
  thread pool (`concurrent.futures.ThreadPoolExecutor`) rather than
  sequentially.
- **Tests** — 15 unit tests (`pytest`) covering every module's happy path and
  failure handling, with HTTP calls mocked via `responses` (no real network
  access needed to run the suite).
- **CI** — GitHub Actions runs lint (`ruff`) and the test suite on every push.
- **Docker** — `Dockerfile` for running the tool without a local Python setup.

## Scope and ethics

- **Use this only against domains/organizations you own or are authorized to
  test.** Recon on a domain you don't control without permission may violate
  its terms of service or the law, even though every data source here is
  public.
- The breach-check and metadata modules are demoed against your own
  email/files by design — they are not built to profile private individuals.
- API keys (Shodan, HIBP) are read from a local `.env` file and are never
  committed.

## Install

One-line install straight from GitHub, no cloning required. [pipx](https://pipx.pypa.io)
is recommended — it installs the CLI into its own isolated environment so it
doesn't clash with other Python projects:

```bash
pipx install git+https://github.com/Arya071/osint-recon-toolkit.git
```

No pipx? Plain pip works too:

```bash
pip install git+https://github.com/Arya071/osint-recon-toolkit.git
```

Either way, you now have an `osint-recon` command on your PATH.

(Optional) Add API keys for the Shodan/HIBP modules — create a `.env` file in
whatever directory you run the tool from:

```
SHODAN_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
```

## Usage

```bash
osint-recon --domain example.com
osint-recon --domain example.com --email you@example.com
osint-recon --domain example.com --files photo.jpg doc.pdf
osint-recon --domain example.com --skip-shodan
```

Reports are written to `reports/` (in your current directory) as both JSON
and a styled HTML file, with a risk-level banner at the top.

### Docker

```bash
docker build -t osint-recon-toolkit .
docker run --rm -v "$(pwd)/reports:/data/reports" osint-recon-toolkit --domain example.com
```

### Developing / running tests

```bash
git clone https://github.com/Arya071/osint-recon-toolkit.git
cd osint-recon-toolkit
pip install -e .
pip install -r requirements-dev.txt
pytest tests/ -v
ruff check osint_recon_toolkit tests
```

## Why this project

Recon is the first phase of any real security assessment or red-team
engagement. This tool consolidates recon techniques (WHOIS, DNS, certificate
transparency, header/tech fingerprinting, TLS inspection, historical content
discovery, exposed-service lookup, breach exposure) that are normally run as
separate manual steps into one repeatable, risk-scored report — mapped to
MITRE ATT&CK so findings tie back to a recognized framework, and tested/CI'd
like production code rather than a one-off script.

## Roadmap ideas

- Export findings directly into a ticketing/SIEM format
- Add async I/O instead of threads for higher module concurrency
- PDF report export
