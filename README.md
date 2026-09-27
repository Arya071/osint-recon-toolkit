# OSINT Recon Tool

A passive OSINT reconnaissance tool that aggregates public information about a
**domain or organization** into a single report — the same kind of recon a
penetration tester or red teamer performs before an engagement in the
reconnaissance phase.

## What it does

| Module | Source | What it gathers |
|---|---|---|
| WHOIS | WHOIS registries | Registrar, creation/expiry dates, org, name servers |
| DNS recon | Public DNS | A/AAAA/MX/NS/TXT/SOA/CNAME records |
| Subdomain enumeration | [crt.sh](https://crt.sh) certificate transparency logs | Subdomains seen in issued TLS certificates |
| Shodan host lookup | [Shodan](https://www.shodan.io) API | Open ports, services, known CVEs on the resolved IP |
| Breach exposure | [Have I Been Pwned](https://haveibeenpwned.com) API | Known breaches for a given email |
| Metadata extraction | Local files you supply | EXIF (images) / document info (PDFs) |

Everything is passive: it only reads public data sources and never sends
traffic to the target's own infrastructure (no port scanning, no active
probing).

## Scope and ethics

- **Use this only against domains/organizations you own or are authorized to
  test.** Recon on a domain you don't control without permission may violate
  its terms of service or the law, even though every data source here is
  public.
- The breach-check and metadata modules are demoed against your own
  email/files by design — they are not built to profile private individuals.
- API keys (Shodan, HIBP) are read from a local `.env` file and are never
  committed.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in SHODAN_API_KEY / HIBP_API_KEY (optional)
```

## Usage

```bash
python src/main.py --domain example.com
python src/main.py --domain example.com --email you@example.com
python src/main.py --domain example.com --files photo.jpg doc.pdf
python src/main.py --domain example.com --skip-shodan
```

Reports are written to `reports/` as both JSON and a styled HTML file.

## Why this project

Recon is the first phase of any real security assessment or red-team
engagement. This tool consolidates several recon techniques (WHOIS, DNS,
certificate transparency, exposed-service lookup, breach exposure) that are
normally run as separate manual steps into one repeatable report — the same
workflow tools like `theHarvester` and `Recon-ng` are built around, scoped
down to something small enough to read end-to-end in an afternoon.

## Roadmap ideas

- Feed subdomain/Shodan findings into a vulnerability-scoring pass
- Export findings directly into a ticketing/SIEM format
- Add Wayback Machine lookups for historical exposed content
