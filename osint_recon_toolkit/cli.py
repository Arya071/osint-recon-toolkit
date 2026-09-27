import argparse
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv

from .modules import (
    breach_check,
    dns_recon,
    metadata_extractor,
    security_headers,
    shodan_lookup,
    subdomain_enum,
    tech_fingerprint,
    tls_inspector,
    wayback_lookup,
    whois_lookup,
)
from .report_generator import generate
from .risk_scoring import score

REPORTS_DIR = Path.cwd() / "reports"

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("osint-recon")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive OSINT recon tool for domains/organizations. "
        "Only queries public data sources and the target's own publicly "
        "served homepage — no active scanning of target infrastructure.",
    )
    parser.add_argument("--domain", required=True, help="Target domain, e.g. example.com")
    parser.add_argument("--email", help="Email to check against known breaches (use your own for demos)")
    parser.add_argument(
        "--files",
        nargs="*",
        default=[],
        help="Local paths to images/PDFs to extract metadata from",
    )
    parser.add_argument("--skip-shodan", action="store_true", help="Skip Shodan lookup")
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = parse_args()

    log.info("Running recon on %s", args.domain)

    # Independent, network-bound modules run concurrently to cut wall-clock time.
    tasks = {
        "whois": lambda: whois_lookup.run(args.domain),
        "dns": lambda: dns_recon.run(args.domain),
        "subdomains": lambda: subdomain_enum.run(args.domain),
        "security_headers": lambda: security_headers.run(args.domain),
        "tech_fingerprint": lambda: tech_fingerprint.run(args.domain),
        "tls": lambda: tls_inspector.run(args.domain),
        "wayback": lambda: wayback_lookup.run(args.domain),
    }
    if not args.skip_shodan:
        tasks["shodan"] = lambda: shodan_lookup.run(args.domain, os.getenv("SHODAN_API_KEY"))
    else:
        tasks["shodan"] = lambda: {"skipped": "--skip-shodan flag set"}

    if args.email:
        tasks["breach"] = lambda: breach_check.run(args.email, os.getenv("HIBP_API_KEY"))
    else:
        tasks["breach"] = lambda: {"skipped": "no --email provided"}

    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in futures:
            name = futures[future]
            log.info("Waiting on module: %s", name)

        for future, name in futures.items():
            results[name] = future.result()
            log.info("Completed module: %s", name)

    if args.files:
        log.info("Extracting metadata from %d file(s)", len(args.files))
        results["metadata"] = metadata_extractor.run(args.files)
    else:
        results["metadata"] = {}

    results["risk_summary"] = score(results)

    json_path, html_path = generate(args.domain, results, REPORTS_DIR)
    log.info("JSON report: %s", json_path)
    log.info("HTML report: %s", html_path)
    log.info("Risk level: %s (%d/100)", results["risk_summary"]["level"], results["risk_summary"]["score"])


if __name__ == "__main__":
    main()
