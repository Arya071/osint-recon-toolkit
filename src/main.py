import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from modules import breach_check, dns_recon, metadata_extractor, shodan_lookup, subdomain_enum, whois_lookup
from report_generator import generate

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive OSINT recon tool for domains/organizations. "
        "Only queries public data sources (WHOIS, DNS, certificate transparency, "
        "Shodan, HIBP) — no active scanning of target infrastructure.",
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

    print(f"[*] Running recon on {args.domain}")

    results = {}

    print("[*] WHOIS lookup...")
    results["whois"] = whois_lookup.run(args.domain)

    print("[*] DNS record enumeration...")
    results["dns"] = dns_recon.run(args.domain)

    print("[*] Subdomain enumeration (crt.sh)...")
    results["subdomains"] = subdomain_enum.run(args.domain)

    if args.skip_shodan:
        results["shodan"] = {"skipped": "--skip-shodan flag set"}
    else:
        print("[*] Shodan host lookup...")
        results["shodan"] = shodan_lookup.run(args.domain, os.getenv("SHODAN_API_KEY"))

    if args.email:
        print(f"[*] Breach exposure check for {args.email}...")
        results["breach"] = breach_check.run(args.email, os.getenv("HIBP_API_KEY"))
    else:
        results["breach"] = {"skipped": "no --email provided"}

    if args.files:
        print(f"[*] Extracting metadata from {len(args.files)} file(s)...")
        results["metadata"] = metadata_extractor.run(args.files)
    else:
        results["metadata"] = {}

    json_path, html_path = generate(args.domain, results, REPORTS_DIR)
    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")


if __name__ == "__main__":
    main()
