import dns.resolver

MITRE_TECHNIQUE = "T1590.002 - Gather Victim Network Information: DNS"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def run(domain: str) -> dict:
    records = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[record_type] = []
        except Exception as exc:
            records[record_type] = [f"error: {exc}"]
    records["mitre_technique"] = MITRE_TECHNIQUE
    return records
