import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def run(domain: str) -> dict:
    results = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[record_type] = []
        except Exception as exc:
            results[record_type] = [f"error: {exc}"]
    return results
