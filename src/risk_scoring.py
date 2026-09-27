def score(results: dict) -> dict:
    """Aggregates findings across modules into a simple weighted risk summary.

    Not a substitute for a real vulnerability assessment — a lightweight
    signal for which findings are worth following up on first.
    """
    findings = []
    points = 0

    tls = results.get("tls", {})
    if tls.get("expiring_soon"):
        findings.append(f"TLS certificate expires in {tls.get('days_remaining')} days")
        points += 15
    if tls.get("error"):
        findings.append("TLS handshake failed or certificate invalid")
        points += 20

    headers = results.get("security_headers", {})
    missing = headers.get("missing_headers", [])
    if missing:
        findings.append(f"{len(missing)} recommended security header(s) missing")
        points += min(len(missing) * 5, 25)

    shodan = results.get("shodan", {})
    vulns = shodan.get("vulns", [])
    if vulns:
        findings.append(f"{len(vulns)} known CVE(s) associated with exposed host (via Shodan)")
        points += min(len(vulns) * 10, 40)

    breach = results.get("breach", {})
    breach_count = breach.get("count", 0)
    if breach_count:
        findings.append(f"Email found in {breach_count} known breach(es)")
        points += min(breach_count * 8, 30)

    subdomains = results.get("subdomains", {})
    sub_count = subdomains.get("count", 0)
    if sub_count > 30:
        findings.append(f"Large attack surface: {sub_count} subdomains discovered")
        points += 10

    points = min(points, 100)
    if points >= 60:
        level = "High"
    elif points >= 30:
        level = "Medium"
    elif points > 0:
        level = "Low"
    else:
        level = "Informational"

    return {"level": level, "score": points, "findings": findings}
