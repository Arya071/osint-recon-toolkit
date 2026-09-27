import socket

import shodan

MITRE_TECHNIQUE = "T1596.005 - Search Open Technical Databases: Scan Databases"


def run(domain: str, api_key: str | None) -> dict:
    if not api_key:
        return {"skipped": "SHODAN_API_KEY not set", "mitre_technique": MITRE_TECHNIQUE}

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as exc:
        return {"error": f"could not resolve {domain}: {exc}", "mitre_technique": MITRE_TECHNIQUE}

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)
    except shodan.APIError as exc:
        return {"error": str(exc), "ip": ip, "mitre_technique": MITRE_TECHNIQUE}

    return {
        "ip": ip,
        "org": host.get("org"),
        "os": host.get("os"),
        "open_ports": host.get("ports", []),
        "vulns": sorted(host.get("vulns", [])) if host.get("vulns") else [],
        "hostnames": host.get("hostnames", []),
        "mitre_technique": MITRE_TECHNIQUE,
    }
