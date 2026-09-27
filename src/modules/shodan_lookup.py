import socket

import shodan


def run(domain: str, api_key: str | None) -> dict:
    if not api_key:
        return {"skipped": "SHODAN_API_KEY not set"}

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as exc:
        return {"error": f"could not resolve {domain}: {exc}"}

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)
    except shodan.APIError as exc:
        return {"error": str(exc), "ip": ip}

    return {
        "ip": ip,
        "org": host.get("org"),
        "os": host.get("os"),
        "open_ports": host.get("ports", []),
        "vulns": sorted(host.get("vulns", [])) if host.get("vulns") else [],
        "hostnames": host.get("hostnames", []),
    }
