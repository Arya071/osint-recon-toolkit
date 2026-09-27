import requests

MITRE_TECHNIQUE = "T1592.002 - Gather Victim Host Information: Software"

EXPECTED_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS; missing means downgrade attacks are possible",
    "Content-Security-Policy": "Mitigates XSS/data-injection by restricting resource origins",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding",
    "Referrer-Policy": "Controls how much referrer data leaks to other sites",
    "Permissions-Policy": "Restricts access to browser features/APIs",
}


def run(domain: str) -> dict:
    """Checks a target's own homepage response headers for common security
    hardening (HSTS, CSP, etc.). Reads one page it already serves publicly —
    equivalent to opening the site in a browser and inspecting headers.
    """
    url = f"https://{domain}"
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as exc:
        return {"error": str(exc), "mitre_technique": MITRE_TECHNIQUE}

    present = {}
    missing = []
    for header, explanation in EXPECTED_HEADERS.items():
        if header in response.headers:
            present[header] = response.headers[header]
        else:
            missing.append({"header": header, "risk": explanation})

    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "unknown"),
        "present_headers": present,
        "missing_headers": missing,
        "score": f"{len(present)}/{len(EXPECTED_HEADERS)}",
        "mitre_technique": MITRE_TECHNIQUE,
    }
