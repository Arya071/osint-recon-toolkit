import re

import requests

MITRE_TECHNIQUE = "T1592.002 - Gather Victim Host Information: Software"

CMS_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Drupal": [r"Drupal.settings", r'name="generator" content="Drupal'],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "Shopify": [r"cdn.shopify.com", r"Shopify.theme"],
    "Wix": [r"static.wixstatic.com"],
    "Squarespace": [r"static1.squarespace.com"],
    "Next.js": [r"__NEXT_DATA__"],
    "React": [r"__react", r"react-root"],
}


def run(domain: str) -> dict:
    """Fingerprints server software and CMS/framework from a target's own
    publicly served homepage (headers + HTML markers) — the same information
    visible to any visitor via view-source.
    """
    url = f"https://{domain}"
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as exc:
        return {"error": str(exc), "mitre_technique": MITRE_TECHNIQUE}

    body = response.text
    detected = [name for name, patterns in CMS_SIGNATURES.items() if any(re.search(p, body, re.IGNORECASE) for p in patterns)]

    return {
        "server_header": response.headers.get("Server", "unknown"),
        "powered_by": response.headers.get("X-Powered-By", "unknown"),
        "detected_technologies": detected or ["none matched known signatures"],
        "mitre_technique": MITRE_TECHNIQUE,
    }
