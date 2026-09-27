import requests

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


def run(email: str, api_key: str | None) -> dict:
    """Checks a single email against known breaches via the HIBP API.

    Intended for checking your own email(s) to demonstrate breach exposure
    reporting. HIBP requires a paid API key as of 2024.
    """
    if not api_key:
        return {"skipped": "HIBP_API_KEY not set"}

    headers = {"hibp-api-key": api_key, "user-agent": "osint-recon-tool"}
    url = HIBP_URL.format(account=email)

    try:
        response = requests.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=15)
    except Exception as exc:
        return {"error": str(exc)}

    if response.status_code == 404:
        return {"breaches": [], "count": 0}
    if response.status_code != 200:
        return {"error": f"HIBP returned status {response.status_code}"}

    breaches = response.json()
    return {
        "breaches": [b.get("Name") for b in breaches],
        "count": len(breaches),
        "details": breaches,
    }
