import requests

CRT_SH_URL = "https://crt.sh/"


def run(domain: str) -> dict:
    """Passive subdomain enumeration via certificate transparency logs (crt.sh).

    Passive-only: reads public CT log data, never touches the target's own
    infrastructure.
    """
    try:
        response = requests.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=15,
        )
        response.raise_for_status()
        entries = response.json()
    except Exception as exc:
        return {"error": str(exc), "subdomains": []}

    subdomains = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name and name.endswith(domain):
                subdomains.add(name)

    return {"subdomains": sorted(subdomains), "count": len(subdomains)}
