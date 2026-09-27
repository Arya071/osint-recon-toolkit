import requests

MITRE_TECHNIQUE = "T1593.002 - Search Open Websites/Domains: Search Engines"

CDX_URL = "https://web.archive.org/cdx/search/cdx"


def run(domain: str) -> dict:
    """Queries the Internet Archive's Wayback Machine for historical snapshots
    of a domain — useful for spotting previously exposed pages/content that
    may no longer be linked but are still archived publicly.
    """
    try:
        response = requests.get(
            CDX_URL,
            params={
                "url": f"{domain}/*",
                "output": "json",
                "collapse": "urlkey",
                "limit": "50",
                "fl": "timestamp,original",
            },
            timeout=15,
        )
        response.raise_for_status()
        rows = response.json()
    except Exception as exc:
        return {"error": str(exc), "mitre_technique": MITRE_TECHNIQUE}

    if not rows or len(rows) < 2:
        return {"snapshot_count": 0, "snapshots": [], "mitre_technique": MITRE_TECHNIQUE}

    snapshots = [{"timestamp": row[0], "url": row[1]} for row in rows[1:]]
    return {
        "snapshot_count": len(snapshots),
        "earliest": snapshots[0]["timestamp"] if snapshots else None,
        "snapshots": snapshots[:20],
        "mitre_technique": MITRE_TECHNIQUE,
    }
