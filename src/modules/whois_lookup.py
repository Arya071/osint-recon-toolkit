import whois


def run(domain: str) -> dict:
    try:
        data = whois.whois(domain)
    except Exception as exc:
        return {"error": str(exc)}

    return {
        "registrar": _stringify(data.get("registrar")),
        "creation_date": _stringify(data.get("creation_date")),
        "expiration_date": _stringify(data.get("expiration_date")),
        "name_servers": _stringify(data.get("name_servers")),
        "org": _stringify(data.get("org")),
        "country": _stringify(data.get("country")),
    }


def _stringify(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value) if value is not None else None
