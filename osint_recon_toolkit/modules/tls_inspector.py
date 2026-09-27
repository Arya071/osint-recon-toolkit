import socket
import ssl
from datetime import UTC, datetime

MITRE_TECHNIQUE = "T1596.003 - Search Open Technical Databases: Digital Certificates"


def run(domain: str, port: int = 443) -> dict:
    """Inspects the TLS certificate a domain presents on connect: issuer,
    validity window, SANs, and negotiated protocol version. A standard TLS
    handshake — the same one any browser performs when visiting the site.
    """
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((domain, port), timeout=10) as sock,
            context.wrap_socket(sock, server_hostname=domain) as tls_sock,
        ):
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
    except Exception as exc:
        return {"error": str(exc), "mitre_technique": MITRE_TECHNIQUE}

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    days_remaining = (not_after - datetime.now(UTC)).days

    sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
    issuer = dict(x[0] for x in cert.get("issuer", []))

    return {
        "issuer": issuer.get("organizationName", str(issuer)),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expiring_soon": days_remaining < 30,
        "protocol": protocol,
        "subject_alt_names": sans,
        "mitre_technique": MITRE_TECHNIQUE,
    }
