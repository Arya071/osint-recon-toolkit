from risk_scoring import score


def test_no_findings_is_informational():
    result = score({})
    assert result["level"] == "Informational"
    assert result["score"] == 0
    assert result["findings"] == []


def test_expiring_tls_raises_risk():
    result = score({"tls": {"expiring_soon": True, "days_remaining": 5}})
    assert result["score"] >= 15
    assert any("expires" in f for f in result["findings"])


def test_multiple_findings_reach_high():
    results = {
        "tls": {"error": "handshake failed"},
        "shodan": {"vulns": ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]},
        "breach": {"count": 3},
    }

    result = score(results)

    assert result["level"] == "High"
    assert result["score"] >= 60


def test_score_caps_at_100():
    results = {
        "tls": {"error": "bad cert"},
        "shodan": {"vulns": [f"CVE-{i}" for i in range(10)]},
        "breach": {"count": 10},
        "security_headers": {"missing_headers": [{"header": h} for h in range(6)]},
    }

    result = score(results)

    assert result["score"] == 100
