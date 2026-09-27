import responses

from osint_recon_toolkit.modules import security_headers


@responses.activate
def test_reports_missing_headers():
    responses.add(
        responses.GET,
        "https://example.com",
        headers={"Server": "nginx"},
        status=200,
    )

    result = security_headers.run("example.com")

    assert result["server"] == "nginx"
    assert result["score"] == "0/6"
    assert len(result["missing_headers"]) == 6
    assert result["mitre_technique"].startswith("T1592")


@responses.activate
def test_reports_present_headers():
    responses.add(
        responses.GET,
        "https://example.com",
        headers={"Strict-Transport-Security": "max-age=63072000"},
        status=200,
    )

    result = security_headers.run("example.com")

    assert "Strict-Transport-Security" in result["present_headers"]
    assert result["score"] == "1/6"


@responses.activate
def test_handles_connection_error():
    responses.add(
        responses.GET,
        "https://unreachable.invalid",
        body=ConnectionError("no route to host"),
    )

    result = security_headers.run("unreachable.invalid")

    assert "error" in result
