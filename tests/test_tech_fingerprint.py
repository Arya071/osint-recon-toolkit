import responses

from modules import tech_fingerprint


@responses.activate
def test_detects_wordpress():
    responses.add(
        responses.GET,
        "https://example.com",
        body='<html><head><meta name="generator" content="WordPress 6.4"></head></html>',
        status=200,
    )

    result = tech_fingerprint.run("example.com")

    assert "WordPress" in result["detected_technologies"]


@responses.activate
def test_no_known_signatures():
    responses.add(
        responses.GET,
        "https://example.com",
        body="<html><body>plain static site</body></html>",
        status=200,
    )

    result = tech_fingerprint.run("example.com")

    assert result["detected_technologies"] == ["none matched known signatures"]
