import responses

from modules import breach_check


def test_skips_without_api_key():
    result = breach_check.run("test@example.com", None)
    assert result["skipped"] == "HIBP_API_KEY not set"


@responses.activate
def test_no_breaches_found():
    responses.add(
        responses.GET,
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
        status=404,
    )

    result = breach_check.run("test@example.com", "fake-key")

    assert result["count"] == 0
    assert result["breaches"] == []


@responses.activate
def test_breaches_found():
    responses.add(
        responses.GET,
        "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
        json=[{"Name": "ExampleBreach"}, {"Name": "AnotherBreach"}],
        status=200,
    )

    result = breach_check.run("test@example.com", "fake-key")

    assert result["count"] == 2
    assert "ExampleBreach" in result["breaches"]
