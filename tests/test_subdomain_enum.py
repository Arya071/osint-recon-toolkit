import responses

from modules import subdomain_enum


@responses.activate
def test_dedupes_and_filters_subdomains():
    responses.add(
        responses.GET,
        "https://crt.sh/",
        json=[
            {"name_value": "www.example.com\nmail.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "unrelated.org"},
        ],
        status=200,
    )

    result = subdomain_enum.run("example.com")

    assert result["count"] == 3
    assert "www.example.com" in result["subdomains"]
    assert "mail.example.com" in result["subdomains"]
    assert "example.com" in result["subdomains"]
    assert "unrelated.org" not in result["subdomains"]


@responses.activate
def test_handles_request_failure():
    responses.add(responses.GET, "https://crt.sh/", status=500)

    result = subdomain_enum.run("example.com")

    assert "error" in result
    assert result["subdomains"] == []
