from unittest.mock import MagicMock, patch

import dns.resolver

from modules import dns_recon


def _answer(text):
    mock = MagicMock()
    mock.to_text.return_value = text
    return mock


@patch("modules.dns_recon.dns.resolver.resolve")
def test_collects_records_per_type(mock_resolve):
    def side_effect(domain, record_type):
        if record_type == "A":
            return [_answer("93.184.216.34")]
        if record_type == "MX":
            raise dns.resolver.NoAnswer()
        if record_type == "NS":
            raise dns.resolver.NXDOMAIN()
        return [_answer(f"{record_type}-value")]

    mock_resolve.side_effect = side_effect

    result = dns_recon.run("example.com")

    assert result["A"] == ["93.184.216.34"]
    assert result["MX"] == []
    assert result["NS"] == []
    assert result["mitre_technique"].startswith("T1590")
