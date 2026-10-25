import pytest
from engine.validator import validate_and_normalize_url, ValidationError, check_ip_security, is_ip_address

def test_valid_urls():
    res = validate_and_normalize_url("https://example.com/login")
    assert res["normalized_url"] == "https://example.com/login"
    assert res["hostname"] == "example.com"
    assert res["scheme"] == "https"
    assert res["is_rdap_eligible"] is True

def test_missing_scheme_auto_prefix():
    res = validate_and_normalize_url("example.org/path")
    assert res["normalized_url"] == "https://example.org/path"
    assert res["scheme"] == "https"
    assert res["hostname"] == "example.org"

def test_disallowed_schemes():
    disallowed = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<html>",
        "ftp://files.example.com",
        "gopher://gopher.example.com"
    ]
    for url in disallowed:
        with pytest.raises(ValidationError) as exc:
            validate_and_normalize_url(url)
        assert "Disallowed URL scheme" in str(exc.value) or "Unsupported URL scheme" in str(exc.value)

def test_empty_or_whitespace_urls():
    for empty in ["", "   ", None]:
        with pytest.raises(ValidationError):
            validate_and_normalize_url(empty)

def test_excessive_url_length():
    huge_url = "https://example.com/" + ("a" * 2100)
    with pytest.raises(ValidationError) as exc:
        validate_and_normalize_url(huge_url)
    assert "exceeds maximum allowed length" in str(exc.value)

def test_ip_address_detection():
    # IPv4 loopback & private
    assert is_ip_address("127.0.0.1") is True
    sec_loop = check_ip_security("127.0.0.1")
    assert sec_loop["is_loopback"] is True
    assert sec_loop["is_non_public"] is True

    # Cloud metadata IP (AWS/GCP/Azure)
    sec_meta = check_ip_security("169.254.169.254")
    assert sec_meta["is_link_local"] is True
    assert sec_meta["is_non_public"] is True

    # Private RFC 1918
    sec_priv = check_ip_security("192.168.1.1")
    assert sec_priv["is_private"] is True
    assert sec_priv["is_non_public"] is True

    # IPv6 loopback
    sec_v6 = check_ip_security("[::1]")
    assert sec_v6["is_loopback"] is True
    assert sec_v6["is_non_public"] is True

    # Public IPv4
    sec_pub = check_ip_security("8.8.8.8")
    assert sec_pub["is_ip"] is True
    assert sec_pub["is_non_public"] is False

def test_rdap_ineligibility_for_ips_and_localhost():
    res_ip = validate_and_normalize_url("http://192.168.1.50/admin")
    assert res_ip["is_rdap_eligible"] is False
    assert res_ip["ip_info"]["is_non_public"] is True

    res_local = validate_and_normalize_url("http://localhost:8000/dashboard")
    assert res_local["is_rdap_eligible"] is False
    assert res_local["is_localhost"] is True

def test_credentials_in_url():
    res = validate_and_normalize_url("https://admin:secret@malicious.com/auth")
    assert res["has_credentials"] is True
    assert res["userinfo"] == "admin:secret"
    assert res["hostname"] == "malicious.com"

def test_internationalized_domain_name():
    # IDN domain (e.g., German umlaut: münchen.de -> xn--mnchen-3ya.de)
    res = validate_and_normalize_url("https://münchen.de")
    assert res["hostname"].startswith("xn--") or res["hostname"] == "münchen.de"
