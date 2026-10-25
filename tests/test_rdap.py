import pytest
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from engine.rdap import RDAPAnalyzer, analyze_domain_intel
from services.rdap_service import (
    fetch_rdap_info,
    is_prohibited_ip,
    is_allowed_rdap_host,
    validate_rdap_destination,
    resolve_hostname_ips,
    SSRFSafeTransport,
    SSRFSafeBackend,
)

@pytest.fixture(autouse=True)
def mock_dns_resolution(monkeypatch):
    """Ensure tests never hit live DNS and return safe mock IP for allowed hosts."""
    def fake_getaddrinfo(hostname, port, *args, **kwargs):
        h = str(hostname).lower().strip(".")
        if "unresolvable" in h:
            raise socket.gaierror(-2, "Name or service not known")
        if h in ("localhost", "127.0.0.1", "127.0.0.1.nip.io", "localtest.me") or h.endswith(".localhost"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        if "private" in h or h == "metadata.internal" or "rebinding" in h or "internal" in h:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 443))]
        if "link-local" in h:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        if "v6-mapped-private" in h:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:192.168.1.1", 443, 0, 0))]
        if "v6-loopback" in h:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)

def test_rdap_analyzer_established_domain():
    # Domain registered 5 years ago
    past_date = (datetime.now(timezone.utc) - timedelta(days=1825)).strftime("%Y-%m-%dT00:00:00Z")
    future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00Z")
    
    mock_payload = {
        "events": [
            {"eventAction": "registration", "eventDate": past_date},
            {"eventAction": "expiration", "eventDate": future_date}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]
            }
        ]
    }

    res = analyze_domain_intel("example.com", mock_payload)
    assert res["score_addition"] == 0
    assert res["intelligence"].available is True
    assert res["intelligence"].registrar == "MarkMonitor Inc."
    assert "DAYS" in res["intelligence"].age

def test_rdap_analyzer_critically_young_domain():
    # Domain registered 10 days ago (< 30 days)
    young_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT00:00:00Z")
    mock_payload = {
        "events": [
            {"eventAction": "registration", "eventDate": young_date}
        ],
        "entities": []
    }

    res = analyze_domain_intel("brand-new-site.xyz", mock_payload)
    assert res["score_addition"] >= 35
    assert any("Critically young domain" in ind for ind in res["indicators"])

def test_rdap_analyzer_moderately_young_domain():
    # Domain registered 60 days ago (< 90 days)
    mid_young_date = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT00:00:00Z")
    mock_payload = {
        "events": [
            {"eventAction": "registration", "eventDate": mid_young_date}
        ],
        "entities": []
    }

    res = analyze_domain_intel("recent-site.com", mock_payload)
    assert res["score_addition"] >= 25
    assert any("Newly registered domain" in ind for ind in res["indicators"])

def test_rdap_analyzer_error_and_not_found():
    res_not_found = analyze_domain_intel("fake-domain.xyz", {"error": "Domain not found in RDAP registry"})
    assert res_not_found["score_addition"] >= 15
    assert any("not found in RDAP" in ind for ind in res_not_found["indicators"])

    res_timeout = analyze_domain_intel("timedout.com", {"error": "RDAP lookup timed out"})
    assert any("unavailable" in ind.lower() for ind in res_timeout["indicators"])

@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_ip_and_invalid_domain():
    # Should reject IP without network request
    res_ip = await fetch_rdap_info("192.168.1.1")
    assert "error" in res_ip
    assert "not supported for IP addresses" in res_ip["error"]

    # Should reject path traversal attempt
    res_path = await fetch_rdap_info("../etc/passwd")
    assert "error" in res_path
    assert "Invalid domain format" in res_path["error"]

@pytest.mark.asyncio
async def test_fetch_rdap_info_invalid_parameters():
    # Rejects None, empty string, and non-string types
    for invalid in [None, "", 12345, []]:
        res = await fetch_rdap_info(invalid)
        assert res == {"error": "Invalid domain parameter"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_success_direct():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    payload = {"handle": "EXAMPLE-COM", "status": ["active"]}
    with patch("services.rdap_service.RDAP_BASE_URL", "https://rdap.org/domain"), \
         patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(200, json=payload, request=req)

        res = await fetch_rdap_info("example.com")
        assert res == payload
        client.get.assert_awaited_once_with("https://rdap.org/domain/example.com", follow_redirects=False)

@pytest.mark.asyncio
async def test_fetch_rdap_info_http_timeout():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.side_effect = httpx.TimeoutException("Read timed out", request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "RDAP lookup timed out"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_connection_failure():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.side_effect = httpx.ConnectError("Connection refused", request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Network error reaching RDAP service"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_non_404_http_error():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(500, request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "RDAP HTTP 500"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_http_404():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(404, request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Domain not found in RDAP registry"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_unexpected_exception():
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.side_effect = RuntimeError("Internal system malfunction")

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Unexpected RDAP processing error"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_malformed_response():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(200, content=b"invalid-json-body", request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Unexpected RDAP processing error"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_redirect_limit_exceeded():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https://authoritative.rdap.org/domain/example.com"},
            request=req
        )

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Redirect limit exceeded"}
        # Initial request + 3 redirected requests = 4 calls total
        assert client.get.call_count == 4


@pytest.mark.asyncio
async def test_fetch_rdap_info_redirect_missing_location():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(302, headers={}, request=req)

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Redirect limit exceeded"}
        assert client.get.call_count == 1

@pytest.mark.asyncio
async def test_fetch_rdap_info_redirect_non_https():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(
            301,
            headers={"Location": "http://insecure.rdap.org/domain/example.com"},
            request=req
        )

        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Insecure redirect rejected"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_redirect_prohibited_destination():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client

        # Redirect to localhost
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https://localhost/domain/example.com"},
            request=req
        )
        res_local = await fetch_rdap_info("example.com")
        assert res_local == {"error": "Prohibited redirect destination"}

        # Redirect to private IP (192.168.1.50)
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https://192.168.1.50/domain/example.com"},
            request=req
        )
        res_private = await fetch_rdap_info("example.com")
        assert res_private == {"error": "Prohibited redirect destination"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_valid_redirect_success():
    req1 = httpx.Request("GET", "https://rdap.org/domain/example.com")
    req2 = httpx.Request("GET", "https://authoritative.rdap.org/domain/example.com")
    payload = {"handle": "AUTH-123", "status": ["active"]}

    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        resp_redirect = httpx.Response(
            302,
            headers={"Location": "https://authoritative.rdap.org/domain/example.com"},
            request=req1
        )
        resp_success = httpx.Response(200, json=payload, request=req2)
        client.get.side_effect = [resp_redirect, resp_success]

        res = await fetch_rdap_info("example.com")
        assert res == payload
        assert client.get.call_count == 2

def test_is_prohibited_ip_unit():
    # Loopback
    assert is_prohibited_ip("127.0.0.1") is True
    assert is_prohibited_ip("::1") is True
    assert is_prohibited_ip("::ffff:127.0.0.1") is True

    # RFC 1918 Private
    assert is_prohibited_ip("10.0.0.1") is True
    assert is_prohibited_ip("172.16.0.1") is True
    assert is_prohibited_ip("192.168.1.1") is True
    assert is_prohibited_ip("::ffff:192.168.1.1") is True
    assert is_prohibited_ip("::ffff:10.0.0.1") is True

    # Link-local
    assert is_prohibited_ip("169.254.169.254") is True
    assert is_prohibited_ip("fe80::1") is True
    assert is_prohibited_ip("::ffff:169.254.169.254") is True

    # RFC 6598 Shared Address Space (Carrier-Grade NAT)
    assert is_prohibited_ip("100.64.0.1") is True
    assert is_prohibited_ip("100.127.255.254") is True
    assert is_prohibited_ip("::ffff:100.64.0.1") is True

    # RFC 5737 Documentation Ranges
    assert is_prohibited_ip("192.0.2.1") is True       # TEST-NET-1
    assert is_prohibited_ip("198.51.100.1") is True    # TEST-NET-2
    assert is_prohibited_ip("203.0.113.1") is True     # TEST-NET-3
    assert is_prohibited_ip("2001:db8::1") is True     # IPv6 Documentation

    # RFC 2544 Benchmarking
    assert is_prohibited_ip("198.18.0.1") is True
    assert is_prohibited_ip("198.19.255.254") is True

    # Unspecified, Broadcast & Reserved
    assert is_prohibited_ip("0.0.0.0") is True
    assert is_prohibited_ip("::") is True
    assert is_prohibited_ip("255.255.255.255") is True
    assert is_prohibited_ip("100::1") is True          # Discard-only prefix
    assert is_prohibited_ip("fc00::1") is True         # Unique Local Address (ULA)

    # Valid Public Routable IPs
    assert is_prohibited_ip("8.8.8.8") is False
    assert is_prohibited_ip("1.1.1.1") is False
    assert is_prohibited_ip("93.184.216.34") is False
    assert is_prohibited_ip("2606:2800:220:1:248:1893:25c8:1946") is False

def test_is_allowed_rdap_host_unit():
    patterns = ["rdap.org", "*.rdap.org", "*.arin.net"]
    assert is_allowed_rdap_host("rdap.org", patterns) is True
    assert is_allowed_rdap_host("authoritative.rdap.org", patterns) is True
    assert is_allowed_rdap_host("whois.arin.net", patterns) is True
    assert is_allowed_rdap_host("evil.attacker.com", patterns) is False
    assert is_allowed_rdap_host("127.0.0.1.nip.io", patterns) is False
    # Fail closed on empty/None
    assert is_allowed_rdap_host("rdap.org", None) is False
    assert is_allowed_rdap_host("rdap.org", []) is False
    # Reject wildcard '*'
    assert is_allowed_rdap_host("evil.com", ["*"]) is False
    assert is_allowed_rdap_host("evil.com", ["*", "rdap.org"]) is False


@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_literal_prohibited_ips():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    prohibited_destinations = [
        "https://127.0.0.1/domain/example.com",
        "https://10.0.0.1/domain/example.com",
        "https://172.16.0.1/domain/example.com",
        "https://192.168.1.1/domain/example.com",
        "https://169.254.169.254/domain/example.com",
        "https://0.0.0.0/domain/example.com",
        "https://[::1]/domain/example.com",
        "https://[fe80::1]/domain/example.com",
        "https://[::ffff:127.0.0.1]/domain/example.com",
        "https://[::ffff:169.254.169.254]/domain/example.com",
        "https://[::ffff:192.168.1.1]/domain/example.com",
    ]
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client

        for dest in prohibited_destinations:
            client.get.return_value = httpx.Response(302, headers={"Location": dest}, request=req)
            res = await fetch_rdap_info("example.com")
            assert res == {"error": "Prohibited redirect destination"}, f"Failed for {dest}"

@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_hostname_resolving_to_private_ip():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client

        # Allowed domain that resolves to private IP (DNS rebinding / internal resolution)
        with patch("services.rdap_service.resolve_hostname_ips", return_value=["192.168.1.100"]):
            client.get.return_value = httpx.Response(
                302,
                headers={"Location": "https://rebinding.rdap.org/domain/example.com"},
                request=req
            )
            res = await fetch_rdap_info("example.com")
            assert res == {"error": "Prohibited redirect destination"}

        # Allowed domain that resolves to cloud metadata IP
        with patch("services.rdap_service.resolve_hostname_ips", return_value=["169.254.169.254"]):
            client.get.return_value = httpx.Response(
                302,
                headers={"Location": "https://metadata.rdap.org/domain/example.com"},
                request=req
            )
            res = await fetch_rdap_info("example.com")
            assert res == {"error": "Prohibited redirect destination"}

        # Allowed domain that resolves to IPv4-mapped IPv6 private IP
        with patch("services.rdap_service.resolve_hostname_ips", return_value=["::ffff:10.0.0.1"]):
            client.get.return_value = httpx.Response(
                302,
                headers={"Location": "https://v6-mapped-private.rdap.org/domain/example.com"},
                request=req
            )
            res = await fetch_rdap_info("example.com")
            assert res == {"error": "Prohibited redirect destination"}

        # Hostname that fails DNS resolution entirely
        with patch("services.rdap_service.resolve_hostname_ips", return_value=[]):
            client.get.return_value = httpx.Response(
                302,
                headers={"Location": "https://unresolvable.rdap.org/domain/example.com"},
                request=req
            )
            res = await fetch_rdap_info("example.com")
            assert res == {"error": "Prohibited redirect destination"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_non_allowlisted_hosts():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https://attacker-controlled.com/domain/example.com"},
            request=req
        )
        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Prohibited redirect destination"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_malformed_and_non_standard_ports():
    req = httpx.Request("GET", "https://rdap.org/domain/example.com")
    with patch("services.rdap_service.httpx.AsyncClient") as mock_cls:
        client = AsyncMock()
        mock_cls.return_value = client
        client.__aenter__.return_value = client

        # Non-standard port (8080)
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https://authoritative.rdap.org:8080/domain/example.com"},
            request=req
        )
        res_port = await fetch_rdap_info("example.com")
        assert res_port == {"error": "Prohibited redirect destination"}

        # Malformed location (no host)
        client.get.return_value = httpx.Response(
            302,
            headers={"Location": "https:///missing-host"},
            request=req
        )
        res_malformed = await fetch_rdap_info("example.com")
        assert res_malformed == {"error": "Prohibited redirect destination"}

@pytest.mark.asyncio
async def test_fetch_rdap_info_rejects_insecure_or_prohibited_initial_base_url():
    # Insecure HTTP base URL
    with patch("services.rdap_service.RDAP_BASE_URL", "http://insecure.rdap.org/domain/"):
        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Insecure redirect rejected"}

    # Prohibited localhost base URL
    with patch("services.rdap_service.RDAP_BASE_URL", "https://localhost:8000/domain/"):
        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Prohibited redirect destination"}

    # Non-allowlisted base URL
    with patch("services.rdap_service.RDAP_BASE_URL", "https://evil.attacker.com/domain/"):
        res = await fetch_rdap_info("example.com")
        assert res == {"error": "Prohibited redirect destination"}

def test_validation_edge_cases_and_helpers():
    # is_prohibited_ip with invalid IP string and IP object
    assert is_prohibited_ip("not-an-ip") is True
    import ipaddress
    assert is_prohibited_ip(ipaddress.ip_address("127.0.0.1")) is True

    # is_allowed_rdap_host with empty patterns and wildcard suffix
    assert is_allowed_rdap_host("test.com", None) is False
    assert is_allowed_rdap_host("special.nic.cz", ["*.nic.cz"]) is True
    assert is_allowed_rdap_host("other.com", ["*.nic.cz"]) is False

    # validate_rdap_destination invalid input types and parse errors
    assert validate_rdap_destination(None)[0] is False
    assert validate_rdap_destination(12345)[0] is False
    assert validate_rdap_destination("https://rdap.org:invalid-port/test")[0] is False
    with patch("services.rdap_service.urlparse", side_effect=Exception("malformed")):
        assert validate_rdap_destination("https://rdap.org")[0] is False

    # resolve_hostname_ips error handling
    with patch("socket.getaddrinfo", side_effect=OSError("Network unreachable")):
        assert resolve_hostname_ips("rdap.org") == []

@pytest.mark.asyncio
async def test_ssrf_safe_backend_connection_level():
    from services.rdap_service import SSRFSafeBackend
    from httpcore._exceptions import ConnectError
    import anyio

    backend = SSRFSafeBackend()

    # 1. Prohibited IP target resolved at connection time
    with pytest.raises(ConnectError) as exc_info:
        await backend.connect_tcp("private.rdap.org", 443)
    assert "Prohibited IP target resolved" in str(exc_info.value)

    # 2. DNS resolution failure at connection time
    with pytest.raises(ConnectError) as exc_info:
        await backend.connect_tcp("unresolvable.rdap.org", 443)
    assert "DNS resolution failed" in str(exc_info.value)

    # 3. Connection pins to the validated IP directly, preserving TLS SNI
    mock_stream = AsyncMock()
    with patch("anyio.connect_tcp", return_value=mock_stream) as mock_connect:
        stream = await backend.connect_tcp("authoritative.rdap.org", 443)
        # Verify connect_tcp was called with the resolved IP ("93.184.216.34"), NOT the hostname!
        mock_connect.assert_awaited_once_with(
            remote_host="93.184.216.34",
            remote_port=443,
            local_host=None
        )

    # 4. No valid IP found when getaddrinfo returns empty list
    with patch("socket.getaddrinfo", return_value=[]):
        with pytest.raises(ConnectError) as exc_info:
            await backend.connect_tcp("empty.rdap.org", 443)
        assert "No valid IP address found" in str(exc_info.value)

    # 5. Socket options application
    mock_stream_opts = MagicMock()
    with patch("anyio.connect_tcp", return_value=mock_stream_opts):
        sock_opt = (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        await backend.connect_tcp("authoritative.rdap.org", 443, socket_options=[sock_opt])
        mock_stream_opts._raw_socket.setsockopt.assert_called_once_with(*sock_opt)

def test_validate_rdap_destination_rejects_credentials_and_parser_confusion():
    allowed = ["rdap.org"]

    # Basic auth with username and password
    ok, reason = validate_rdap_destination("https://user:password@rdap.org/domain/example.com", allowed)
    assert ok is False
    assert reason == "Prohibited redirect destination"

    # Username only
    ok, reason = validate_rdap_destination("https://admin@rdap.org/domain/example.com", allowed)
    assert ok is False
    assert reason == "Prohibited redirect destination"

    # Empty user with @ symbol
    ok, reason = validate_rdap_destination("https://@rdap.org/domain/example.com", allowed)
    assert ok is False
    assert reason == "Prohibited redirect destination"

    # Parser confusion: credentials placed in host portion
    ok, reason = validate_rdap_destination("https://rdap.org:secret@rdap.org/domain/example.com", allowed)
    assert ok is False
    assert reason == "Prohibited redirect destination"

    # Valid URL without user credentials
    ok, reason = validate_rdap_destination("https://rdap.org/domain/example.com", allowed)
    assert ok is True
    assert reason == ""

@pytest.mark.asyncio
async def test_ssrf_safe_backend_multi_record_dns_order_independent():
    from httpcore._exceptions import ConnectError
    backend = SSRFSafeBackend()

    # Case 1: Public record first, prohibited (RFC 6598 / private) record second
    public_first = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.0.1", 443)),
    ]
    with patch("socket.getaddrinfo", return_value=public_first):
        with pytest.raises(ConnectError) as exc_info:
            await backend.connect_tcp("authoritative.rdap.org", 443)
        assert "Prohibited IP target resolved" in str(exc_info.value)
        assert "100.64.0.1" in str(exc_info.value)

    # Case 2: Prohibited record first, public record second
    prohibited_first = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
    ]
    with patch("socket.getaddrinfo", return_value=prohibited_first):
        with pytest.raises(ConnectError) as exc_info:
            await backend.connect_tcp("authoritative.rdap.org", 443)
        assert "Prohibited IP target resolved" in str(exc_info.value)
        assert "192.168.1.100" in str(exc_info.value)

    # Validate that validate_rdap_destination also rejects multi-record DNS regardless of order
    with patch("services.rdap_service.resolve_hostname_ips", return_value=["93.184.216.34", "100.64.0.1"]):
        ok, reason = validate_rdap_destination("https://rdap.org/domain/test", ["rdap.org"])
        assert ok is False
        assert reason == "Prohibited redirect destination"

    with patch("services.rdap_service.resolve_hostname_ips", return_value=["192.168.1.100", "93.184.216.34"]):
        ok, reason = validate_rdap_destination("https://rdap.org/domain/test", ["rdap.org"])
        assert ok is False
        assert reason == "Prohibited redirect destination"

def test_ssrf_safe_transport_preserves_pool_limits_and_compatibility():
    import httpcore
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=15, keepalive_expiry=25.0)
    transport = SSRFSafeTransport(limits=limits, http2=True, retries=2)

    # Verify custom connection limits and protocol options remain intact
    assert transport._pool._max_connections == 50
    assert transport._pool._max_keepalive_connections == 15
    assert transport._pool._keepalive_expiry == 25.0
    assert transport._pool._http2 is True
    assert transport._pool._retries == 2

    # Verify SSRFSafeBackend is attached to the pool
    assert isinstance(transport._pool._network_backend, SSRFSafeBackend)

    # Verify connection creation inherits SSRFSafeBackend and settings
    origin = httpcore.Origin(b"https", b"rdap.org", 443)
    conn = transport._pool.create_connection(origin)
    assert isinstance(conn._network_backend, SSRFSafeBackend)
    assert conn._http2 is True
    assert conn._retries == 2

    # Verify pinned dependency compatibility
    assert httpx.__version__ == "0.28.1"
    assert httpcore.__version__ == "1.0.9"






