import pytest
from unittest.mock import patch

@pytest.mark.asyncio
async def test_health_check(async_client):
    resp = await async_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data

@pytest.mark.asyncio
async def test_frontend_serve(async_client):
    resp = await async_client.get("/")
    assert resp.status_code == 200
    assert "Threat Intelligence Core" in resp.text

@pytest.mark.asyncio
async def test_scan_endpoint_valid_url(async_client):
    with patch("engine.aggregator.fetch_rdap_info") as mock_rdap:
        mock_rdap.return_value = {
            "events": [{"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy"]]]}]
        }
        resp = await async_client.post("/api/scan", json={"url": "https://example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "level" in data
        assert isinstance(data["reasons"], list)
        assert data["intelligence"]["registrar"] == "GoDaddy"

@pytest.mark.asyncio
async def test_scan_endpoint_disallowed_scheme(async_client):
    resp = await async_client.post("/api/scan", json={"url": "javascript:alert('xss')"})
    assert resp.status_code == 400
    assert "Disallowed URL scheme" in resp.json()["error"]

@pytest.mark.asyncio
async def test_scan_endpoint_empty_url(async_client):
    resp = await async_client.post("/api/scan", json={"url": "   "})
    assert resp.status_code == 400
    assert "empty" in resp.json()["error"].lower()

@pytest.mark.asyncio
async def test_recent_and_stats_endpoints(async_client):
    # Stats check
    stats_resp = await async_client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert "total_scans" in stats

    # Recent scans check
    recent_resp = await async_client.get("/api/recent?limit=5")
    assert recent_resp.status_code == 200
    recent = recent_resp.json()
    assert isinstance(recent, list)

@pytest.mark.asyncio
async def test_rate_limiting(async_client):
    # In test environment, limit is configured to 10
    with patch("engine.aggregator.fetch_rdap_info") as mock_rdap:
        mock_rdap.return_value = {"error": "Mocked unavailable"}
        
        # Issue 10 allowed requests
        for _ in range(10):
            res = await async_client.post("/api/scan", json={"url": "https://test-example.org"})
            assert res.status_code == 200

        # 11th request must trigger HTTP 429
        rate_limited_res = await async_client.post("/api/scan", json={"url": "https://test-example.org"})
        assert rate_limited_res.status_code == 429
        assert "Rate limit exceeded" in rate_limited_res.text
        assert "Retry-After" in rate_limited_res.headers
