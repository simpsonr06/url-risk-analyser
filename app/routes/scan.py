from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
import logging
from database.models import ScanRequest, ScanResponse, DashboardStats, RecentScanItem
from engine.aggregator import analyze_url
from engine.validator import ValidationError
from database.queries import insert_scan, get_recent_scans, get_dashboard_stats
from app.limiter import check_rate_limit
from typing import List

logger = logging.getLogger(__name__)
router = APIRouter()

def safe_get(data, key):
    """Safely extract attributes from dict or Pydantic model."""
    if not data:
        return None
    if hasattr(data, key):
        return getattr(data, key)
    if isinstance(data, dict):
        return data.get(key)
    return None

@router.post(
    "/scan",
    response_model=ScanResponse,
    dependencies=[Depends(check_rate_limit)],
    summary="Analyze URL Risk",
    description="Analyzes the target URL using heuristics, entropy, and domain intelligence."
)
async def scan_endpoint(request: ScanRequest):
    """
    Main endpoint to analyze a URL.
    Returns composite risk score, classification level, indicators, and RDAP details.
    """
    if not request.url or not request.url.strip():
        return JSONResponse(status_code=400, content={"error": "URL cannot be empty"})

    try:
        # Perform Analysis
        response = await analyze_url(request.url)
        
        rdap_data = response.intelligence
        
        # Save scan result to database
        insert_scan(
            url=request.url.strip(),
            score=response.score,
            classification=response.level,
            creation_date=safe_get(rdap_data, "created") or "N/A",
            expiration_date=safe_get(rdap_data, "expires") or "N/A",
            registrar=safe_get(rdap_data, "registrar") or "N/A"
        )
        
        return response

    except ValidationError as ve:
        return JSONResponse(status_code=400, content={"error": str(ve)})
    except Exception as e:
        logger.error(f"Error analyzing URL '{request.url}': {e}", exc_info=True)
        return JSONResponse(
            status_code=500, 
            content={"error": "Internal processing error while analyzing URL"}
        )

@router.get(
    "/recent",
    response_model=List[RecentScanItem],
    summary="Get Recent Scans",
    description="Retrieve recent scan records for the dashboard."
)
async def recent_scans_endpoint(limit: int = Query(10, ge=1, le=100)):
    """Retrieve recent scan history for the dashboard."""
    return get_recent_scans(limit=limit)

@router.get(
    "/stats",
    response_model=DashboardStats,
    summary="Get Dashboard Statistics",
    description="Retrieve aggregate scan metrics."
)
async def stats_endpoint():
    """Retrieve aggregate statistics for the dashboard."""
    return get_dashboard_stats()
