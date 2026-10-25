from typing import Optional
from engine.validator import validate_and_normalize_url, ValidationError
from engine.heuristics import analyze_heuristics
from engine.entropy import analyze_entropy
from engine.rdap import analyze_domain_intel
from engine.scoring import calculate_final_score, classify_score
from services.rdap_service import fetch_rdap_info
from database.models import ScanResponse, IntelligenceInfo

async def analyze_url(url: str) -> ScanResponse:
    """
    Central orchestration engine.
    
    1. Validates and normalizes input URL (guards against SSRF, bad schemes, invalid formats).
    2. Runs weighted heuristics (HTTPS, ports, subdomains, TLDs, typosquatting, impersonation).
    3. Runs Shannon entropy and digit analysis on domain labels.
    4. Performs RDAP intelligence lookup if eligible (skips IPs and loopback).
    5. Combines risk weights, clamps composite score to [0, 100], and classifies threat level.
    """
    # 1. Validation & Normalization
    val_meta = validate_and_normalize_url(url)
    normalized_url = val_meta["normalized_url"]

    # 2. Heuristics Evaluation
    heuristic_res = analyze_heuristics(normalized_url, val_meta)

    # 3. Entropy Analysis
    entropy_res = analyze_entropy(val_meta["hostname"])

    # 4. Domain Intelligence (RDAP)
    if val_meta["is_rdap_eligible"] and val_meta["rdap_domain"]:
        raw_rdap = await fetch_rdap_info(val_meta["rdap_domain"])
        rdap_res = analyze_domain_intel(val_meta["rdap_domain"], raw_rdap)
    else:
        # Gracefully handle targets where domain RDAP is not applicable
        if val_meta["ip_info"]["is_ip"]:
            label = "Direct IP Address (RDAP domain lookup skipped)"
        elif val_meta["is_localhost"]:
            label = "Localhost Environment (External intelligence disabled)"
        else:
            label = "Non-standard hostname (RDAP lookup skipped)"

        rdap_res = {
            "score_addition": 0,
            "indicators": [],
            "intelligence": IntelligenceInfo(
                available=False,
                registrar=label,
                age="N/A",
                created=None,
                expires=None
            )
        }

    # 5. Composite Scoring & Deduplication
    total_score = calculate_final_score(
        heuristic_res["score_addition"],
        entropy_res["score_addition"],
        rdap_res["score_addition"]
    )
    classification = classify_score(total_score)

    # Deduplicate indicators while preserving order
    raw_indicators = (
        heuristic_res["indicators"] + 
        entropy_res["indicators"] + 
        rdap_res["indicators"]
    )
    unique_indicators = []
    seen = set()
    for ind in raw_indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    return ScanResponse(
        score=total_score,
        level=classification,
        reasons=unique_indicators,
        intelligence=rdap_res["intelligence"]
    )
