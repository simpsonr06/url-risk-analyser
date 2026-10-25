from engine.heuristics import (
    analyze_heuristics, 
    extract_domain_parts, 
    levenshtein_distance
)

def test_extract_domain_parts():
    # Standard single-part TLD
    reg, root, subs = extract_domain_parts("sub.example.com")
    assert reg == "example.com"
    assert root == "example"
    assert subs == ["sub"]

    # Two-part TLD
    reg2, root2, subs2 = extract_domain_parts("portal.security.service.co.uk")
    assert reg2 == "service.co.uk"
    assert root2 == "service"
    assert subs2 == ["portal", "security"]

    # www prefix stripping
    reg3, root3, subs3 = extract_domain_parts("www.google.com")
    assert reg3 == "google.com"
    assert subs3 == []

def test_levenshtein_distance():
    assert levenshtein_distance("paypal.com", "paypal.com") == 0
    assert levenshtein_distance("paypa1.com", "paypal.com") == 1
    assert levenshtein_distance("g00gle.com", "google.com") == 2
    assert levenshtein_distance("completelydifferent.com", "google.com") > 5

def test_missing_https_heuristic():
    res = analyze_heuristics("http://normal-site.org")
    assert any("Missing HTTPS" in ind for ind in res["indicators"])
    assert res["score_addition"] >= 25

def test_at_symbol_heuristic():
    res = analyze_heuristics("https://user@legitimate.com.evil.xyz")
    assert any("@" in ind for ind in res["indicators"])

def test_suspicious_tld_heuristic():
    res = analyze_heuristics("https://update-account.xyz")
    assert any("High-risk Top-Level Domain" in ind for ind in res["indicators"])

def test_deep_subdomains_heuristic():
    res = analyze_heuristics("https://a.b.c.target-domain.com")
    assert any("Multiple nested subdomains" in ind for ind in res["indicators"])

def test_typosquatting_detection():
    res = analyze_heuristics("https://paypa1.com/login")
    assert any("Potential typosquatting" in ind for ind in res["indicators"])
    assert res["score_addition"] >= 40

def test_brand_impersonation_and_phish_keywords():
    res = analyze_heuristics("https://login-verify-paypal.xyz/account")
    # Compound threat detection
    assert any("Brand impersonation detected" in ind for ind in res["indicators"])
    assert any("phishing keywords" in ind.lower() for ind in res["indicators"])
    assert res["score_addition"] >= 80

def test_trusted_domain_safety():
    # Legitimate Google with HTTPS
    res_safe = analyze_heuristics("https://google.com/search")
    assert res_safe["score_addition"] == 0
    assert len(res_safe["indicators"]) == 0

    # Insecure Google over HTTP still triggers HTTPS warning
    res_http = analyze_heuristics("http://google.com")
    assert any("Missing HTTPS" in ind for ind in res_http["indicators"])
    assert res_http["score_addition"] > 0
