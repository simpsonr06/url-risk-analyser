from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
from engine.validator import check_ip_security, is_ip_address

# Common multi-part public suffixes
TWO_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in", "gen.in",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "com.br", "net.br",
    "co.jp", "ne.jp", "ac.jp"
}

# Suspicious or frequently abused TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ru", ".top", ".biz", ".info", 
    ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".buzz", ".country"
}

# High-profile brands frequently targeted by phishing
TARGET_BRANDS = [
    "paypal", "google", "apple", "amazon", "microsoft", 
    "netflix", "facebook", "instagram", "chase", "wellsfargo", "bankofamerica"
]

# Exact trusted domains
TRUSTED_DOMAINS = {
    "google.com", "paypal.com", "apple.com", "amazon.com", 
    "microsoft.com", "netflix.com", "facebook.com", "instagram.com"
}

# Keywords indicative of phishing intent
PHISH_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "authenticate", "wallet", "password", "confirm", "support-billing"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_domain_parts(hostname: str) -> Tuple[str, str, List[str]]:
    """
    Extract (registrable_domain, root_name, subdomains) from a hostname.
    Respects common two-part TLDs.
    """
    clean_host = hostname.lower().strip(".")
    if not clean_host or is_ip_address(clean_host):
        return clean_host, clean_host, []

    labels = clean_host.split(".")
    if len(labels) <= 1:
        return clean_host, clean_host, []

    # Check for known two-part TLD (e.g. example.co.uk)
    if len(labels) >= 3:
        potential_two_part = f"{labels[-2]}.{labels[-1]}"
        if potential_two_part in TWO_PART_TLDS:
            registrable = f"{labels[-3]}.{labels[-2]}.{labels[-1]}"
            root_name = labels[-3]
            subdomains = labels[:-3]
            return registrable, root_name, subdomains

    # Default single TLD (e.g. example.com)
    registrable = f"{labels[-2]}.{labels[-1]}"
    root_name = labels[-2]
    subdomains = labels[:-2]
    # Filter out standard 'www'
    subdomains = [s for s in subdomains if s != "www"]
    return registrable, root_name, subdomains

def analyze_heuristics(url: str, validation_meta: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Analyze URL structure against weighted heuristic rules.
    
    Accepts an optional pre-computed validation_meta dict from engine/validator.py.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    score_addition = 0
    indicators = []

    # 1. Scheme Analysis
    is_insecure = parsed.scheme != "https"
    if is_insecure:
        score_addition += 25
        indicators.append("Missing HTTPS encryption (Insecure connection)")

    # 2. IP Address & Destination Analysis
    ip_sec = check_ip_security(hostname)
    if ip_sec["is_ip"]:
        score_addition += 40
        indicators.append("Host is a direct IP address rather than a domain name")
        if ip_sec["is_non_public"]:
            score_addition += 40
            indicators.append("Host resolves to a private, loopback, or reserved IP address")
    elif hostname in ("localhost", "127.0.0.1") or hostname.endswith(".localhost"):
        score_addition += 40
        indicators.append("Host targets localhost / loopback environment")

    # 3. Credentials / Obfuscation in URL
    if "@" in (parsed.netloc or ""):
        score_addition += 30
        indicators.append("URL contains '@' symbol (often used for credential theft or misleading authorities)")

    # 4. Length Analysis
    if len(url) > 75:
        score_addition += 15
        indicators.append(f"Excessive URL length ({len(url)} characters)")

    # 5. Non-standard Port
    if parsed.port and parsed.port not in (80, 443):
        score_addition += 20
        indicators.append(f"Non-standard web port detected: {parsed.port}")

    # Domain label decomposition
    registrable_domain, root_name, subdomains = extract_domain_parts(hostname)

    # 6. Trusted Domain Handling
    # If the registrable domain is officially trusted and not an IP
    if registrable_domain in TRUSTED_DOMAINS:
        # If HTTPS is present and no subdomains/path brand impersonation
        if not is_insecure and len(subdomains) == 0:
            return {
                "score_addition": 0,
                "indicators": [],
                "domain": hostname,
                "registrable_domain": registrable_domain
            }
        elif is_insecure:
            return {
                "score_addition": 25,
                "indicators": ["Missing HTTPS encryption on trusted domain"],
                "domain": hostname,
                "registrable_domain": registrable_domain
            }

    # 7. Deep Subdomains Check
    if len(subdomains) >= 3:
        score_addition += 25
        indicators.append(f"Multiple nested subdomains detected ({len(subdomains)} levels)")

    # 8. Suspicious TLD Check
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score_addition += 30
        indicators.append(f"High-risk Top-Level Domain (TLD) detected on {hostname}")

    # 9. Typosquatting Detection (Levenshtein Distance)
    is_typosquatting = False
    for trusted in TRUSTED_DOMAINS:
        dist = levenshtein_distance(registrable_domain, trusted)
        if 0 < dist <= 2:
            is_typosquatting = True
            indicators.append(f"Potential typosquatting of legitimate domain '{trusted}' (distance: {dist})")
            score_addition += 40
            break

    # 10. Phishing Intent Keywords
    url_lower = url.lower()
    matched_keywords = [kw for kw in PHISH_KEYWORDS if kw in url_lower]
    if len(matched_keywords) >= 2:
        score_addition += 30
        indicators.append(f"Multiple phishing keywords detected: {', '.join(matched_keywords)}")
    elif len(matched_keywords) == 1:
        score_addition += 15
        indicators.append(f"Suspicious security keyword in URL: '{matched_keywords[0]}'")

    # 11. Brand Impersonation in Non-Official Domain
    is_brand_impersonated = False
    if root_name not in TARGET_BRANDS:
        for brand in TARGET_BRANDS:
            if brand in hostname or brand in (parsed.path or "").lower():
                is_brand_impersonated = True
                indicators.append(f"Brand impersonation detected: targets brand '{brand}' outside official domain")
                score_addition += 40
                break

    # Compound Threat Correlation: Brand Impersonation + Phishing Keywords
    if is_brand_impersonated and len(matched_keywords) >= 1:
        indicators.append("High Severity Compound Vector: Brand impersonation combined with phishing keywords")
        score_addition = max(score_addition, 80)

    return {
        "score_addition": score_addition,
        "indicators": indicators,
        "domain": hostname,
        "registrable_domain": registrable_domain
    }
