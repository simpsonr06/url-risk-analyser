import math
from typing import Dict, Any

def calculate_shannon_entropy(string: str) -> float:
    """
    Calculate the Shannon entropy of a string (in bits per symbol).
    Higher entropy indicates more randomness, often seen in Domain Generation Algorithms (DGA).
    """
    if not string:
        return 0.0
    length = float(len(string))
    prob = [float(string.count(c)) / length for c in set(string)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
    return entropy

def analyze_entropy(domain: str) -> Dict[str, Any]:
    """
    Analyze domain randomness and digit frequency to detect DGA or machine-generated domains.
    """
    if not domain:
        return {"score_addition": 0, "indicators": []}

    score_addition = 0
    indicators = []

    # Strip subdomains and TLD to focus entropy check on primary domain label
    parts = domain.split(".")
    base_label = parts[0] if parts else domain
    
    # If base is 'www', inspect next label if available
    if base_label == "www" and len(parts) > 1:
        base_label = parts[1]

    entropy = calculate_shannon_entropy(base_label)
    digits = sum(c.isdigit() for c in base_label)
    label_len = len(base_label)

    # Heuristics: high entropy or excessive digits in domain name
    is_high_entropy = entropy > 3.8 and label_len >= 8
    is_high_digits = digits >= 4

    if is_high_entropy or is_high_digits:
        details = []
        if is_high_entropy:
            details.append(f"Shannon Entropy: {entropy:.2f}")
            score_addition += 20
        if is_high_digits:
            details.append(f"Numeric Digits: {digits}")
            score_addition += 15

        indicators.append(f"High domain randomness / potential DGA ({', '.join(details)})")

    return {
        "score_addition": score_addition,
        "indicators": indicators,
        "entropy": round(entropy, 2),
        "digits": digits
    }
