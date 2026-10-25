def classify_score(score: int) -> str:
    """
    Classify the risk level based on the composite score:
    - 0 to 20: Safe
    - 21 to 50: Suspicious
    - 51 to 100: High Risk
    """
    if score <= 20:
        return "Safe"
    elif score <= 50:
        return "Suspicious"
    else:
        return "High Risk"

def calculate_final_score(*module_scores: int) -> int:
    """Combine module scores and clamp strictly between 0 and 100."""
    total = sum(module_scores)
    return max(0, min(total, 100))
