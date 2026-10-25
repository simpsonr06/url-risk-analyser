from engine.entropy import calculate_shannon_entropy, analyze_entropy

def test_entropy_calculation_empty_and_uniform():
    assert calculate_shannon_entropy("") == 0.0
    # Repeating single character has 0 entropy
    assert calculate_shannon_entropy("aaaaa") == 0.0

def test_entropy_calculation_randomness():
    normal_entropy = calculate_shannon_entropy("google")
    random_entropy = calculate_shannon_entropy("x7k9p2m4q1z8w")
    assert random_entropy > normal_entropy
    assert random_entropy > 3.0

def test_analyze_entropy_normal_domain():
    res = analyze_entropy("github.com")
    assert res["score_addition"] == 0
    assert len(res["indicators"]) == 0

def test_analyze_entropy_dga_domain():
    # Long high-entropy random string
    dga_domain = "q9z8x7c6v5b4m3.biz"
    res = analyze_entropy(dga_domain)
    assert res["score_addition"] > 0
    assert any("randomness" in ind.lower() or "dga" in ind.lower() for ind in res["indicators"])

def test_analyze_entropy_excessive_digits():
    digit_domain = "login987654321.com"
    res = analyze_entropy(digit_domain)
    assert res["score_addition"] > 0
    assert any("Numeric Digits" in ind for ind in res["indicators"])
