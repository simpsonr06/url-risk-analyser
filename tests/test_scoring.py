from engine.scoring import calculate_final_score, classify_score

def test_score_clamping():
    assert calculate_final_score(0, 0, 0) == 0
    assert calculate_final_score(15, 20, 25) == 60
    # Values exceeding 100 must be clamped to 100
    assert calculate_final_score(50, 40, 40) == 100
    assert calculate_final_score(150) == 100
    # Negative scores clamped to 0
    assert calculate_final_score(-20) == 0

def test_classification_boundaries():
    # Boundary tests: 0, 20, 21, 50, 51, 100
    assert classify_score(0) == "Safe"
    assert classify_score(10) == "Safe"
    assert classify_score(20) == "Safe"
    assert classify_score(21) == "Suspicious"
    assert classify_score(35) == "Suspicious"
    assert classify_score(50) == "Suspicious"
    assert classify_score(51) == "High Risk"
    assert classify_score(80) == "High Risk"
    assert classify_score(100) == "High Risk"
