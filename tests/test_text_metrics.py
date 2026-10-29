from app.evaluation.text_metrics import analyze_text


def test_text_analysis_reports_repeated_bit_and_hex_character_metrics():
    result = analyze_text("Unicode sample: café 🔐")
    assert result["recovery_matches"] is True
    assert result["aes_block_bits"] == 128
    assert result["avalanche_rounds"] >= 10
    assert len(result["avalanche_samples"]) == result["avalanche_rounds"]
    assert all(0 <= item["bit_change_percent"] <= 100 for item in result["avalanche_samples"])
    assert all(0 <= item["hex_character_change_percent"] <= 100 for item in result["avalanche_samples"])
    assert 0 <= result["avalanche_mean_percent"] <= 100
    assert result["hex_character_reference_percent"] == 100
