from app.evaluation.crypto_demos import analyze_hash, run_signature_demo


def test_hash_analysis_returns_sha256_digest_and_bounded_toy_demos():
    result = analyze_hash("sentinel test")

    assert result["algorithm"] == "SHA-256"
    assert len(result["digest_hex"]) == 64
    assert result["input_bytes"] == len("sentinel test".encode())
    assert result["generation_time_ms"] >= 0
    assert result["size_benchmarks"]
    assert result["toy_demonstration"]["digest_bits"] == 12
    assert result["toy_demonstration"]["scope"] == "educational only"


def test_signature_demo_signs_verifies_and_rejects_modified_message():
    result = run_signature_demo("signed sample")

    assert result["algorithm"] == "Ed25519"
    assert result["valid_signature_verified"] is True
    assert result["modified_message_verified"] is False
    assert result["signature_generation_time_ms"] >= 0
    assert result["verification_time_ms"] >= 0
    assert "private_key" not in result
