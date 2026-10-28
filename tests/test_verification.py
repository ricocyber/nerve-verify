import json
from pathlib import Path

import pytest

from nerve_verify.chain import verify_chain
from nerve_verify.crypto import verify_receipt

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.mark.parametrize("path", sorted((FIXTURES_DIR / "valid").glob("*.json")))
def test_valid_receipts_pass(path):
    receipt = _load(path)
    report = verify_receipt(receipt)
    assert report.all_passed, f"{path.name} failed: {[c for c in report.checks if not c.passed]}"


def test_forged_signature_fails():
    receipt = _load(FIXTURES_DIR / "adversarial" / "forged_signature.json")
    report = verify_receipt(receipt)
    assert not report.all_passed
    sig_check = next(c for c in report.checks if c.name == "signature")
    assert not sig_check.passed


def test_altered_payload_fails():
    receipt = _load(FIXTURES_DIR / "adversarial" / "altered_payload.json")
    report = verify_receipt(receipt)
    assert not report.all_passed
    sig_check = next(c for c in report.checks if c.name == "signature")
    assert not sig_check.passed


def test_broken_chain_detects_duplicate_id():
    chain_report = verify_chain(FIXTURES_DIR / "adversarial" / "broken_chain")
    assert not chain_report.all_passed
    dup_check = next(c for c in chain_report.sequence_checks if c.name == "duplicates")
    assert not dup_check.passed


def test_future_timestamp_fails():
    receipt = _load(FIXTURES_DIR / "adversarial" / "future_timestamp.json")
    report = verify_receipt(receipt)
    assert not report.all_passed
    ts_check = next(c for c in report.checks if c.name == "timestamp")
    assert not ts_check.passed


def test_malformed_schema_fails():
    receipt = _load(FIXTURES_DIR / "adversarial" / "malformed_schema.json")
    report = verify_receipt(receipt)
    assert not report.all_passed
    schema_check = next(c for c in report.checks if c.name == "schema")
    assert not schema_check.passed


def test_wrong_key_fails_pinned_check():
    receipt = _load(FIXTURES_DIR / "adversarial" / "wrong_key.json")
    demo_key_info = json.loads((FIXTURES_DIR / "demo_key.json").read_text())
    known_good_key = demo_key_info["public_key_hex"]

    report = verify_receipt(receipt, pin_key_hex=known_good_key)
    assert not report.all_passed
    sig_check = next(c for c in report.checks if c.name == "signature")
    assert not sig_check.passed
    assert "KEY_MISMATCH" in sig_check.detail


def test_wrong_key_self_consistent_without_pin():
    """Without --pin-key, a valid signature under a DIFFERENT key than claimed
    still verifies as self-consistent — this is documented, not a bug.
    Self-consistency != origin authentication."""
    receipt = _load(FIXTURES_DIR / "adversarial" / "wrong_key.json")
    report = verify_receipt(receipt)
    sig_check = next(c for c in report.checks if c.name == "signature")
    assert sig_check.passed
    assert "self-consistent only" in sig_check.detail


def test_all_16_fixtures_classified_correctly():
    """Master coverage check: 10 valid PASS, 6 adversarial FAIL (or the one
    exception documented above, which fails only under --pin-key)."""
    valid_paths = sorted((FIXTURES_DIR / "valid").glob("*.json"))
    assert len(valid_paths) == 10
    for path in valid_paths:
        assert verify_receipt(_load(path)).all_passed

    adversarial_paths = sorted(
        p for p in (FIXTURES_DIR / "adversarial").glob("*.json")
    )
    assert len(adversarial_paths) == 5  # 6th adversarial case is the broken_chain/ dir

    for path in adversarial_paths:
        receipt = _load(path)
        if path.name == "wrong_key.json":
            demo_key_info = json.loads((FIXTURES_DIR / "demo_key.json").read_text())
            report = verify_receipt(receipt, pin_key_hex=demo_key_info["public_key_hex"])
        else:
            report = verify_receipt(receipt)
        assert not report.all_passed, f"{path.name} should have failed verification"

    chain_report = verify_chain(FIXTURES_DIR / "adversarial" / "broken_chain")
    assert not chain_report.all_passed
