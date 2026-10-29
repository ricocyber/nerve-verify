import json
from pathlib import Path

from click.testing import CliRunner

from nerve_verify.cli import main
from nerve_verify.crypto import is_sha384_hex, verify_receipt

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
VALID = FIXTURES_DIR / "valid" / "valid_00.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _check(receipt: dict, name: str):
    return next(c for c in verify_receipt(receipt).checks if c.name == name)


def test_sha384_rejects_int_parser_quirks():
    assert not is_sha384_hex("0x" + "a" * 94)
    assert not is_sha384_hex("a" * 95 + "_")
    assert not is_sha384_hex(" " + "a" * 95)
    assert is_sha384_hex("A" * 96)


def test_unsupported_signature_algorithm_fails():
    receipt = {**_load(VALID), "signature_algorithm": "none"}
    sig = _check(receipt, "signature")
    assert not sig.passed
    assert "UNSUPPORTED_ALGORITHM" in sig.detail


def test_non_string_signature_fails_cleanly():
    receipt = {**_load(VALID), "signature": 12345}
    assert not _check(receipt, "signature").passed


def test_non_object_receipt_fails_cleanly():
    report = verify_receipt(["not", "a", "receipt"])
    assert not report.all_passed
    assert report.checks[0].name == "schema"


def test_uppercase_payload_hash_matches(tmp_path):
    payload = b"hello"
    import hashlib
    receipt = _load(VALID)
    receipt["input_hash"] = hashlib.sha384(payload).hexdigest().upper()
    report = verify_receipt(receipt, input_data=payload)
    assert next(c for c in report.checks if c.name == "input_hash").passed


def test_cli_check_json_output():
    result = CliRunner().invoke(main, ["check", str(VALID), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verdict"] == "PASS"
    assert {c["name"] for c in data["checks"]} >= {"schema", "signature", "timestamp"}


def test_cli_check_json_output_on_failure():
    forged = FIXTURES_DIR / "adversarial" / "forged_signature.json"
    result = CliRunner().invoke(main, ["check", str(forged), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["verdict"] == "FAIL"


def test_cli_chain_json_output():
    broken = FIXTURES_DIR / "adversarial" / "broken_chain"
    result = CliRunner().invoke(main, ["chain", str(broken), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["verdict"] == "FAIL"
    assert any(c["name"] == "duplicates" and not c["passed"] for c in data["sequence_checks"])


def test_cli_check_bad_json_exits_2_without_traceback(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result = CliRunner().invoke(main, ["check", str(bad)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_cli_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "nerve-verify" in result.output


def test_cli_stdin_matches_file_verification():
    for path, code in ((VALID, 0), (FIXTURES_DIR / "adversarial" / "forged_signature.json", 1)):
        runner = CliRunner()
        from_file = runner.invoke(main, ["check", str(path), "--json"])
        from_stdin = runner.invoke(main, ["check", "-", "--json"], input=path.read_bytes())
        assert from_stdin.exit_code == from_file.exit_code == code
        file_report, stdin_report = json.loads(from_file.output), json.loads(from_stdin.output)
        assert stdin_report.pop("receipt") == "-"
        file_report.pop("receipt")
        assert stdin_report == file_report


def test_cli_stdin_text_output():
    result = CliRunner().invoke(main, ["check", "-"], input=VALID.read_bytes())
    assert result.exit_code == 0
    assert "verdict: PASS" in result.output


def test_cli_stdin_bad_json_exits_2_without_traceback():
    for data in (b"", b"{not json", b"\xff"):
        result = CliRunner().invoke(main, ["check", "-", "--json"], input=data)
        assert result.exit_code == 2
        assert "cannot read stdin as JSON" in result.output
        assert "Traceback" not in result.output


def test_cli_stdin_non_object_is_verification_failure():
    result = CliRunner().invoke(main, ["check", "-", "--json"], input="[]")
    assert result.exit_code == 1
    assert json.loads(result.output)["verdict"] == "FAIL"


def test_cli_stdin_applies_pin_and_payload_options(tmp_path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"synthetic mismatched payload")
    options = ["--json", "--pin-key", "00" * 32, "--input-file", str(payload), "--output-file", str(payload)]
    runner = CliRunner()
    from_file = runner.invoke(main, ["check", str(VALID), *options])
    from_stdin = runner.invoke(main, ["check", "-", *options], input=VALID.read_bytes())
    assert from_stdin.exit_code == from_file.exit_code == 1
    file_report, stdin_report = json.loads(from_file.output), json.loads(from_stdin.output)
    file_report.pop("receipt")
    stdin_report.pop("receipt")
    assert stdin_report == file_report
