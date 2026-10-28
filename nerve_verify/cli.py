"""nerve-verify CLI. Zero network calls.

Exit codes: 0 = PASS, 1 = FAIL, 2 = usage or unreadable input.
"""

import copy
import json
from pathlib import Path

import click

from nerve_verify import __version__
from nerve_verify.chain import verify_chain
from nerve_verify.crypto import VerificationReport, verify_receipt
from nerve_verify.demo_receipt import DEMO_RECEIPT


def _print_report(label: str, report: VerificationReport) -> bool:
    click.echo(f"\n{label}")
    for check in report.checks:
        status = click.style("PASS", fg="green") if check.passed else click.style("FAIL", fg="red")
        click.echo(f"  [{status}] {check.name}: {check.detail}")
    verdict = "PASS" if report.all_passed else "FAIL"
    color = "green" if report.all_passed else "red"
    click.echo(click.style(f"  verdict: {verdict}", fg=color, bold=True))
    return report.all_passed


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise click.UsageError(f"cannot read {path.name} as JSON: {exc}") from exc


@click.group()
@click.version_option(__version__, prog_name="nerve-verify")
def main() -> None:
    """Independent verification toolkit for NerveSystem Asset Action Receipts."""


@main.command()
@click.argument("receipt_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--input-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
              help="Original input payload, to independently verify input_hash.")
@click.option("--output-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
              help="Original output payload, to independently verify output_hash.")
@click.option("--pin-key", default=None, help="Known-good hex public key to authenticate origin.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")
def check(receipt_path: Path, input_file: Path | None, output_file: Path | None,
          pin_key: str | None, as_json: bool) -> None:
    """Validate a single receipt: schema, hashes, signature, timestamp."""
    receipt = _load_json(receipt_path)
    input_data = input_file.read_bytes() if input_file else None
    output_data = output_file.read_bytes() if output_file else None

    report = verify_receipt(receipt, input_data=input_data, output_data=output_data, pin_key_hex=pin_key)
    if as_json:
        click.echo(json.dumps({"receipt": receipt_path.name, **report.to_dict()}, indent=2))
        passed = report.all_passed
    else:
        passed = _print_report(f"nerve-verify check: {receipt_path.name}", report)
    raise SystemExit(0 if passed else 1)


@main.command()
@click.argument("receipts_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")
def chain(receipts_dir: Path, as_json: bool) -> None:
    """Verify every receipt in a directory, plus ordering and duplicate-ID checks."""
    report = verify_chain(receipts_dir)

    if as_json:
        click.echo(json.dumps({
            "verdict": "PASS" if report.all_passed else "FAIL",
            "entries": [
                {"receipt": entry.path.name, **VerificationReport(checks=checks).to_dict()}
                for entry, checks in report.entries
            ],
            "sequence_checks": VerificationReport(checks=report.sequence_checks).to_dict()["checks"],
        }, indent=2))
        raise SystemExit(0 if report.all_passed else 1)

    for entry, checks in report.entries:
        _print_report(f"  entry: {entry.path.name}", VerificationReport(checks=checks))
    _print_report("sequence checks", VerificationReport(checks=report.sequence_checks))
    raise SystemExit(0 if report.all_passed else 1)


@main.command("tamper-demo")
def tamper_demo() -> None:
    """Verify a pre-signed demo receipt, change one field, and show verification fail."""
    click.echo(click.style("=== STEP 1: valid receipt ===", bold=True))
    _print_report("valid receipt", verify_receipt(DEMO_RECEIPT))

    tampered = copy.deepcopy(DEMO_RECEIPT)
    tampered["confidence"] = round(tampered["confidence"] + 0.01, 4)

    click.echo(click.style("\n=== STEP 2: one field flipped (confidence changed, signature untouched) ===", bold=True))
    passed = _print_report("tampered receipt", verify_receipt(tampered))

    click.echo()
    if not passed:
        click.echo(click.style(
            "Tamper detected: altering the body invalidates the signature without touching it directly.",
            fg="yellow",
        ))
    raise SystemExit(0 if not passed else 1)


if __name__ == "__main__":
    main()
