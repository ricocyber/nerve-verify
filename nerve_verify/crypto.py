"""Canonical serialization, hashing, and Ed25519 verification.

A from-scratch verifier that uses only public primitives (Ed25519,
SHA-384). It does not import or trust any NerveSystem code.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA_VERSION = "nervesystem-receipt-v1"
_NON_BODY_FIELDS = ("signature", "public_key", "signature_algorithm")
_REQUIRED_FIELDS = (
    "schema_version",
    "ontology_version",
    "timestamp_utc",
    "source_system",
    "target_format",
    "input_hash",
    "output_hash",
    "confidence",
    "elapsed_seconds",
    "anomalies",
    "nervesystem_id",
)
_SHA384_HEX_LEN = 96
_ED25519_PUBKEY_HEX_LEN = 64
_ED25519_SIG_HEX_LEN = 128
_SUPPORTED_ALGORITHM = "Ed25519"
_CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)


class ReceiptFormatError(ValueError):
    """Raised when a receipt fails structural/schema validation."""


def canonical_bytes(obj: Any) -> bytes:
    """Sorted-keys, no-whitespace JSON, UTF-8 encoded."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-fA-F]{{{length}}}", value) is not None


def is_sha384_hex(value: Any) -> bool:
    return _is_hex(value, _SHA384_HEX_LEN)


def validate_schema(receipt: Any) -> list[str]:
    """Return a list of schema errors; empty list means structurally valid."""
    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object"]
    errors = []
    for field_name in _REQUIRED_FIELDS:
        if field_name not in receipt:
            errors.append(f"missing required field: {field_name}")
    if receipt.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: {receipt.get('schema_version')!r} "
            f"(expected {SCHEMA_VERSION!r})"
        )
    for hash_field in ("input_hash", "output_hash"):
        val = receipt.get(hash_field)
        if val is not None and not is_sha384_hex(val):
            errors.append(f"{hash_field} is not a valid SHA-384 hex digest")
    return errors


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class VerificationReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "verdict": "PASS" if self.all_passed else "FAIL",
            "checks": [asdict(c) for c in self.checks],
        }


def _receipt_body(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k not in _NON_BODY_FIELDS}


def verify_signature(receipt: dict, pin_key_hex: str | None = None) -> CheckResult:
    sig_hex = receipt.get("signature")
    pub_hex = receipt.get("public_key")
    algo = receipt.get("signature_algorithm")

    if not sig_hex or not pub_hex or algo == "unavailable":
        return CheckResult("signature", False, "NO_SIGNATURE: signature or public_key absent")

    if algo != _SUPPORTED_ALGORITHM:
        return CheckResult(
            "signature", False,
            f"UNSUPPORTED_ALGORITHM: {algo!r} (expected {_SUPPORTED_ALGORITHM!r})",
        )

    if not _is_hex(pub_hex, _ED25519_PUBKEY_HEX_LEN) or not _is_hex(sig_hex, _ED25519_SIG_HEX_LEN):
        return CheckResult(
            "signature", False,
            "MALFORMED_KEY_OR_SIGNATURE: expected 64-hex public_key and 128-hex signature",
        )

    if pin_key_hex is not None and pub_hex.lower() != pin_key_hex.lower():
        return CheckResult(
            "signature", False,
            "KEY_MISMATCH: receipt's embedded public_key does not match --pin-key",
        )

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        body_bytes = canonical_bytes(_receipt_body(receipt))
        pub.verify(bytes.fromhex(sig_hex), body_bytes)
    except (InvalidSignature, ValueError) as exc:
        return CheckResult("signature", False, f"signature verification failed: {exc}")

    origin_note = (
        "origin-authenticated against --pin-key"
        if pin_key_hex is not None
        else "self-consistent only — receipt not checked against a known/pinned key"
    )
    return CheckResult("signature", True, f"valid Ed25519 signature ({origin_note})")


def verify_hash_claims(
    receipt: dict,
    input_data: bytes | None = None,
    output_data: bytes | None = None,
) -> list[CheckResult]:
    """Never claim recomputation without the original payload."""
    results = []
    for hash_field, payload in (("input_hash", input_data), ("output_hash", output_data)):
        claimed = receipt.get(hash_field)
        if not is_sha384_hex(claimed):
            results.append(CheckResult(hash_field, False, "not a valid SHA-384 hex digest"))
            continue
        if payload is None:
            results.append(
                CheckResult(
                    hash_field, True,
                    "present, well-formed — NOT independently verified (no source payload supplied)",
                )
            )
            continue
        recomputed = sha384_hex(payload)
        if recomputed == claimed.lower():
            results.append(CheckResult(hash_field, True, "recomputed hash matches claimed hash"))
        else:
            results.append(
                CheckResult(hash_field, False, f"recomputed {recomputed} != claimed {claimed}")
            )
    return results


def verify_timestamp(receipt: dict, now: datetime | None = None) -> CheckResult:
    ts_raw = receipt.get("timestamp_utc")
    try:
        ts = datetime.fromisoformat(ts_raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return CheckResult("timestamp", False, f"not valid ISO 8601: {ts_raw!r}")

    reference = now or datetime.now(timezone.utc)
    if ts > reference + _CLOCK_SKEW_TOLERANCE:
        return CheckResult(
            "timestamp", False,
            f"timestamp {ts.isoformat()} is in the future beyond clock-skew tolerance",
        )
    return CheckResult("timestamp", True, f"{ts.isoformat()} is internally consistent")


def verify_receipt(
    receipt: dict,
    input_data: bytes | None = None,
    output_data: bytes | None = None,
    pin_key_hex: str | None = None,
    now: datetime | None = None,
) -> VerificationReport:
    """Run the full verification algorithm on a single receipt."""
    checks: list[CheckResult] = []

    schema_errors = validate_schema(receipt)
    if schema_errors:
        checks.append(CheckResult("schema", False, "; ".join(schema_errors)))
        return VerificationReport(checks=checks)
    checks.append(CheckResult("schema", True, f"matches {SCHEMA_VERSION}"))

    checks.append(verify_timestamp(receipt, now=now))
    checks.extend(verify_hash_claims(receipt, input_data=input_data, output_data=output_data))
    checks.append(verify_signature(receipt, pin_key_hex=pin_key_hex))

    return VerificationReport(checks=checks)
