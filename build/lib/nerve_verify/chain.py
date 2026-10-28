"""Directory-level verification: every receipt, plus ordering and duplicate-ID checks.

This checks each receipt independently and the set's timestamp ordering and
nervesystem_id uniqueness. It makes no claim beyond those checks.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nerve_verify.crypto import CheckResult, verify_receipt


@dataclass(frozen=True)
class ChainEntry:
    path: Path
    receipt: dict | None
    load_error: str | None


@dataclass(frozen=True)
class ChainReport:
    entries: list[tuple[ChainEntry, list[CheckResult]]]
    sequence_checks: list[CheckResult]

    @property
    def all_passed(self) -> bool:
        entry_ok = all(
            all(c.passed for c in checks) for _entry, checks in self.entries
        )
        seq_ok = all(c.passed for c in self.sequence_checks)
        return entry_ok and seq_ok


def _load_entry(path: Path) -> ChainEntry:
    try:
        receipt = json.loads(path.read_text())
        if not isinstance(receipt, dict):
            return ChainEntry(path, None, "top-level JSON is not an object")
        return ChainEntry(path, receipt, None)
    except (OSError, json.JSONDecodeError) as exc:
        return ChainEntry(path, None, str(exc))


def _parse_ts(receipt: dict) -> datetime | None:
    try:
        ts = datetime.fromisoformat(receipt["timestamp_utc"])
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None


def verify_chain(receipts_dir: Path) -> ChainReport:
    paths = sorted(receipts_dir.glob("*.json"))
    entries = [_load_entry(p) for p in paths]

    per_entry: list[tuple[ChainEntry, list[CheckResult]]] = []
    for entry in entries:
        if entry.load_error is not None:
            per_entry.append(
                (entry, [CheckResult("load", False, entry.load_error)])
            )
            continue
        report = verify_receipt(entry.receipt)
        per_entry.append((entry, report.checks))

    sequence_checks: list[CheckResult] = []

    valid = [
        (e, _parse_ts(e.receipt))
        for e in entries
        if e.receipt is not None
    ]
    timestamps = [ts for _e, ts in valid if ts is not None]
    if timestamps == sorted(timestamps):
        sequence_checks.append(
            CheckResult("ordering", True, "timestamps are non-decreasing across the directory")
        )
    else:
        sequence_checks.append(
            CheckResult("ordering", False, "timestamps are NOT in non-decreasing order — possible reordering")
        )

    ids = [
        e.receipt.get("nervesystem_id")
        for e, _ts in valid
        if e.receipt.get("nervesystem_id") is not None
    ]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        sequence_checks.append(
            CheckResult("duplicates", False, f"duplicate nervesystem_id values found: {sorted(duplicates)}")
        )
    else:
        sequence_checks.append(
            CheckResult("duplicates", True, "no duplicate nervesystem_id values")
        )

    if not paths:
        sequence_checks.append(
            CheckResult("gaps", False, f"no receipt files (*.json) found in {receipts_dir}")
        )

    return ChainReport(entries=per_entry, sequence_checks=sequence_checks)
