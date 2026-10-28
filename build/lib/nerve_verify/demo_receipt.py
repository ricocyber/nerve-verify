"""A pre-signed DEMO receipt for `nerve-verify tamper-demo`.

Signed once with the throwaway demo key in fixtures/demo_key.json.
This package verifies receipts; it does not issue them.
"""

DEMO_RECEIPT = {
    "schema_version": "nervesystem-receipt-v1",
    "ontology_version": "nervesystem-ontology-2026-04-22",
    "timestamp_utc": "2026-01-01T12:00:00+00:00",
    "source_system": "demo-source",
    "target_format": "demo-target",
    "input_hash": "0" * 96,
    "output_hash": "01" * 48,
    "confidence": 0.9,
    "elapsed_seconds": 0.03,
    "anomalies": [],
    "nervesystem_id": "demo-0000",
    "signature": (
        "d16a66a2ce8888a6c64871794bb0932dc9c1e79db69c52ab34498ff53e96619d"
        "0579aaa4865d00dd5c4df98dc95e3cce758975b99d7aed8ee550453e9b7afb0f"
    ),
    "public_key": "e268483b1b02650c3f4f840c8ba24329cc0bd13d4bec4423164e9d473c939324",
    "signature_algorithm": "Ed25519",
}
