"""
Fixture-based compatibility tests.

Loads JSON golden vectors from spec-tests/fixtures/ and verifies:
  - should_decode=True: decode succeeds and re-encodes to same hex
  - should_decode=False: decode returns None
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from bitchat_protocol import (
    decode, encode, hex_to_bytes, bytes_to_hex,
    decode_announcement, encode_announcement,
    decode_private_message, encode_private_message,
    decode_request_sync, encode_request_sync,
)

# tests/ → bitchat-python-protocol/ → BitchatSDK/ → Projects/ — spec-tests is a
# sibling of the BitchatSDK workspace (same location the compiled JS tests use).
FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "spec-tests" / "fixtures"

FIXTURE_FILES = [
    "broadcast_message_v1.json",
    "directed_message_v1.json",
    "malformed_packets.json",
    "announcement_packet.json",
    "private_message_tlv.json",
    "request_sync.json",
]

# TLV-only fixture types (no binary packet wrapper)
_TLV_TYPES = {"announcement", "private_message_tlv", "request_sync"}

_TLV_DECODERS = {
    "announcement": decode_announcement,
    "private_message_tlv": decode_private_message,
    "request_sync": decode_request_sync,
}

_TLV_ENCODERS = {
    "announcement": encode_announcement,
    "private_message_tlv": encode_private_message,
    "request_sync": encode_request_sync,
}


def is_valid_hex(s: Any) -> bool:
    return isinstance(s, str) and len(s) > 0 and bool(re.match(r"^[0-9a-f]+$", s)) and len(s) % 2 == 0


def load_fixtures(filename: str) -> list[dict]:
    fp = FIXTURES_DIR / filename
    if not fp.exists():
        return []
    return json.loads(fp.read_text())


def generate_fixture_params():
    params = []
    for fname in FIXTURE_FILES:
        fixtures = load_fixtures(fname)
        for entry in fixtures:
            hex_val = entry.get("encoded_hex") or entry.get("encoded_raw_hex")
            if not is_valid_hex(hex_val):
                continue  # Illustrative fixture — skip
            params.append(pytest.param(entry, id=entry.get("id", "unknown")))
    return params


def _is_tlv_only(entry: dict) -> bool:
    """True for TLV-type fixtures that have tlv_input (not wrapped in a binary packet)."""
    return entry.get("type") in _TLV_TYPES and "tlv_input" in entry


@pytest.mark.parametrize("entry", generate_fixture_params())
def test_fixture(entry: dict):
    hex_val = entry.get("encoded_hex") or entry.get("encoded_raw_hex")
    assert is_valid_hex(hex_val), f"No valid hex in fixture {entry.get('id')}"

    raw = hex_to_bytes(hex_val)

    if entry.get("should_decode"):
        if _is_tlv_only(entry):
            ftype = entry["type"]
            decoded = _TLV_DECODERS[ftype](raw)
            assert decoded is not None, f"Expected TLV decode success for {entry.get('id')}"
            re_encoded = _TLV_ENCODERS[ftype](decoded)
        else:
            decoded = decode(raw)
            assert decoded is not None, f"Expected decode success for {entry.get('id')}"
            re_encoded = encode(decoded, padding=False)

        if not entry.get("no_roundtrip"):
            assert bytes_to_hex(re_encoded) == hex_val, (
                f"Re-encoded bytes mismatch for {entry.get('id')}:\n"
                f"  expected: {hex_val}\n"
                f"  got:      {bytes_to_hex(re_encoded)}"
            )
    else:
        if _is_tlv_only(entry):
            result = _TLV_DECODERS[entry["type"]](raw)
        else:
            result = decode(raw)
        assert result is None, (
            f"Expected decode failure for {entry.get('id')} but got a packet"
        )
