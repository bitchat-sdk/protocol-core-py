"""
Tests for the REQUEST_SYNC TLV codec (sync.py).

The hex vectors here are the canonical cross-language golden vectors —
identical assertions exist in BitchatProtocol (Swift), bitchat-android-sdk
(Kotlin), and @bitchat-sdk/protocol-core (TypeScript), and they are exported
to spec-tests/fixtures/request_sync.json by spec-tests/scripts/generate.py.
"""

import pytest

from bitchat_protocol import (
    MAX_P,
    MessageType,
    RequestSyncPacket,
    TLVEncodeError,
    decode_request_sync,
    encode_request_sync,
    sync_type_flags_from_message_types,
    sync_type_flags_to_message_types,
)

# ── Golden vectors ────────────────────────────────────────────────────────────

GOLDEN_BASIC = "01000113020004000800000300050102030405"
GOLDEN_MAX_P = "01000120020004ffffffff03000100"
GOLDEN_EXTENDED = (
    "0100010802000400000100030001ff0400010305000800000000000f4240060003616263"
)


def test_golden_basic_encode():
    packet = RequestSyncPacket(p=19, m=1 << 19, data=bytes([1, 2, 3, 4, 5]))
    assert encode_request_sync(packet).hex() == GOLDEN_BASIC


def test_golden_basic_decode():
    decoded = decode_request_sync(bytes.fromhex(GOLDEN_BASIC))
    assert decoded is not None
    assert decoded.p == 19
    assert decoded.m == 1 << 19
    assert decoded.data == bytes([1, 2, 3, 4, 5])
    assert decoded.types is None
    assert decoded.since_timestamp is None
    assert decoded.fragment_id_filter is None


def test_golden_max_p_round_trip():
    packet = RequestSyncPacket(p=MAX_P, m=0xFFFF_FFFF, data=b"\x00")
    assert encode_request_sync(packet).hex() == GOLDEN_MAX_P
    decoded = decode_request_sync(bytes.fromhex(GOLDEN_MAX_P))
    assert decoded is not None
    assert decoded.p == MAX_P
    assert decoded.m == 0xFFFF_FFFF


def test_golden_extended_round_trip():
    packet = RequestSyncPacket(
        p=8,
        m=256,
        data=b"\xff",
        types=sync_type_flags_from_message_types(
            [MessageType.ANNOUNCE, MessageType.MESSAGE]
        ),
        since_timestamp=1_000_000,
        fragment_id_filter="abc",
    )
    assert encode_request_sync(packet).hex() == GOLDEN_EXTENDED

    decoded = decode_request_sync(bytes.fromhex(GOLDEN_EXTENDED))
    assert decoded is not None
    assert decoded.p == 8
    assert decoded.m == 256
    assert decoded.data == b"\xff"
    assert decoded.types == 0x03
    assert decoded.since_timestamp == 1_000_000
    assert decoded.fragment_id_filter == "abc"
    assert sync_type_flags_to_message_types(decoded.types) == [
        MessageType.ANNOUNCE,
        MessageType.MESSAGE,
    ]


# ── Validation ────────────────────────────────────────────────────────────────

def _encoded_with_p(p: int) -> bytes:
    return encode_request_sync(RequestSyncPacket(p=p, m=1024, data=b"\x00"))


def test_decode_rejects_p_zero():
    assert decode_request_sync(_encoded_with_p(0)) is None


def test_decode_rejects_p_above_max():
    assert decode_request_sync(_encoded_with_p(MAX_P + 1)) is None


def test_decode_accepts_p_bounds():
    assert decode_request_sync(_encoded_with_p(1)) is not None
    assert decode_request_sync(_encoded_with_p(MAX_P)) is not None


def test_decode_rejects_m_zero():
    encoded = encode_request_sync(RequestSyncPacket(p=1, m=0, data=b"\x00"))
    assert decode_request_sync(encoded) is None


def test_decode_rejects_missing_data_tlv():
    # Only P and M present.
    assert decode_request_sync(bytes.fromhex("0100011302000400080000")) is None


def test_decode_rejects_truncated_tlv():
    assert decode_request_sync(bytes.fromhex("010001")) is None
    assert decode_request_sync(b"") is None


def test_decode_rejects_oversized_filter_data():
    packet = RequestSyncPacket(p=19, m=1 << 19, data=bytes(1025))
    encoded = encode_request_sync(packet)
    assert decode_request_sync(encoded) is None
    assert decode_request_sync(encoded, max_accept_bytes=2048) is not None


def test_decode_skips_unknown_tlv():
    prefixed = bytes.fromhex("7f0002beef" + GOLDEN_BASIC)
    decoded = decode_request_sync(prefixed)
    assert decoded is not None
    assert decoded.p == 19
    assert decoded.m == 1 << 19


def test_decode_skips_invalid_utf8_fragment_filter():
    # Valid basic fields + fragment TLV with invalid UTF-8: field is skipped, decode succeeds.
    encoded = bytes.fromhex(GOLDEN_BASIC + "060002fffe")
    decoded = decode_request_sync(encoded)
    assert decoded is not None
    assert decoded.fragment_id_filter is None


def test_encode_rejects_m_out_of_range():
    with pytest.raises(TLVEncodeError):
        encode_request_sync(RequestSyncPacket(p=1, m=1 << 32, data=b"\x00"))


def test_encode_omits_zero_types():
    packet = RequestSyncPacket(p=19, m=1 << 19, data=bytes([1, 2, 3, 4, 5]), types=0)
    assert encode_request_sync(packet).hex() == GOLDEN_BASIC


def test_sync_type_flags_mask_56_bits():
    flags = sync_type_flags_from_message_types(list(MessageType))
    assert flags == 0xFF
    assert sync_type_flags_to_message_types(1 << 60) == []
