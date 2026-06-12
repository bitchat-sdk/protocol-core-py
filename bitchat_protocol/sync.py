"""
TLV codec for BitChat REQUEST_SYNC payloads (gossip sync via GCS filters).

Format: [Type:1][Length:2 big-endian][Value:n] — note the 16-bit length,
unlike the announcement / private-message TLVs which use a 1-byte length.

RequestSyncPacket TLV types:
  0x01 = P (uint8) — Golomb-Rice parameter
  0x02 = M (uint32, big-endian) — hash range (N * 2^P)
  0x03 = data (opaque) — GR bitstream bytes (MSB-first)
  0x04 = types (1-8 bytes, little-endian) — sync-type flags bitmask (optional)
  0x05 = since timestamp (uint64, big-endian, ms since epoch) (optional)
  0x06 = fragment ID filter (UTF-8) (optional)

The decoder is lenient about unknown tags (forward-compatible) and strict
about field validity: it rejects p outside 1..=MAX_P, m == 0, missing
required fields, and filter data above `max_accept_bytes`.

Wire-compatible with RequestSyncPacket.swift (BitchatProtocol) and
RequestSyncPacket.kt (bitchat-android-sdk; basic TLVs 0x01-0x03 only).
"""

from __future__ import annotations

from typing import Optional

from .errors import TLVEncodeError
from .types import MessageType, RequestSyncPacket

# Maximum accepted Golomb-Rice parameter. Mirrors upstream GCSFilter.maxP;
# values above this make no sense for a GCS filter and are rejected on decode.
MAX_P = 32

# Receiver-side hard cap on filter data to avoid DoS via oversized filters.
MAX_ACCEPT_FILTER_BYTES = 1024

# Sync-type flags use at most 56 bits (mirrors SyncTypeFlags.swift).
_SYNC_TYPE_FLAGS_MASK = 0x00FF_FFFF_FFFF_FFFF

# ── RequestSyncPacket tag constants ──────────────────────────────────────────
_RS_P = 0x01
_RS_M = 0x02
_RS_DATA = 0x03
_RS_TYPES = 0x04
_RS_SINCE = 0x05
_RS_FRAGMENT_ID = 0x06

# Bit index per message type within the sync-type flags bitmask
# (mirrors SyncTypeFlags.bitIndex(for:) in BitchatProtocol).
_SYNC_TYPE_BIT = {
    MessageType.ANNOUNCE: 0,
    MessageType.MESSAGE: 1,
    MessageType.LEAVE: 2,
    MessageType.NOISE_HANDSHAKE: 3,
    MessageType.NOISE_ENCRYPTED: 4,
    MessageType.FRAGMENT: 5,
    MessageType.REQUEST_SYNC: 6,
    MessageType.FILE_TRANSFER: 7,
}


def sync_type_flags_from_message_types(types: list[MessageType]) -> int:
    """Build a sync-type flags bitmask from message types."""
    raw = 0
    for t in types:
        bit = _SYNC_TYPE_BIT.get(t)
        if bit is not None:
            raw |= 1 << bit
    return raw & _SYNC_TYPE_FLAGS_MASK


def sync_type_flags_to_message_types(flags: int) -> list[MessageType]:
    """Expand a sync-type flags bitmask into the message types it selects."""
    flags &= _SYNC_TYPE_FLAGS_MASK
    return [t for t, bit in _SYNC_TYPE_BIT.items() if flags & (1 << bit)]


def encode_request_sync(packet: RequestSyncPacket) -> bytes:
    """Encode a RequestSyncPacket to TLV bytes.

    Matches the Swift encoder byte-for-byte: `p` is masked to one byte
    (validity is enforced on decode), optional fields are emitted only
    when present, and `types == 0` is omitted like Swift's nil `toData()`.
    """
    if not (0 <= packet.m <= 0xFFFF_FFFF):
        raise TLVEncodeError("m out of range for uint32")
    if len(packet.data) > 0xFFFF:
        raise TLVEncodeError("data too long (max 65535 bytes per TLV)")

    out = bytearray()
    out.extend(_make_tlv16(_RS_P, bytes([packet.p & 0xFF])))
    out.extend(_make_tlv16(_RS_M, packet.m.to_bytes(4, "big")))
    out.extend(_make_tlv16(_RS_DATA, packet.data))

    if packet.types is not None:
        types_bytes = _sync_type_flags_to_bytes(packet.types)
        if types_bytes is not None:
            out.extend(_make_tlv16(_RS_TYPES, types_bytes))
    if packet.since_timestamp is not None:
        if not (0 <= packet.since_timestamp <= 0xFFFF_FFFF_FFFF_FFFF):
            raise TLVEncodeError("since_timestamp out of range for uint64")
        out.extend(_make_tlv16(_RS_SINCE, packet.since_timestamp.to_bytes(8, "big")))
    if packet.fragment_id_filter is not None:
        fid_bytes = packet.fragment_id_filter.encode("utf-8")
        if len(fid_bytes) > 0xFFFF:
            raise TLVEncodeError("fragment_id_filter too long (max 65535 bytes UTF-8)")
        out.extend(_make_tlv16(_RS_FRAGMENT_ID, fid_bytes))

    return bytes(out)


def decode_request_sync(
    data: bytes,
    max_accept_bytes: int = MAX_ACCEPT_FILTER_BYTES,
) -> Optional[RequestSyncPacket]:
    """Decode TLV bytes into a RequestSyncPacket. Returns None on failure."""
    offset = 0
    p: Optional[int] = None
    m: Optional[int] = None
    payload: Optional[bytes] = None
    types: Optional[int] = None
    since_timestamp: Optional[int] = None
    fragment_id_filter: Optional[str] = None

    while offset + 3 <= len(data):
        tag = data[offset]; offset += 1
        length = (data[offset] << 8) | data[offset + 1]; offset += 2
        if offset + length > len(data):
            return None
        value = data[offset:offset + length]; offset += length

        if tag == _RS_P:
            if len(value) == 1:
                p = value[0]
        elif tag == _RS_M:
            if len(value) == 4:
                m = int.from_bytes(value, "big")
        elif tag == _RS_DATA:
            if len(value) > max_accept_bytes:
                return None
            payload = value
        elif tag == _RS_TYPES:
            if 1 <= len(value) <= 8:
                types = int.from_bytes(value, "little") & _SYNC_TYPE_FLAGS_MASK
        elif tag == _RS_SINCE:
            if len(value) == 8:
                since_timestamp = int.from_bytes(value, "big")
        elif tag == _RS_FRAGMENT_ID:
            try:
                fragment_id_filter = value.decode("utf-8")
            except UnicodeDecodeError:
                pass
        # Unknown tag — skip (forward-compatible)

    if p is None or m is None or payload is None:
        return None
    if p < 1 or p > MAX_P or m <= 0:
        return None
    return RequestSyncPacket(
        p=p, m=m, data=payload,
        types=types, since_timestamp=since_timestamp,
        fragment_id_filter=fragment_id_filter,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_tlv16(tag: int, value: bytes) -> bytes:
    return bytes([tag, (len(value) >> 8) & 0xFF, len(value) & 0xFF]) + value


def _sync_type_flags_to_bytes(flags: int) -> Optional[bytes]:
    """Minimal little-endian bytes for a flags bitmask; None when zero
    (mirrors SyncTypeFlags.toData() returning nil for empty flags)."""
    flags &= _SYNC_TYPE_FLAGS_MASK
    if flags == 0:
        return None
    out = bytearray()
    while flags > 0 and len(out) < 8:
        out.append(flags & 0xFF)
        flags >>= 8
    return bytes(out)
