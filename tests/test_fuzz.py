"""
Fuzz and stress tests for the BitChat binary protocol codec.

These tests verify that:
  - decode() never raises on any input (only returns None)
  - encode/decode round-trips are lossless
  - adversarial inputs (truncations, bit flips, bombs) are safely rejected
  - high-volume throughput is acceptable
"""

from __future__ import annotations

import random
import struct
import zlib

import pytest

from bitchat_protocol import (
    BitchatPacket,
    MessageType,
    decode,
    encode,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_packet(
    payload: bytes = b"hello fuzz",
    version: int = 1,
    ttl: int = 7,
    sender_id: bytes = bytes.fromhex("0102030405060708"),
) -> BitchatPacket:
    return BitchatPacket(
        version=version,
        type=int(MessageType.MESSAGE),
        ttl=ttl,
        timestamp=1_711_123_456_789,
        flags=0,
        sender_id=sender_id,
        payload=payload,
    )


def _wire(pkt: BitchatPacket) -> bytes:
    result = encode(pkt, padding=False)
    assert result is not None
    return result


# ---------------------------------------------------------------------------
# Basic rejection
# ---------------------------------------------------------------------------

class TestBasicRejection:
    def test_empty_bytes(self):
        assert decode(b"") is None

    def test_single_byte(self):
        for b in range(256):
            assert decode(bytes([b])) is None

    def test_all_zeros_various_lengths(self):
        for n in (0, 1, 7, 14, 21, 22, 64, 128):
            assert decode(bytes(n)) is None

    def test_all_ones(self):
        for n in (22, 32, 64):
            assert decode(bytes([0xFF] * n)) is None

    def test_invalid_version(self):
        wire = bytearray(_wire(_valid_packet()))
        for bad in (0, 3, 10, 127, 255):
            wire[0] = bad
            assert decode(bytes(wire)) is None, f"version={bad} should be rejected"

    def test_payload_length_exceeds_data(self):
        # v1 header: version=1, type, ttl, timestamp(8), flags, payloadLen(2), senderID(8)
        # Claim payload is 60000 bytes but provide only 30 bytes total
        header = struct.pack(">BBBQQHH", 1, 2, 7, 0, 1_711_000_000_000, 0, 60_000)
        # That pack is wrong — let me build it byte by byte
        raw = bytes([0x01, 0x02, 0x07])            # version, type, ttl
        raw += struct.pack(">Q", 1_711_000_000_000)  # timestamp 8 bytes
        raw += bytes([0x00])                          # flags
        raw += struct.pack(">H", 60_000)             # payload length = 60000
        raw += bytes(8)                               # sender ID
        raw += bytes(30)                              # only 30 bytes of "payload"
        assert decode(raw) is None

    def test_unsupported_version_3(self):
        wire = bytearray(_wire(_valid_packet()))
        wire[0] = 3
        assert decode(bytes(wire)) is None


# ---------------------------------------------------------------------------
# Truncation fuzzing
# ---------------------------------------------------------------------------

class TestTruncation:
    def test_every_prefix_is_safe(self):
        """Every proper prefix of a valid packet must return None."""
        wire = _wire(_valid_packet())
        for i in range(len(wire)):
            result = decode(wire[:i])
            assert result is None, (
                f"Expected None for wire[:{ i}] (full length={len(wire)}), got {result!r}"
            )

    def test_full_packet_decodes(self):
        pkt = _valid_packet()
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.payload == pkt.payload
        assert result.sender_id == pkt.sender_id

    def test_truncated_v2_packet(self):
        pkt = BitchatPacket(
            version=2,
            type=int(MessageType.NOISE_ENCRYPTED),
            ttl=3,
            timestamp=0,
            flags=0,
            sender_id=bytes(8),
            payload=b"v2 test",
        )
        wire = _wire(pkt)
        for i in range(len(wire)):
            result = decode(wire[:i])
            assert result is None, f"Prefix length {i} should return None"


# ---------------------------------------------------------------------------
# Bit-flip fuzzing
# ---------------------------------------------------------------------------

class TestBitFlip:
    def test_single_bit_flip_never_raises(self):
        """Flipping any single bit must never cause an exception."""
        wire = bytearray(_wire(_valid_packet(payload=b"bitflip test")))
        for byte_idx in range(len(wire)):
            for bit in range(8):
                flipped = bytearray(wire)
                flipped[byte_idx] ^= 1 << bit
                try:
                    decode(bytes(flipped))
                except Exception as exc:
                    pytest.fail(
                        f"decode() raised {type(exc).__name__} after flipping "
                        f"byte {byte_idx} bit {bit}: {exc}"
                    )

    def test_random_mutations_never_raise(self):
        """Randomly mutate a valid packet 50_000 times; decode must never raise."""
        wire = bytearray(_wire(_valid_packet()))
        rng = random.Random(0xDEADBEEF)
        for _ in range(50_000):
            mutated = bytearray(wire)
            for _ in range(rng.randint(1, 4)):
                idx = rng.randint(0, len(mutated) - 1)
                mutated[idx] = rng.randint(0, 255)
            try:
                decode(bytes(mutated))
            except Exception as exc:
                pytest.fail(f"decode() raised {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Random input fuzzing
# ---------------------------------------------------------------------------

class TestRandomInput:
    @pytest.mark.parametrize("seed", [0, 1, 42, 999, 0xCAFE])
    def test_random_bytes_never_raise(self, seed: int):
        """10_000 random byte sequences of varying length must never raise."""
        rng = random.Random(seed)
        for _ in range(10_000):
            n = rng.randint(0, 256)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            try:
                decode(data)
            except Exception as exc:
                pytest.fail(
                    f"decode() raised {type(exc).__name__} on "
                    f"{len(data)}-byte random input (seed={seed}): {exc}"
                )

    def test_large_random_blobs_never_raise(self):
        """Several large random blobs (up to 64KB) must never raise."""
        rng = random.Random(0xABCD)
        for _ in range(200):
            n = rng.randint(1000, 65535)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            try:
                decode(data)
            except Exception as exc:
                pytest.fail(f"decode() raised on {n}-byte blob: {exc}")


# ---------------------------------------------------------------------------
# Decompression bomb detection
# ---------------------------------------------------------------------------

class TestCompressionBomb:
    # The codec uses raw deflate (wbits=-15), not zlib-wrapped deflate.
    _DEFLATE = {"wbits": -15}

    def _compress(self, data: bytes) -> bytes:
        return zlib.compress(data, level=6, wbits=-15)

    def _make_compressed_v1_packet(
        self, original_size: int, compressed_payload: bytes
    ) -> bytes:
        """Craft a raw v1 packet with IS_COMPRESSED flag set."""
        flags = 0x04  # IS_COMPRESSED
        # payload in wire = original_size(2 bytes BE) + compressed_bytes
        original_size_clamped = min(original_size, 0xFFFF)
        payload_data = struct.pack(">H", original_size_clamped) + compressed_payload
        payload_len = len(payload_data)
        raw = bytes([0x01, 0x02, 0x07])  # version, type, ttl
        raw += struct.pack(">Q", 1_711_000_000_000)  # timestamp
        raw += bytes([flags])
        raw += struct.pack(">H", payload_len)
        raw += bytes(8)  # sender ID
        raw += payload_data
        return raw

    def test_legitimate_compression_accepted(self):
        """A legitimately compressed payload (low ratio) should decode."""
        original = bytes(range(256)) * 4  # 1 KB
        compressed = self._compress(original)
        raw = self._make_compressed_v1_packet(len(original), compressed)
        result = decode(raw)
        assert result is not None
        assert result.payload == original

    def test_bomb_ratio_rejected(self):
        """Claim a huge original_size vs tiny compressed blob → should return None."""
        compressed = self._compress(b"x" * 100)
        # Claim the original was 50_001 × len(compressed) + 1 bytes (ratio > 50_000)
        bomb_original = min(50_001 * len(compressed) + 1, 0xFFFF)
        raw = self._make_compressed_v1_packet(bomb_original, compressed)
        result = decode(raw)
        # If decompressed size != claimed size → None; if ratio detected → None
        assert result is None

    def test_mismatched_original_size_rejected(self):
        """Claim wrong original_size; decompressed length won't match → None."""
        original = b"hello world" * 5
        compressed = self._compress(original)
        wrong_original_size = len(original) + 100  # mismatch
        raw = self._make_compressed_v1_packet(wrong_original_size, compressed)
        assert decode(raw) is None


# ---------------------------------------------------------------------------
# TLV adversarial inputs
# ---------------------------------------------------------------------------

class TestTLVFuzz:
    def test_announcement_truncated_at_every_byte(self):
        from bitchat_protocol import AnnouncementPacket, encode_announcement, decode_announcement
        pkt = AnnouncementPacket(
            nickname="fuzz",
            noise_public_key=bytes(32),
            signing_public_key=bytes(32),
        )
        data = encode_announcement(pkt)
        assert data is not None
        for i in range(len(data)):
            result = decode_announcement(data[:i])
            assert result is None, f"prefix length {i} should return None"

    def test_announcement_random_bytes_never_raise(self):
        from bitchat_protocol import decode_announcement
        rng = random.Random(7)
        for _ in range(5_000):
            n = rng.randint(0, 128)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            try:
                decode_announcement(data)
            except Exception as exc:
                pytest.fail(f"decode_announcement raised: {exc}")

    def test_private_message_truncated_at_every_byte(self):
        from bitchat_protocol import PrivateMessagePacket, encode_private_message, decode_private_message
        pkt = PrivateMessagePacket(message_id="abc-123", content="hello")
        data = encode_private_message(pkt)
        assert data is not None
        for i in range(len(data)):
            result = decode_private_message(data[:i])
            assert result is None

    def test_private_message_random_bytes_never_raise(self):
        from bitchat_protocol import decode_private_message
        rng = random.Random(13)
        for _ in range(5_000):
            n = rng.randint(0, 64)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            try:
                decode_private_message(data)
            except Exception as exc:
                pytest.fail(f"decode_private_message raised: {exc}")


# ---------------------------------------------------------------------------
# Edge case values
# ---------------------------------------------------------------------------

class TestEdgeCaseValues:
    def test_max_ttl(self):
        pkt = _valid_packet()
        pkt = BitchatPacket(**{**pkt.__dict__, "ttl": 255})
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.ttl == 255

    def test_min_ttl(self):
        pkt = BitchatPacket(**{**_valid_packet().__dict__, "ttl": 0})
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.ttl == 0

    def test_max_timestamp(self):
        pkt = BitchatPacket(**{**_valid_packet().__dict__, "timestamp": 2**64 - 1})
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.timestamp == 2**64 - 1

    def test_zero_timestamp(self):
        pkt = BitchatPacket(**{**_valid_packet().__dict__, "timestamp": 0})
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.timestamp == 0

    def test_empty_payload(self):
        pkt = _valid_packet(payload=b"")
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.payload == b""

    def test_single_byte_payload(self):
        pkt = _valid_packet(payload=b"\x00")
        wire = _wire(pkt)
        result = decode(wire)
        assert result is not None
        assert result.payload == b"\x00"

    def test_all_message_types(self):
        for mt in MessageType:
            pkt = BitchatPacket(**{**_valid_packet().__dict__, "type": int(mt)})
            wire = _wire(pkt)
            result = decode(wire)
            assert result is not None, f"MessageType.{mt.name} failed"
            assert result.type == int(mt)

    def test_all_zero_sender_id(self):
        pkt = _valid_packet(sender_id=bytes(8))
        result = decode(_wire(pkt))
        assert result is not None
        assert result.sender_id == bytes(8)

    def test_all_ff_sender_id(self):
        pkt = _valid_packet(sender_id=bytes([0xFF] * 8))
        result = decode(_wire(pkt))
        assert result is not None


# ---------------------------------------------------------------------------
# Stress: high-volume round-trip
# ---------------------------------------------------------------------------

class TestStress:
    def test_10k_random_roundtrip(self):
        """10_000 random packets must encode and decode without loss."""
        rng = random.Random(0x1337)
        for i in range(10_000):
            payload_size = rng.randint(0, 64)
            pkt = BitchatPacket(
                version=1,
                type=rng.randint(1, 0x22),
                ttl=rng.randint(0, 7),
                timestamp=rng.randint(0, 2**63 - 1),
                flags=0,
                sender_id=bytes(rng.randint(0, 255) for _ in range(8)),
                payload=bytes(rng.randint(0, 255) for _ in range(payload_size)),
            )
            wire = encode(pkt, padding=False)
            assert wire is not None, f"encode failed at iteration {i}"
            result = decode(wire)
            assert result is not None, f"decode failed at iteration {i}"
            assert result.type == pkt.type
            assert result.ttl == pkt.ttl
            assert result.timestamp == pkt.timestamp
            assert result.sender_id == pkt.sender_id
            assert result.payload == pkt.payload

    def test_compression_roundtrip_large_payload(self):
        """32 KB compressible payload must round-trip and trigger compression."""
        payload = bytes(range(256)) * 128  # 32 KB
        pkt = _valid_packet(payload=payload)
        wire = encode(pkt, padding=False)
        assert wire is not None
        assert len(wire) < len(payload), "compression did not kick in"
        result = decode(wire)
        assert result is not None
        assert result.payload == payload

    def test_padding_roundtrip(self):
        """Padded packets must round-trip identically."""
        pkt = _valid_packet(payload=b"padded packet test")
        wire_padded = encode(pkt, padding=True)
        wire_bare = encode(pkt, padding=False)
        assert wire_padded is not None
        assert wire_bare is not None
        assert len(wire_padded) >= len(wire_bare)
        result = decode(wire_padded)
        assert result is not None
        assert result.payload == pkt.payload

    def test_v2_roundtrip(self):
        """v2 packets (4-byte length field) encode and decode correctly."""
        pkt = BitchatPacket(
            version=2,
            type=int(MessageType.NOISE_ENCRYPTED),
            ttl=5,
            timestamp=9_999_999_999_999,
            flags=0,
            sender_id=b"\xde\xad\xbe\xef\xca\xfe\xba\xbe",
            payload=b"v2 payload content",
        )
        wire = encode(pkt, padding=False)
        assert wire is not None
        result = decode(wire)
        assert result is not None
        assert result.version == 2
        assert result.payload == pkt.payload
