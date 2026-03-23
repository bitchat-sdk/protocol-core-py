"""Tests for the TLV codec — AnnouncementPacket and PrivateMessagePacket."""

import pytest
from bitchat_protocol import (
    AnnouncementPacket,
    PrivateMessagePacket,
    encode_announcement,
    decode_announcement,
    encode_private_message,
    decode_private_message,
)

ZERO_KEY = bytes(32)
KEY_B = bytes([0xab] * 32)


class TestAnnouncementPacket:
    def test_roundtrip_minimal(self):
        original = AnnouncementPacket(
            nickname="Alice",
            noise_public_key=ZERO_KEY,
            signing_public_key=KEY_B,
        )
        encoded = encode_announcement(original)
        decoded = decode_announcement(encoded)
        assert decoded is not None
        assert decoded.nickname == "Alice"
        assert decoded.noise_public_key == ZERO_KEY
        assert decoded.signing_public_key == KEY_B
        assert decoded.direct_neighbors is None

    def test_roundtrip_with_neighbors(self):
        n1 = bytes(range(8))
        n2 = bytes(range(8, 16))
        original = AnnouncementPacket(
            nickname="Bob",
            noise_public_key=ZERO_KEY,
            signing_public_key=ZERO_KEY,
            direct_neighbors=[n1, n2],
        )
        decoded = decode_announcement(encode_announcement(original))
        assert decoded is not None
        assert decoded.direct_neighbors is not None
        assert len(decoded.direct_neighbors) == 2
        assert decoded.direct_neighbors[0] == n1
        assert decoded.direct_neighbors[1] == n2

    def test_unicode_nickname(self):
        original = AnnouncementPacket(
            nickname="こんにちは",
            noise_public_key=ZERO_KEY,
            signing_public_key=ZERO_KEY,
        )
        decoded = decode_announcement(encode_announcement(original))
        assert decoded is not None
        assert decoded.nickname == "こんにちは"

    def test_skips_unknown_tags(self):
        """Unknown TLV tags must be skipped (forward-compatible)."""
        original = AnnouncementPacket(
            nickname="Alice",
            noise_public_key=ZERO_KEY,
            signing_public_key=ZERO_KEY,
        )
        valid = encode_announcement(original)
        # Prepend an unknown TLV (tag=0xff, len=3, value=0x112233)
        unknown = bytes([0xff, 0x03, 0x11, 0x22, 0x33])
        with_unknown = unknown + valid
        decoded = decode_announcement(with_unknown)
        assert decoded is not None, "Should decode despite unknown TLV tag"
        assert decoded.nickname == "Alice"

    def test_returns_none_missing_required_fields(self):
        # Only nickname TLV, no keys
        partial = bytes([0x01, 0x05]) + b"Alice"
        assert decode_announcement(partial) is None

    def test_returns_none_truncated(self):
        original = AnnouncementPacket(
            nickname="Alice",
            noise_public_key=ZERO_KEY,
            signing_public_key=ZERO_KEY,
        )
        encoded = encode_announcement(original)
        assert decode_announcement(encoded[:4]) is None

    def test_caps_neighbors_at_10(self):
        """Only up to 10 neighbors are encoded."""
        neighbors = [bytes([i] * 8) for i in range(15)]
        original = AnnouncementPacket(
            nickname="X",
            noise_public_key=ZERO_KEY,
            signing_public_key=ZERO_KEY,
            direct_neighbors=neighbors,
        )
        decoded = decode_announcement(encode_announcement(original))
        assert decoded is not None
        assert decoded.direct_neighbors is not None
        assert len(decoded.direct_neighbors) <= 10


class TestPrivateMessagePacket:
    def test_roundtrip_basic(self):
        original = PrivateMessagePacket(message_id="msg-001", content="Hello")
        decoded = decode_private_message(encode_private_message(original))
        assert decoded is not None
        assert decoded.message_id == "msg-001"
        assert decoded.content == "Hello"

    def test_roundtrip_unicode_content(self):
        original = PrivateMessagePacket(message_id="u-1", content="こんにちは")
        decoded = decode_private_message(encode_private_message(original))
        assert decoded is not None
        assert decoded.content == "こんにちは"

    def test_roundtrip_empty_content(self):
        original = PrivateMessagePacket(message_id="empty", content="")
        decoded = decode_private_message(encode_private_message(original))
        assert decoded is not None
        assert decoded.content == ""

    def test_strict_rejects_unknown_tag(self):
        """PrivateMessagePacket decoder is strict: unknown tags → None."""
        valid = encode_private_message(PrivateMessagePacket(message_id="id", content="hi"))
        # Prepend unknown tag
        bad = bytes([0xff, 0x01, 0xaa]) + valid
        assert decode_private_message(bad) is None

    def test_returns_none_missing_fields(self):
        # Only messageID, no content (truncated to just the first TLV)
        encoded = encode_private_message(PrivateMessagePacket(message_id="x", content="hi"))
        assert decode_private_message(encoded[:4]) is None
