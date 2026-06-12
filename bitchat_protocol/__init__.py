"""
bitchat_protocol — BitChat binary protocol encode/decode for Python.

Quickstart:

    from bitchat_protocol import encode, decode, MessageType, AnnouncementPacket, BitchatPacket

    packet = BitchatPacket(
        version=1, type=int(MessageType.MESSAGE), ttl=7,
        timestamp=0, flags=0,
        sender_id=bytes.fromhex('abcdef0123456789'),
        payload=b'Hello, BitChat!',
    )
    wire = encode(packet)
    decoded = decode(wire)
"""

from .types import (
    MessageType,
    NoisePayloadType,
    PacketFlag,
    BitchatPacket,
    AnnouncementPacket,
    PrivateMessagePacket,
    RequestSyncPacket,
)
from .errors import (
    BitchatProtocolError,
    PacketTooShortError,
    PayloadTooLargeError,
    UnsupportedVersionError,
    TruncatedFieldError,
    DecompressionError,
    SuspiciousCompressionRatioError,
    TLVDecodeError,
    TLVEncodeError,
)
from .codec import encode, decode, hex_to_bytes, bytes_to_hex
from .tlv import (
    encode_announcement,
    decode_announcement,
    encode_private_message,
    decode_private_message,
)
from .sync import (
    MAX_P,
    MAX_ACCEPT_FILTER_BYTES,
    encode_request_sync,
    decode_request_sync,
    sync_type_flags_from_message_types,
    sync_type_flags_to_message_types,
)
from .peer import (
    peer_id_from_noise_key,
    peer_id_to_bytes,
    peer_id_from_bytes,
    nostr_geo_dm_peer_id,
    nostr_geo_chat_peer_id,
)

# Single source of truth for the package version (pyproject reads it via hatch).
__version__ = "0.1.3"

__all__ = [
    # Types
    "MessageType",
    "NoisePayloadType",
    "PacketFlag",
    "BitchatPacket",
    "AnnouncementPacket",
    "PrivateMessagePacket",
    "RequestSyncPacket",
    # Errors
    "BitchatProtocolError",
    "PacketTooShortError",
    "UnsupportedVersionError",
    "TruncatedFieldError",
    "DecompressionError",
    "PayloadTooLargeError",
    "SuspiciousCompressionRatioError",
    "TLVDecodeError",
    "TLVEncodeError",
    # Codec
    "encode",
    "decode",
    "hex_to_bytes",
    "bytes_to_hex",
    # TLV
    "encode_announcement",
    "decode_announcement",
    "encode_private_message",
    "decode_private_message",
    # Sync
    "MAX_P",
    "MAX_ACCEPT_FILTER_BYTES",
    "encode_request_sync",
    "decode_request_sync",
    "sync_type_flags_from_message_types",
    "sync_type_flags_to_message_types",
    # Peer
    "peer_id_from_noise_key",
    "peer_id_to_bytes",
    "peer_id_from_bytes",
    "nostr_geo_dm_peer_id",
    "nostr_geo_chat_peer_id",
]
