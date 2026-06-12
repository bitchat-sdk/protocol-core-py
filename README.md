# bitchat-protocol

[![PyPI](https://img.shields.io/pypi/v/bitchat-protocol)](https://pypi.org/project/bitchat-protocol/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org)

BitChat binary protocol encode/decode for Python.

Implements the wire format from the BitChat mesh networking protocol:
binary packet encode/decode, TLV codec for announcement and private message
structures, and peer ID derivation utilities.

## Installation

```bash
pip install bitchat-protocol
```

Requires Python 3.10+.

## Quick Start

```python
from bitchat_protocol import (
    encode, decode,
    BitchatPacket, MessageType,
    encode_announcement, decode_announcement,
    AnnouncementPacket,
    peer_id_from_noise_key,
)

# Encode a broadcast message
import time
packet = BitchatPacket(
    version=1,
    type=int(MessageType.MESSAGE),
    ttl=7,
    timestamp=int(time.time() * 1000),
    flags=0,
    sender_id=bytes.fromhex('abcdef0123456789'),
    payload='Hello, BitChat!'.encode(),
)
wire = encode(packet, padding=True)   # padded for BLE transmission

# Decode from bytes received over BLE or Nostr relay
decoded = decode(wire)
if decoded:
    print('type:', decoded.type)
    print('payload:', decoded.payload.decode())
```

## API

### Packet Encode/Decode

```python
encode(packet: BitchatPacket, *, padding: bool = False) -> bytes
decode(data: bytes) -> BitchatPacket | None
```

`decode()` returns `None` (never raises) on invalid or truncated input.

### TLV: AnnouncementPacket

```python
encode_announcement(packet: AnnouncementPacket) -> bytes
decode_announcement(data: bytes) -> AnnouncementPacket | None
```

Decoder is **lenient**: unknown TLV tags are skipped (forward-compatible).

### TLV: PrivateMessagePacket

```python
encode_private_message(packet: PrivateMessagePacket) -> bytes
decode_private_message(data: bytes) -> PrivateMessagePacket | None
```

Decoder is **strict**: returns `None` on any unknown TLV tag.

### TLV: RequestSyncPacket

REQUEST_SYNC gossip-sync payloads carrying [GCS](https://en.wikipedia.org/wiki/Golomb_coding) filter parameters. Unlike the TLVs above, these use **16-bit big-endian lengths**.

```python
encode_request_sync(packet: RequestSyncPacket) -> bytes
decode_request_sync(data: bytes, max_accept_bytes: int = MAX_ACCEPT_FILTER_BYTES) -> RequestSyncPacket | None

@dataclass
class RequestSyncPacket:
    p: int                                    # Golomb-Rice parameter (decode accepts 1..=MAX_P = 32)
    m: int                                    # hash range M = N * 2^P (uint32)
    data: bytes                               # GR bitstream bytes (MSB-first)
    types: int | None = None                  # sync-type flags bitmask
    since_timestamp: int | None = None        # only sync packets newer than this (ms, uint64)
    fragment_id_filter: str | None = None     # restrict sync to one fragment ID
```

```python
from bitchat_protocol import (
    MessageType, RequestSyncPacket,
    encode_request_sync, decode_request_sync, sync_type_flags_from_message_types,
)

wire = encode_request_sync(RequestSyncPacket(
    p=19,
    m=1 << 19,
    data=gcs_filter_bytes,
    types=sync_type_flags_from_message_types([MessageType.ANNOUNCE, MessageType.MESSAGE]),
))
request = decode_request_sync(wire)  # None on any invalid input
```

The decoder is **lenient about unknown tags** (forward-compatible — the optional
`types`/`since_timestamp`/`fragment_id_filter` TLVs are iOS-side extensions that
older decoders skip) and **strict about validity**: it rejects `p` outside
`1..=MAX_P` (32), `m = 0`, missing required fields, and filter data larger than
`max_accept_bytes` (default `MAX_ACCEPT_FILTER_BYTES` = 1024, a DoS guard).

Helpers: `sync_type_flags_from_message_types(types)` / `sync_type_flags_to_message_types(flags)`
convert between `list[MessageType]` and the flags bitmask.

### Peer ID Utilities

```python
peer_id_from_noise_key(noise_public_key: bytes) -> str   # 16-char hex
peer_id_to_bytes(peer_id: str) -> bytes                  # 8 bytes
peer_id_from_bytes(data: bytes) -> str                   # 16-char hex
nostr_geo_dm_peer_id(nostr_pubkey_hex: str) -> str       # "nostr_" + prefix
nostr_geo_chat_peer_id(nostr_pubkey_hex: str) -> str     # "nostr:" + prefix
```

### Utilities

```python
hex_to_bytes(hex_str: str) -> bytes
bytes_to_hex(data: bytes) -> str
```

## Wire Format

### v1 Header (14 bytes)
```
[version:1][type:1][ttl:1][timestamp:8 BE uint64][flags:1][payloadLen:2 BE uint16]
[senderID:8]
[recipientID:8]         — if flags & HAS_RECIPIENT
[payload:payloadLen]
[signature:64]          — if flags & HAS_SIGNATURE
```

### v2 Header (16 bytes)
Same but `payloadLen` is 4 bytes (BE uint32) and source routing is supported.

### Flags Byte
| Bit | Value | Name |
|-----|-------|------|
| 0 | 0x01 | HAS_RECIPIENT |
| 1 | 0x02 | HAS_SIGNATURE |
| 2 | 0x04 | IS_COMPRESSED |
| 3 | 0x08 | HAS_ROUTE (v2+ only) |
| 4 | 0x10 | IS_RSR |

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Compatibility

This package implements the same binary wire format as:
- `ios/bitchat/Protocols/BinaryProtocol.swift`
- `android/.../BinaryProtocol.kt`

Cross-language compatibility is verified against the
[`bitchat-sdk/spec-tests`](https://github.com/bitchat-sdk/spec-tests) golden
fixture suite. Clone that repo as a sibling of this one, then `pytest`
runs all cross-language vectors automatically — without it, the fixture
suite silently skips.

## License

Unlicense — public domain.
