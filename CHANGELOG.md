# Changelog — bitchat_protocol (Python)

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-03-22

Initial GA release.

### Added
- `encode(packet, padding=False)` / `decode(data)` — binary packet encode/decode; `decode` never raises
- `BitchatPacket` dataclass: `version`, `type`, `ttl`, `timestamp`, `flags`, `sender_id`, `payload`
- Protocol v1 (14-byte header) and v2 (16-byte header) support
- Compression: raw deflate (wbits=-15) with 50,000:1 ratio safety cap; `IS_COMPRESSED` flag handling
- `MessageType` enum with all wire-defined message types
- TLV codec:
  - `AnnouncementPacket(nickname, noise_public_key, signing_public_key)`
  - `PrivateMessagePacket(message_id, content, recipient_id?, sender_id?, timestamp?)`
  - `encode_announcement(pkt)` / `decode_announcement(data)` → `AnnouncementPacket | None`
  - `encode_private_message(pkt)` / `decode_private_message(data)` → `PrivateMessagePacket | None`
- `peer_id_from_noise_key(noise_public_key)` — derive 8-byte peer ID from 32-byte key
- `peer_id_to_hex(peer_id)` / `peer_id_from_hex(hex_str)` — hex conversion helpers
- Cross-language compatibility: wire format matches `@bitchat/protocol-core` (JS) and `BitchatProtocol` (Swift)
- Comprehensive fuzz and stress test suite (38 tests)

### Protocol Compatibility
Wire-format compatible with BitChat iOS (Swift), BitChat Android (Kotlin), `@bitchat/protocol-core`, and `BitchatProtocol`.

[0.1.0]: https://github.com/bitchat-sdk/protocol-core-py/releases/tag/v0.1.0

[Unreleased]: https://github.com/bitchat-sdk/protocol-core-py/compare/v0.1.0...HEAD