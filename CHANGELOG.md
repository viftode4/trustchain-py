# Changelog

## 2.1.0 (2026-02-28)

### Breaking Changes
- `aioquic`, `grpcio`, `protobuf`, and `hypercorn` are now **optional** dependencies
  - Base install: `pip install trustchain-sdk` (lightweight, HTTP-only)
  - QUIC transport: `pip install trustchain-sdk[quic]`
  - gRPC transport: `pip install trustchain-sdk[grpc]`
  - Full install: `pip install trustchain-sdk[all]`

### Features
- **Delegation certificate verification**: verify via backing block signature
- **Scope enforcement**: `create_proposal()` enforces delegation scope on interaction types
- **Revocation check on accept**: `accept_delegation()` rejects already-revoked delegations
- **Sidecar wrappers**: added `chain()`, `block()`, `crawl()`, `metrics()` methods
- **Rust-compatible paths**: all client/transport paths match Rust sidecar endpoints

### Fixes
- Fraud propagation checks ALL delegates (active + revoked), not just active
- QUIC transport: persist connections instead of closing after first use
- `init_delegate()` URL fixed from `/trustchain/delegate` to `/delegate`
- Delegation expiry edge case: `>` changed to `>=` for TTL=0 consistency

### Deprecations
- `TrustChainNode` emits `DeprecationWarning` — use `TrustChainSidecar` instead

## 2.0.0

- Initial v2 release with half-block protocol
- TrustEngine with NetFlow Sybil resistance
- Delegation protocol (create, accept, revoke, succession)
- QUIC P2P transport
- HTTPS transport with TLS
- gRPC transport
- Consensus (CHECO)
- Sidecar SDK with `trustchain.init()`
