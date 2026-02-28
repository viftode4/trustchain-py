# TrustChain SDK

Python SDK for TrustChain — decentralized trust primitives for agents, humans, and devices.

## Installation

```bash
pip install trustchain-sdk
```

## Quick Start

```python
import trustchain

# Create identities
alice = trustchain.Identity()
bob = trustchain.Identity()

# Create a protocol instance
protocol = trustchain.TrustChainProtocol()

# Propose an interaction
proposal = protocol.propose(alice, bob, transaction={"type": "service", "outcome": "completed"})

# Bob agrees
agreement = protocol.agree(bob, proposal)
```

### Zero-config sidecar (with Rust binary)

```python
import trustchain

# Start the TrustChain sidecar — all HTTP calls are now trust-protected
trustchain.init()

# That's it. Every outbound HTTP request goes through the transparent proxy.
```

## Installing the Rust Binary

The sidecar requires the `trustchain-node` binary. Install it via:

```bash
# From crates.io
cargo install trustchain-node

# Or download from GitHub Releases
# https://github.com/levvlad/trustchain/releases

# Or place the binary at ~/.trustchain/bin/trustchain-node
```

## Modules

| Module | Description |
|--------|-------------|
| `trustchain.identity` | Ed25519 identity management |
| `trustchain.halfblock` | Half-block data structure and validation |
| `trustchain.blockstore` | Block storage (memory + SQLite) |
| `trustchain.protocol` | Protocol state machine |
| `trustchain.trust` | Trust computation engine |
| `trustchain.netflow` | NetFlow Sybil resistance |
| `trustchain.consensus` | CHECO consensus |
| `trustchain.chain` | Chain operations and validation |
| `trustchain.crawler` | Network crawler and DAG view |
| `trustchain.transport` | QUIC, HTTP, discovery, connection pooling |
| `trustchain.grpc` | gRPC client/server |
| `trustchain.api` | FastAPI HTTP node |
| `trustchain.sidecar` | Rust binary manager (zero-config) |

## Related Projects

- [trustchain](https://github.com/levvlad/trustchain) — Rust node and core crates
- [trustchain-agent-os](https://github.com/levvlad/trustchain-agent-os) — Agent framework with trust-native protocol layer

## License

MIT
