# TrustChain Python SDK

[![PyPI](https://img.shields.io/pypi/v/trustchain-py.svg)](https://pypi.org/project/trustchain-py/)
[![CI](https://github.com/viftode4/trustchain-py/actions/workflows/ci.yml/badge.svg)](https://github.com/viftode4/trustchain-py/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Python SDK for TrustChain — decentralized trust primitives for AI agents.**

`trustchain-py` is the Python face of the TrustChain trust primitive. At its simplest it is a one-liner (`trustchain.init()`) that downloads and starts the Rust sidecar binary, sets `HTTP_PROXY`, and makes every outbound HTTP call trust-protected. For agents that need full programmatic control it exposes the complete protocol: Ed25519 identities, half-block creation and validation, chain storage, trust computation, NetFlow Sybil resistance, QUIC transport, and gRPC. 290 tests.

## Installation

```bash
pip install trustchain-py
```

### Optional extras

```bash
pip install trustchain-py[quic]   # QUIC P2P transport (aioquic)
pip install trustchain-py[grpc]   # gRPC client/server (grpcio + protobuf)
pip install trustchain-py[node]   # full Python node (hypercorn ASGI)
pip install trustchain-py[all]    # everything above
```

Requires Python 3.11+.

## Quick Start

### Zero-config sidecar (recommended)

```python
import trustchain

# Downloads the Rust binary if needed, starts the sidecar, sets HTTP_PROXY.
# All outbound HTTP calls from this process are now trust-protected.
trustchain.init()
```

That is the entire integration for most agents. The sidecar runs on port 8203 as a transparent HTTP proxy; agents never call TrustChain directly.

The sidecar binary (`trustchain-node`) must be available. Install it separately:

```bash
# From crates.io
cargo install trustchain-node

# Or place the binary at ~/.trustchain/bin/trustchain-node
# Or download from https://github.com/levvlad/trustchain/releases
```

### Programmatic protocol usage

```python
import trustchain

# Create identities
alice = trustchain.Identity()
bob = trustchain.Identity()

# Create a protocol instance backed by an in-memory block store
store = trustchain.MemoryBlockStore()
protocol = trustchain.TrustChainProtocol(alice, store)

# Alice proposes an interaction with Bob
proposal = protocol.create_proposal(
    bob.pubkey_hex,
    {"type": "service_call", "outcome": "completed"},
)

# Bob validates the proposal and creates the counter-signed agreement
bob_protocol = trustchain.TrustChainProtocol(bob, store)
agreement = bob_protocol.create_agreement(proposal)

print(f"Block pair recorded: seq={proposal.sequence_number}")
```

### Trust scoring

```python
from trustchain.trust import TrustEngine
from trustchain.blockstore import SqliteBlockStore

store = SqliteBlockStore("agent.db")
engine = TrustEngine(store)

score = engine.compute_trust(peer_pubkey)
print(f"Trust score for peer: {score:.3f}")  # 0.0 to 1.0
```

### SQLite-backed node

```python
import asyncio
from trustchain.api import TrustChainNode

async def main():
    node = TrustChainNode(db_path="agent.db")
    await node.start()          # serves HTTP REST on :8202
    await node.run_forever()

asyncio.run(main())
```

## Modules

| Module | Description |
|--------|-------------|
| `trustchain.identity` | Ed25519 keypair generation, loading, and serialization |
| `trustchain.halfblock` | `HalfBlock` data structure, signing, and validation |
| `trustchain.blockstore` | `MemoryBlockStore` and `SqliteBlockStore` |
| `trustchain.protocol` | `TrustChainProtocol` — proposal/agreement state machine |
| `trustchain.trust` | `TrustEngine` — weighted three-component trust scoring |
| `trustchain.netflow` | NetFlow Sybil resistance (max-flow from seed nodes) |
| `trustchain.consensus` | CHECO checkpoint consensus |
| `trustchain.chain` | Chain operations, validation, and gap detection |
| `trustchain.crawler` | Network graph crawler and DAG view builder |
| `trustchain.transport` | QUIC P2P, HTTP connection pooling, peer discovery |
| `trustchain.grpc` | gRPC client and server (requires `[grpc]` extra) |
| `trustchain.api` | FastAPI HTTP node (full REST API, same endpoints as Rust) |
| `trustchain.sidecar` | Rust binary manager — download, start, health-check, proxy setup |
| `trustchain.delegation` | Identity delegation, succession, and revocation |

## Trust Score Components

`TrustEngine.compute_trust(pubkey)` returns a weighted score from three components:

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| **Chain Integrity** | 30% | Hash links valid, no sequence gaps, Ed25519 signatures verify |
| **NetFlow** | 40% | Max-flow from seed nodes — primary Sybil resistance |
| **Statistical** | 30% | Volume, completion rate, counterparty diversity, account age, entropy |

## Architecture

```
Your Python agent
      │
      ├── trustchain.init()          sets HTTP_PROXY → Rust sidecar (:8203)
      │                              (transparent, zero-code-change integration)
      │
      └── trustchain.TrustChainProtocol  (full programmatic control)
              │
              ├── Identity           Ed25519 keypair
              ├── BlockStore         MemoryBlockStore / SqliteBlockStore
              ├── TrustEngine        NetFlow + chain integrity + statistical
              └── Transport          QUIC P2P / HTTP REST / gRPC
```

The Python SDK's `trustchain.api.TrustChainNode` implements the same HTTP REST API as the Rust binary. The Rust binary is recommended for production deployments; the Python node is useful for testing and environments where the binary is unavailable.

> **Note**: The sidecar delegation API endpoints (`/trustchain/delegate` etc.) are implemented in the Python SDK's `TrustChainNode` only. The Rust sidecar does not expose these endpoints — use the standard `/delegate` and `/revoke` REST endpoints on the Rust node's HTTP API instead.

## Development

```bash
git clone https://github.com/levvlad/trustchain-py.git
cd trustchain-py
pip install -e ".[dev]"
pytest tests/ -v
```

## Related Projects

- [trustchain](https://github.com/levvlad/trustchain) — Rust node: production sidecar binary, core crates, QUIC P2P, MCP server
- [trustchain-agent-os](https://github.com/levvlad/trustchain-agent-os) — Agent framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, Google ADK, ElizaOS)

## License

MIT
