# TrustChain Python SDK

[![PyPI](https://img.shields.io/pypi/v/trustchain-py.svg)](https://pypi.org/project/trustchain-py/)
[![CI](https://github.com/viftode4/trustchain-py/actions/workflows/ci.yml/badge.svg)](https://github.com/viftode4/trustchain-py/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Decentralized trust for AI agents. One decorator, zero config.**

TrustChain gives every agent-to-agent interaction a cryptographic trust score — without changing your code. Add one decorator, and all HTTP calls are automatically trust-protected via a transparent sidecar proxy. No blockchain, no tokens, no gas fees.

## Quick Start

```bash
pip install trustchain-py
```

```python
from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # All outbound HTTP calls are now trust-protected.
    # The sidecar binary downloads automatically on first run.
    import requests
    requests.get("https://other-agent.example.com/api")

main()
```

That's it. The `@with_trust` decorator:
1. Downloads the `trustchain-node` binary (if not already present)
2. Starts the sidecar proxy
3. Sets `HTTP_PROXY` so all HTTP calls go through the trust layer
4. Cleans up on exit

### Trust tools for agent frameworks

```python
from trustchain import with_trust, trust_tools

@with_trust()
def main():
    tools = trust_tools()  # 4 tools: check_trust, discover_peers, get_interaction_history, verify_chain
    # Pass to LangChain, CrewAI, or any agent framework
    for tool in tools:
        print(f"{tool['name']}: {tool['description']}")

main()
```

### Framework integrations

```python
# LangChain — record interactions as trust blocks
from trustchain.integrations.langchain import TrustChainCallbackHandler
app.invoke(input, config={"callbacks": [TrustChainCallbackHandler()]})

# FastAPI — auto-inject trust headers
from trustchain.integrations.asgi import TrustChainMiddleware
app.add_middleware(TrustChainMiddleware)

# MCP — gate tools on trust score
from trustchain.integrations.mcp import TrustChainMCPMiddleware
server.add_middleware(TrustChainMCPMiddleware(min_trust=0.5))

# CrewAI — record crew runs
from trustchain.integrations.crewai import trust_crew
crew = trust_crew(crew)
```

Install extras: `pip install trustchain-py[langchain]`, `[mcp]`, `[crewai]`

### CLI

```bash
trustchain wrap -- python my_agent.py   # run any command with trust proxy
trustchain status                        # query running sidecar
trustchain download                      # pre-download binary (for Docker/CI)
trustchain demo                          # 3-agent demo with live trust visualization
```

## How It Works

```
Your agent process
      │
      ├── @with_trust / trustchain.init()
      │         │
      │         ├── Downloads trustchain-node binary (first run)
      │         ├── Starts sidecar on localhost
      │         └── Sets HTTP_PROXY → sidecar (:8203)
      │
      └── All HTTP requests → sidecar → bilateral trust handshake → forward to destination
```

Every call to a known TrustChain peer triggers an invisible bilateral handshake: both parties sign a half-block recording the interaction. Trust scores emerge from real interaction history, verified via NetFlow Sybil analysis.

## Programmatic Usage

```python
import trustchain

# Create identities
alice = trustchain.Identity()
bob = trustchain.Identity()

# Proposal/agreement protocol
store = trustchain.MemoryBlockStore()
protocol = trustchain.TrustChainProtocol(alice, store)
proposal = protocol.create_proposal(bob.pubkey_hex, {"type": "service_call"})

# Trust scoring
engine = trustchain.TrustEngine(store)
score = engine.compute_trust(bob.pubkey_hex)
```

## Modules

| Module | Description |
|--------|-------------|
| `trustchain.sidecar` | `TrustChainSidecar`, `@with_trust`, `init()`, `download_binary()` |
| `trustchain.tools` | `trust_tools()` — framework-agnostic trust tools |
| `trustchain.integrations` | LangChain, FastAPI/ASGI, MCP, CrewAI adapters |
| `trustchain.cli` | CLI entry point (`trustchain` command) |
| `trustchain.protocol` | `TrustChainProtocol` — proposal/agreement state machine |
| `trustchain.trust` | `TrustEngine` — NetFlow + chain integrity + statistical scoring |
| `trustchain.netflow` | NetFlow Sybil resistance (max-flow from seed nodes) |
| `trustchain.identity` | Ed25519 keypair generation and management |
| `trustchain.halfblock` | `HalfBlock` data structure, signing, and validation |
| `trustchain.blockstore` | `MemoryBlockStore` and `SqliteBlockStore` |
| `trustchain.delegation` | Identity delegation, succession, and revocation |
| `trustchain.crawler` | Network graph crawler and DAG builder |

## Development

```bash
git clone https://github.com/viftode4/trustchain-py.git
cd trustchain-py
pip install -e ".[dev]"
python -m pytest tests/ -v   # 311 tests
```

## Public Seed Node

A public seed node is running at `http://5.161.255.238:8202`. It is the default bootstrap peer — agents connect automatically without any configuration.

> Early-access: not production-scale yet. Will be replaced with a domain and additional nodes as the network grows.

## Protocol

Implements [draft-pouwelse-trustchain-01](https://datatracker.ietf.org/doc/draft-pouwelse-trustchain/) (Pouwelse, TU Delft, 2018) — the base bilateral ledger protocol. Trust computation, NetFlow Sybil resistance, delegation, and succession are specified in draft-viftode-trustchain-trust-00 (filed March 2026). Rust is the authoritative implementation; Python stays wire-compatible.

## Related Projects

- [trustchain](https://github.com/viftode4/trustchain) — Rust core: sidecar binary, QUIC P2P, MCP server, dashboard
- [trustchain-js](https://github.com/viftode4/trustchain-js) — TypeScript SDK
- [trustchain-agent-os](https://github.com/viftode4/trustchain-agent-os) — Agent framework adapters (12 frameworks)

## License

MIT
