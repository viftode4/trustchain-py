# TrustChain Python SDK — 5-Minute Quickstart

**What you'll have after this**: a running trust layer for your agents or services, with signed interaction records and optional multi-agent trust scoring.

**No blockchain. No gas fees. No validators.**

---

## Install

```bash
pip install trustchain-py
```

The Rust sidecar binary downloads automatically on first use from GitHub Releases. To pre-download it:

```bash
trustchain download
```

---

## Pick your path

| Path | When to use |
|------|-------------|
| [Zero-config decorator](#path-1-zero-config-decorator) | Wrapping an existing app — least code |
| [Audit mode](#path-2-audit-mode) | Single-agent, offline, no peers needed |
| [Multi-agent trust](#path-3-multi-agent-trust) | Two or more agents interacting |
| [LangChain integration](#path-4-langchain--langgraph) | LangChain or LangGraph apps |

---

## Path 1: Zero-config decorator

Wraps your function in a trust-protected sidecar. All outbound HTTP calls are routed through the proxy automatically — no code changes inside the function.

```python
from trustchain import with_trust

@with_trust
def main():
    import httpx
    resp = httpx.get("https://api.example.com/data")
    print(resp.json())

main()
```

The decorator starts the sidecar, sets `HTTP_PROXY`, runs your function, then shuts down cleanly. Works with `async def` too.

---

## Path 2: Audit mode

Single-agent operation. No peers, no network required. Useful for compliance logging, tamper-evident audit trails, and offline environments.

```python
from trustchain import TrustChainSidecar

with TrustChainSidecar(name="my-agent", bootstrap=[]) as tc:
    # Record signed audit entries
    tc.audit({"event_type": "tool_call", "action": "web_search", "outcome": "success"})
    tc.audit({"event_type": "decision", "action": "selected_provider_a", "outcome": "completed"})

    # Verify the chain
    report = tc.audit_report()
    print(f"Chain integrity: {report['integrity_score']}")

    # Export a signed bundle (share with auditors, store for compliance)
    bundle = tc.export_chain()
```

`bootstrap=[]` keeps the sidecar fully offline — it will not attempt to reach any seed node.

---

## Path 3: Multi-agent trust

Two or more agents exchange bilateral signed interaction records. Each side signs; neither side can forge the other's signature.

```python
from trustchain import TrustChainSidecar

alice = TrustChainSidecar(name="alice")
bob = TrustChainSidecar(name="bob")

# Introduce agents to each other
alice.register_peer(bob.pubkey, bob.http_url)
bob.register_peer(alice.pubkey, alice.http_url)

# Record a bilateral interaction (both sides sign)
alice.propose(bob.pubkey, {"type": "task_completion", "task": "data_analysis"})

# Query trust score
score = alice.trust_score(bob.pubkey)
print(f"Alice trusts Bob: {score}")
```

Trust score is a float in `[0.0, 1.0]` computed from four factors: connectivity, chain integrity, peer diversity, and recency-weighted outcomes.

> **Tip:** Open the dashboard to inspect chains visually: `http://127.0.0.1:{port}/dashboard`

---

## Path 4: LangChain / LangGraph

Drop-in callback — no other changes to your app.

```python
from trustchain.integrations.langchain import TrustChainCallbackHandler

handler = TrustChainCallbackHandler()
app.invoke(input, config={"callbacks": [handler]})
```

Every LLM call, tool call, and chain step is recorded as a signed audit entry. Other integrations live in `trustchain.integrations`: `asgi`, `mcp`, `crewai`.

---

## CLI reference

```bash
trustchain download          # Pre-download the sidecar binary
trustchain demo              # Run an interactive 3-agent demo
trustchain log               # Print the local audit trail
trustchain verify            # Verify chain integrity
trustchain export -o chain.json  # Export signed chain to a file
```

---

## Key facts

- **Identity**: Ed25519 keypair auto-generated on first run, stored locally. Your public key is your agent's permanent identifier.
- **Wire format**: JSON with sorted keys for canonical hashing. Human-readable and inspectable.
- **Seed node**: connects to `5.161.255.238:8202` by default for Sybil-resistance scoring. Pass `bootstrap=[]` to disable.
- **Proxy model**: the sidecar runs on `localhost:{port}`. Set `HTTP_PROXY` to that address and trust is transparent to your application code.
- **Timestamps**: all values are integer milliseconds (never float seconds).

---

## What's next

- `trustchain demo` — watch three agents build trust from scratch
- [API reference](./api.md) — full `TrustChainSidecar` method list
- [Trust model](./trust-model.md) — how the four-factor score is computed
- [Integrations](./integrations.md) — ASGI middleware, MCP, CrewAI adapters
