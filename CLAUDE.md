# TrustChain Python SDK -- Claude Code Instructions

Python SDK for TrustChain. PyPI name: `trustchain-py`. Import as `import trustchain`.
Implements IETF draft-pouwelse-trustchain-01 with NetFlow Sybil resistance.

## Setup & Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -x -q   # 311 tests; 1 pre-existing gRPC port-bind failure is expected
```

CI runs on ubuntu/windows/macos x Python 3.11/3.12/3.13. Integration job builds Rust binary and
sets `TRUSTCHAIN_BIN` env var -- tests skip Rust-dependent cases when the var is absent.

## Package Structure (`src/trustchain/`)

| Module | Purpose |
|---|---|
| `halfblock.py` | v2 `HalfBlock`, `BlockType`, `compute_block_hash`, `create_half_block`, `sign_block`, `verify_block` |
| `protocol.py` | `TrustChainProtocol` -- two-phase proposal/agreement engine; `MAX_DELEGATION_TTL_MS` |
| `block.py` | v1 compat `Block`/`HalfBlock` projections over `InteractionRecord` (read-only) |
| `blockstore.py` | `BlockStore` ABC, `MemoryBlockStore`, `SQLiteBlockStore` |
| `trust.py` | `TrustEngine`, completion-rate scoring with temporal decay |
| `netflow.py` | `NetFlowTrust` -- max-flow Sybil resistance; incremental graph via `_known_seqs` |
| `delegation/` | `DelegationCertificate`, `DelegationRecord`, `DelegationStore`, `MemoryDelegationStore` |
| `transport/` | `Transport` ABC, `HTTPTransport`, QUIC transport (optional dep `aioquic`) |
| `sidecar.py` | `TrustChainSidecar` -- zero-config client wrapping the Rust sidecar binary |
| `crawler.py` | `BlockStoreCrawler`, `HTTPCrawler`, `ChainCrawler`, `DAGView`, `TamperingReport` |
| `exceptions.py` | Typed exceptions: `DelegationError`, `SignatureError`, `ProposalError`, etc. |

## Key Conventions

**Timestamps** -- always `int` milliseconds, never `float` seconds. Use `_now_ms()` from `halfblock.py`.

**Canonical JSON hashing** -- `json.dumps(obj, sort_keys=True, separators=(',', ':'))` with
`signature=""` zeroed before hashing. Signatures are Ed25519 over UTF-8 of the hex `block_hash`.

**Use `TrustChainSidecar`**, not the deprecated `TrustChainNode`. Sidecar HTTP paths:
`/receive_proposal`, `/receive_agreement`, `/accept_delegation`, `/accept_succession`,
`/crawl`, `/status`, `/healthz`, `/metrics`.

**Delegation** -- `MAX_DELEGATION_TTL_MS = 30 * 24 * 3600 * 1000` (30 days) enforced in
`protocol.py`. Empty scope under a restricted parent = privilege escalation = rejected.
Raise `DelegationError` for all delegation failures, not generic exceptions.

**Trust scores** -- no `round()` on trust values (breaks Rust parity). NetFlow zero -> score zero
when seed nodes are configured (Sybil gate must not be bypassed by statistical fallback).

## Rust Parity

This SDK must stay wire-compatible with `trustchain-rs` (Rust workspace). Same hash algorithm,
same block field order (BTreeMap sorted keys), same constants. **Rust is authoritative** -- when
behavior is ambiguous, match Rust. Run the integration CI job to verify cross-language compat.

## Do Not

- Use `float` for timestamps -- always `int` ms.
- Call `round()` on trust scores.
- Auto-accept delegations or successions -- both require explicit caller action.
- Add runtime dependencies without discussion (current core deps: `cryptography`, `networkx`,
  `fastapi`, `uvicorn`, `httpx`; extras: `aioquic`, `grpcio`, `hypercorn`).
- Modify `GENESIS_HASH` (`"0" * 64`) -- it is wire-protocol-fixed.
