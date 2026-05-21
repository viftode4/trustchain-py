<!-- OMX:AGENTS-INIT:MANAGED -->
<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-07 | Updated: 2026-05-21 -->

# trustchain-py

## Purpose
Python SDK for TrustChain. PyPI name `trustchain-py`, import as `import trustchain`. Implements IETF draft-pouwelse-trustchain-01 with NetFlow Sybil resistance and a zero-config `TrustChainSidecar` client that wraps the Rust binary. Must stay wire-compatible with the Rust workspace — Rust is authoritative when behavior is ambiguous. See `CLAUDE.md` for parity rules.

## Key Files
| File | Description |
|------|-------------|
| `CLAUDE.md` | Python SDK parity rules (read first) |
| `pyproject.toml` | Package metadata + extras (`dev`, `aioquic`, `grpcio`, `hypercorn`) |
| `CHANGELOG.md` | Release notes |
| `README.md` | SDK overview |
| `LICENSE` | License |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/trustchain/` | Package source: `halfblock`, `protocol`, `block`, `blockstore`, `trust`, `netflow`, `delegation/`, `transport/`, `sidecar`, `crawler`, `exceptions` |
| `tests/` | Pytest suite (475 tests) |
| `benchmarks/` | Performance benchmarks |
| `docs/` | SDK documentation |
| `dist/` | Build artifacts (sdist / wheel) |

## For AI Agents
### Working In This Directory
- Read `CLAUDE.md` before non-trivial changes.
- Timestamps: always `int` milliseconds. Use `_now_ms()` from `halfblock.py`. Never `float` seconds.
- Canonical JSON: `json.dumps(obj, sort_keys=True, separators=(',', ':'))` with `signature=""` before hashing. Signature is Ed25519 over UTF-8 of hex `block_hash`.
- Use `TrustChainSidecar`, NOT deprecated `TrustChainNode`.
- Sidecar HTTP paths: `/receive_proposal`, `/receive_agreement`, `/accept_delegation`, `/accept_succession`, `/crawl`, `/status`, `/healthz`, `/metrics`.
- `MAX_DELEGATION_TTL_MS = 30 * 24 * 3600 * 1000` enforced in `protocol.py`. Empty scope under restricted parent = privilege escalation → reject.
- Raise `DelegationError` for delegation failures, not generic exceptions.
- No `round()` on trust scores (breaks Rust parity).
- NetFlow zero → score zero when seed nodes are configured (Sybil gate must not be bypassed by statistical fallback).
- Never modify `GENESIS_HASH = "0" * 64` — wire-protocol-fixed.
- Never auto-accept delegations or successions.

### Testing Requirements
- `pip install -e ".[dev]"`
- `python -m pytest tests/ -x -q` (475 tests; 1 pre-existing gRPC port-bind failure is expected)
- CI: ubuntu/windows/macos × Python 3.11/3.12/3.13
- Integration job sets `TRUSTCHAIN_BIN` to a built Rust binary; tests skip Rust-dependent cases when unset.

### Common Patterns
- Add typed exceptions in `exceptions.py` rather than raising generic ones.
- Lazy imports for optional transports (`aioquic`, `grpcio`, `hypercorn`).
- BlockStore implementations: `MemoryBlockStore` for tests, `SQLiteBlockStore` for persistence.

## Dependencies
### Internal
- Wire-compatible with `../trustchain` (authoritative). Consumed by `../trustchain-agent-os`, `../trustchain-aquarium`, `../trustchain-economy`.

### External
- Core: `cryptography`, `networkx`, `fastapi`, `uvicorn`, `httpx`.
- Optional extras: `aioquic`, `grpcio`, `hypercorn`.

<!-- OMX:AGENTS-INIT:MANUAL:START -->
## Local Notes
- Read `CLAUDE.md` here before making non-trivial changes; it contains the Python SDK parity rules.
- Verification: `pip install -e \".[dev]\"` then `python -m pytest tests/ -x -q`.
- Use integer millisecond timestamps only, preserve canonical JSON hashing parity with Rust, and do not call `round()` on trust scores.
- Use `TrustChainSidecar`, not the deprecated `TrustChainNode`.
- Rust is authoritative for ambiguous behavior; wire-format changes must stay aligned with `../trustchain` and `../trustchain-js`.
<!-- OMX:AGENTS-INIT:MANUAL:END -->
