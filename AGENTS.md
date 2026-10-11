## Local Notes
- Read `CLAUDE.md` here before making non-trivial changes; it contains the Python SDK parity rules.
- Verification: `pip install -e \".[dev]\"` then `python -m pytest tests/ -x -q`.
- Use integer millisecond timestamps only, preserve canonical JSON hashing parity with Rust, and do not call `round()` on trust scores.
- Use `TrustChainSidecar`, not the deprecated `TrustChainNode`.
- Rust is authoritative for ambiguous behavior; wire-format changes must stay aligned with `../trustchain` and `../trustchain-js`.
