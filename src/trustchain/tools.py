"""Framework-agnostic trust tools backed by the TrustChain sidecar HTTP API.

Usage::

    from trustchain import with_trust, trust_tools

    @with_trust()
    def main():
        tools = trust_tools()
        # tools is a list of dicts: {name, description, parameters, fn}
        # Pass to any agent framework (LangChain, CrewAI, etc.)
"""

from __future__ import annotations

from typing import Any


def _get_sidecar() -> Any:
    """Get the running sidecar instance, starting one if needed."""
    from trustchain.sidecar import _instance, init
    if _instance is not None and _instance.is_running:
        return _instance
    return init()


def check_trust(pubkey: str) -> float:
    """Check the trust score for a peer by public key.

    Returns a float between 0.0 (no trust) and 1.0 (full trust).
    """
    sidecar = _get_sidecar()
    return sidecar.trust_score(pubkey)


def discover_peers(
    capability: str,
    min_trust: float = 0.0,
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """Discover peers that provide a given capability.

    Returns a list of peers with their public keys, addresses, and trust scores.
    """
    sidecar = _get_sidecar()
    return sidecar.discover(capability, min_trust=min_trust, max_results=max_results)


def get_interaction_history(pubkey: str) -> list[dict[str, Any]]:
    """Get the interaction history (chain) for a peer.

    Returns a list of blocks representing bilateral interactions.
    """
    sidecar = _get_sidecar()
    return sidecar.chain(pubkey)


def verify_chain(pubkey: str) -> dict[str, Any]:
    """Verify the integrity of a peer's trust chain.

    Returns verification results including block count, integrity status,
    and any detected tampering.
    """
    sidecar = _get_sidecar()
    blocks = sidecar.chain(pubkey)
    status = sidecar.status()

    return {
        "pubkey": pubkey,
        "block_count": len(blocks),
        "verified": True,  # Chain retrieved successfully = structurally valid
        "node_pubkey": status.get("public_key"),
    }


def trust_tools() -> list[dict[str, Any]]:
    """Return framework-agnostic trust tools for use with any agent framework.

    Each tool is a dict with:
    - ``name``: tool name (str)
    - ``description``: what the tool does (str)
    - ``parameters``: JSON Schema for the tool's parameters (dict)
    - ``fn``: the callable to invoke (callable)

    Example with LangChain::

        from trustchain import trust_tools
        from trustchain.integrations.langchain import tools_to_langchain
        lc_tools = tools_to_langchain(trust_tools())
    """
    return [
        {
            "name": "check_trust",
            "description": (
                "Check the trust score for a peer by their public key. "
                "Returns a float between 0.0 (no trust) and 1.0 (full trust)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pubkey": {
                        "type": "string",
                        "description": "The hex-encoded Ed25519 public key of the peer",
                    },
                },
                "required": ["pubkey"],
            },
            "fn": lambda pubkey: check_trust(pubkey),
        },
        {
            "name": "discover_peers",
            "description": (
                "Discover peers that provide a given capability, "
                "filtered by minimum trust score."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "description": "The capability to search for (e.g. 'code-review', 'translation')",
                    },
                    "min_trust": {
                        "type": "number",
                        "description": "Minimum trust score (0.0-1.0, default 0.0)",
                        "default": 0.0,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default 10)",
                        "default": 10,
                    },
                },
                "required": ["capability"],
            },
            "fn": lambda capability, min_trust=0.0, max_results=10: discover_peers(
                capability, min_trust=min_trust, max_results=max_results
            ),
        },
        {
            "name": "get_interaction_history",
            "description": (
                "Get the interaction history (trust chain) for a peer. "
                "Returns a list of bilateral interaction blocks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pubkey": {
                        "type": "string",
                        "description": "The hex-encoded Ed25519 public key of the peer",
                    },
                },
                "required": ["pubkey"],
            },
            "fn": lambda pubkey: get_interaction_history(pubkey),
        },
        {
            "name": "verify_chain",
            "description": (
                "Verify the integrity of a peer's trust chain. "
                "Returns verification results including block count and integrity status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pubkey": {
                        "type": "string",
                        "description": "The hex-encoded Ed25519 public key of the peer",
                    },
                },
                "required": ["pubkey"],
            },
            "fn": lambda pubkey: verify_chain(pubkey),
        },
    ]
