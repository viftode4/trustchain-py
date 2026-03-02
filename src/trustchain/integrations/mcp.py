"""MCP (Model Context Protocol) middleware for TrustChain.

Usage::

    from trustchain.integrations.mcp import TrustChainMCPMiddleware

    server = FastMCP("my-server")
    server.add_middleware(TrustChainMCPMiddleware())

Simplified from agent-os — uses the sidecar HTTP API directly,
not internal BlockStore. Checks caller trust before allowing tool execution.

Install: ``pip install trustchain-py[mcp]``
"""

from __future__ import annotations

from typing import Any


class TrustChainMCPMiddleware:
    """MCP middleware that gates tool execution on trust scores.

    When a caller provides an ``X-TrustChain-Pubkey`` header, the middleware
    checks the caller's trust score against ``min_trust``. If the score is
    below the threshold, the tool call is rejected.
    """

    def __init__(
        self,
        *,
        min_trust: float = 0.0,
        auto_init: bool = True,
        name: str | None = None,
    ) -> None:
        self._min_trust = min_trust
        self._auto_init = auto_init
        self._name = name
        self._sidecar: Any = None

    def _get_sidecar(self) -> Any:
        if self._sidecar is not None and self._sidecar.is_running:
            return self._sidecar
        if not self._auto_init:
            return None
        from trustchain.sidecar import init
        self._sidecar = init(name=self._name)
        return self._sidecar

    async def __call__(self, request: Any, call_next: Any) -> Any:
        """Middleware handler — check trust before forwarding."""
        sidecar = self._get_sidecar()

        # Extract caller pubkey from request context
        caller_pubkey = None
        if hasattr(request, "headers"):
            caller_pubkey = request.headers.get("X-TrustChain-Pubkey")
        elif hasattr(request, "meta"):
            caller_pubkey = getattr(request.meta, "pubkey", None)

        # Gate on trust if we have a caller identity and a threshold
        if caller_pubkey and sidecar and self._min_trust > 0:
            try:
                score = sidecar.trust_score(caller_pubkey)
                if score < self._min_trust:
                    return {
                        "error": "insufficient_trust",
                        "message": (
                            f"Trust score {score:.3f} is below minimum "
                            f"{self._min_trust:.3f}"
                        ),
                        "pubkey": caller_pubkey,
                    }
            except Exception:
                pass  # If trust check fails, allow through (fail-open)

        # Forward to next handler
        response = await call_next(request)

        # Record the interaction
        if caller_pubkey and sidecar:
            try:
                tool_name = getattr(request, "method", "unknown")
                sidecar._post("/checkpoint", {
                    "transaction": {
                        "type": "mcp_tool_call",
                        "tool": tool_name,
                        "peer": caller_pubkey,
                        "source": "mcp",
                    },
                })
            except Exception:
                pass

        return response
