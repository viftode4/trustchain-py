"""FastAPI/ASGI middleware for TrustChain.

Usage::

    from fastapi import FastAPI
    from trustchain.integrations.asgi import TrustChainMiddleware

    app = FastAPI()
    app.add_middleware(TrustChainMiddleware)

Starts the TrustChain sidecar on app startup and injects trust headers
into responses. No additional dependencies required (FastAPI is a core dep).
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TrustChainMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that manages the TrustChain sidecar lifecycle.

    - Starts the sidecar on first request (lazy init).
    - Adds ``X-TrustChain-Pubkey`` header to all responses.
    - Records inbound requests as interactions (best-effort).
    """

    def __init__(
        self,
        app: Any,
        *,
        name: str | None = None,
        log_level: str = "info",
    ) -> None:
        super().__init__(app)
        self._name = name
        self._log_level = log_level
        self._sidecar: Any = None

    def _ensure_sidecar(self) -> Any:
        if self._sidecar is not None and self._sidecar.is_running:
            return self._sidecar
        from trustchain.sidecar import init
        self._sidecar = init(name=self._name, log_level=self._log_level)
        return self._sidecar

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        sidecar = self._ensure_sidecar()
        response = await call_next(request)

        # Inject trust identity header
        if sidecar.pubkey:
            response.headers["X-TrustChain-Pubkey"] = sidecar.pubkey

        # Record inbound interaction (best-effort)
        peer_pubkey = request.headers.get("X-TrustChain-Pubkey")
        if peer_pubkey and sidecar.pubkey and peer_pubkey != sidecar.pubkey:
            try:
                sidecar._post("/checkpoint", {
                    "transaction": {
                        "type": "http_request",
                        "method": request.method,
                        "path": request.url.path,
                        "peer": peer_pubkey,
                        "source": "asgi",
                    },
                })
            except Exception:
                pass  # Best-effort

        return response
