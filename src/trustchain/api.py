"""HTTPS Transport for TrustChain v2.

FastAPI server endpoints + httpx client for real P2P communication between
TrustChain nodes. Each node combines a protocol engine, block store, and API.

.. deprecated::
    TrustChainNode is deprecated. Use TrustChainSidecar (sidecar.py) with the
    Rust trustchain-node binary instead. TrustChainNode is kept for in-process
    testing but should not be used in production.
"""

from __future__ import annotations

import asyncio
import logging
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, field_validator

from trustchain.blockstore import BlockStore
from trustchain.delegation import DelegationStore
from trustchain.halfblock import HalfBlock
from trustchain.identity import Identity
from trustchain.protocol import TrustChainProtocol

logger = logging.getLogger("trustchain.api")


# ---- Pydantic models for API serialization ----


_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


def _validate_hex_string(v: str, field_name: str) -> str:
    if not _HEX_PATTERN.match(v):
        raise ValueError(f"{field_name} must be a hex string")
    return v


class HalfBlockModel(BaseModel):
    """Pydantic model for HalfBlock serialization over HTTP."""

    public_key: str
    sequence_number: int
    link_public_key: str
    link_sequence_number: int
    previous_hash: str
    signature: str
    block_type: str
    transaction: Dict[str, Any]
    block_hash: str
    timestamp: int

    @field_validator("public_key", "link_public_key")
    @classmethod
    def validate_pubkey(cls, v: str) -> str:
        return _validate_hex_string(v, "public_key")

    @field_validator("block_hash", "previous_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        return _validate_hex_string(v, "hash")

    def to_halfblock(self) -> HalfBlock:
        return HalfBlock(
            public_key=self.public_key,
            sequence_number=self.sequence_number,
            link_public_key=self.link_public_key,
            link_sequence_number=self.link_sequence_number,
            previous_hash=self.previous_hash,
            signature=self.signature,
            block_type=self.block_type,
            transaction=self.transaction,
            block_hash=self.block_hash,
            timestamp=self.timestamp,
        )

    @classmethod
    def from_halfblock(cls, block: HalfBlock) -> HalfBlockModel:
        return cls(
            public_key=block.public_key,
            sequence_number=block.sequence_number,
            link_public_key=block.link_public_key,
            link_sequence_number=block.link_sequence_number,
            previous_hash=block.previous_hash,
            signature=block.signature,
            block_type=block.block_type,
            transaction=block.transaction,
            block_hash=block.block_hash,
            timestamp=block.timestamp,
        )


class ProposeRequest(BaseModel):
    block: HalfBlockModel


class ProposeResponse(BaseModel):
    accepted: bool
    agreement: Optional[HalfBlockModel] = None
    error: Optional[str] = None


class CrawlResponse(BaseModel):
    blocks: List[HalfBlockModel]


class StatusResponse(BaseModel):
    public_key: str
    latest_seq: int = 0
    block_count: int = 0
    peer_count: int = 0
    # Legacy fields (kept for backward compat, populated from new fields).
    chain_length: int = 0
    total_blocks: int = 0
    peers: List[str] = []
    active_delegations: int = 0
    is_delegated: bool = False
    root_identity: Optional[str] = None


class DelegationRequest(BaseModel):
    delegate_pubkey: str
    scope: List[str] = []
    max_depth: int = 0
    ttl_seconds: float = 3600.0

    @field_validator("delegate_pubkey")
    @classmethod
    def validate_delegate_pubkey(cls, v: str) -> str:
        return _validate_hex_string(v, "delegate_pubkey")


class DelegationResponse(BaseModel):
    accepted: bool
    delegation_id: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class RevocationRequest(BaseModel):
    delegation_id: str


class SuccessionRequest(BaseModel):
    new_pubkey: str

    @field_validator("new_pubkey")
    @classmethod
    def validate_new_pubkey(cls, v: str) -> str:
        return _validate_hex_string(v, "new_pubkey")


# ---- TrustChain Client (httpx) ----


class TrustChainClient:
    """HTTPS client for talking to remote TrustChain nodes."""

    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self._client = None

    async def _get_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def send_proposal(
        self, peer_url: str, proposal: HalfBlock
    ) -> Tuple[bool, Optional[HalfBlock], Optional[str]]:
        """Send a proposal to a remote peer, receive agreement back.

        Returns (accepted, agreement_block, error_message).
        """
        client = await self._get_client()
        model = HalfBlockModel.from_halfblock(proposal)
        try:
            resp = await client.post(
                f"{peer_url}/receive_proposal",
                json={"proposal": model.model_dump()},
            )
            if resp.status_code == 200:
                data = ProposeResponse(**resp.json())
                agreement = data.agreement.to_halfblock() if data.agreement else None
                return data.accepted, agreement, data.error
            return False, None, f"HTTP {resp.status_code}: {resp.text}"
        except Exception as e:
            return False, None, str(e)

    async def crawl_chain(
        self, peer_url: str, pubkey: str, start_seq: int = 1
    ) -> List[HalfBlock]:
        """Fetch blocks from a remote peer."""
        client = await self._get_client()
        try:
            resp = await client.get(
                f"{peer_url}/crawl/{pubkey}",
                params={"start_seq": start_seq},
            )
            if resp.status_code == 200:
                data = CrawlResponse(**resp.json())
                return [b.to_halfblock() for b in data.blocks]
            return []
        except Exception:
            return []

    async def get_block(
        self, peer_url: str, pubkey: str, seq: int
    ) -> Optional[HalfBlock]:
        """Get a specific block from a remote peer."""
        client = await self._get_client()
        try:
            resp = await client.get(
                f"{peer_url}/block/{pubkey}/{seq}"
            )
            if resp.status_code == 200:
                data = resp.json()
                block_data = data.get("block", data)
                model = HalfBlockModel(**block_data)
                return model.to_halfblock()
            return None
        except Exception:
            return None

    async def get_status(self, peer_url: str) -> Optional[Dict[str, Any]]:
        """Get status of a remote peer."""
        client = await self._get_client()
        try:
            resp = await client.get(f"{peer_url}/status")
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ---- TrustChain Node ----


class TrustChainNode:
    """A running TrustChain node — combines protocol, store, and API.

    Each node is a full participant in the TrustChain network: it can
    create proposals, receive and agree to proposals, serve its chain
    to crawlers, and initiate transactions with peers.
    """

    def __init__(
        self,
        identity: Identity,
        store: BlockStore,
        host: str = "0.0.0.0",
        port: int = 8100,
        use_http3: bool = False,
        delegation_store: Optional[DelegationStore] = None,
    ) -> None:
        warnings.warn(
            "TrustChainNode is deprecated. Use TrustChainSidecar instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.identity = identity
        self.store = store
        self.delegation_store = delegation_store
        self.protocol = TrustChainProtocol(identity, store, delegation_store)
        self.client = TrustChainClient(identity)
        self.host = host
        self.port = port
        self.use_http3 = use_http3
        self.peers: Dict[str, str] = {}  # pubkey -> URL
        self.app = self._build_app()
        self._server = None
        self._serve_task = None
        self._shutdown_event = None

    @property
    def pubkey(self) -> str:
        return self.identity.pubkey_hex

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def register_peer(self, pubkey: str, url: str) -> None:
        """Register a known peer's TrustChain node URL."""
        self.peers[pubkey] = url

    def _build_app(self) -> FastAPI:
        """Build the FastAPI application with TrustChain endpoints."""
        app = FastAPI(title="TrustChain Node", version="2.0.0")

        node = self  # capture for closures

        @app.post("/trustchain/propose", response_model=ProposeResponse)
        async def receive_proposal(request: ProposeRequest) -> ProposeResponse:
            """Receive a proposal, validate, create agreement, return it."""
            try:
                proposal = request.block.to_halfblock()

                # Validate the proposal
                node.protocol.receive_proposal(proposal)

                # Create agreement
                agreement = node.protocol.create_agreement(proposal)

                return ProposeResponse(
                    accepted=True,
                    agreement=HalfBlockModel.from_halfblock(agreement),
                )
            except Exception as e:
                logger.warning("Proposal rejected: %s", e)
                return ProposeResponse(accepted=False, error="Proposal validation failed")

        @app.post("/trustchain/agree")
        async def receive_agreement(request: ProposeRequest) -> Dict[str, Any]:
            """Receive an agreement half-block."""
            try:
                agreement = request.block.to_halfblock()
                node.protocol.receive_agreement(agreement)
                return {"accepted": True}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @app.get("/trustchain/blocks/{pubkey}", response_model=CrawlResponse)
        async def crawl_blocks(
            pubkey: str,
            start_seq: int = Query(default=1, ge=1),
            limit: int = Query(default=100, ge=1, le=1000),
        ) -> CrawlResponse:
            """Return blocks for a given pubkey starting from start_seq."""
            blocks = node.store.crawl(pubkey, start_seq)[:limit]
            return CrawlResponse(
                blocks=[HalfBlockModel.from_halfblock(b) for b in blocks]
            )

        @app.get("/trustchain/blocks/{pubkey}/{seq}")
        async def get_block(pubkey: str, seq: int) -> HalfBlockModel:
            """Get a specific block."""
            block = node.store.get_block(pubkey, seq)
            if block is None:
                raise HTTPException(status_code=404, detail="Block not found")
            return HalfBlockModel.from_halfblock(block)

        @app.get("/trustchain/status", response_model=StatusResponse)
        async def status() -> StatusResponse:
            """Node status information."""
            active_delegations = 0
            is_delegated = False
            root_identity = None
            if node.delegation_store:
                active_delegations = node.delegation_store.get_active_delegation_count(
                    node.pubkey
                )
                my_deleg = node.delegation_store.get_delegation_by_delegate(node.pubkey)
                if my_deleg:
                    is_delegated = True
                    # Walk to root
                    current = my_deleg
                    while current.parent_delegation_id is not None:
                        parent = node.delegation_store.get_delegation(
                            current.parent_delegation_id
                        )
                        if parent is None:
                            break
                        current = parent
                    root_identity = current.delegator_pubkey

            latest_seq = node.store.get_latest_seq(node.pubkey)
            block_count = node.store.get_block_count()
            peer_list = list(node.peers.keys())
            return StatusResponse(
                public_key=node.pubkey,
                latest_seq=latest_seq,
                block_count=block_count,
                peer_count=len(peer_list),
                chain_length=latest_seq,
                total_blocks=block_count,
                peers=peer_list,
                active_delegations=active_delegations,
                is_delegated=is_delegated,
                root_identity=root_identity,
            )

        @app.post("/trustchain/crawl-request")
        async def crawl_request(pubkey: str) -> CrawlResponse:
            """Respond to a crawl request for any known chain."""
            blocks = node.store.get_chain(pubkey)
            return CrawlResponse(
                blocks=[HalfBlockModel.from_halfblock(b) for b in blocks]
            )

        # ---- Delegation endpoints ----

        @app.post("/trustchain/delegate", response_model=DelegationResponse)
        async def create_delegation(
            request: DelegationRequest,
        ) -> DelegationResponse:
            """Create a delegation for an ephemeral agent."""
            try:
                proposal = node.protocol.create_delegation(
                    delegate_pubkey=request.delegate_pubkey,
                    scope=request.scope,
                    max_depth=request.max_depth,
                    ttl_seconds=request.ttl_seconds,
                )
                delegation_id = proposal.transaction["delegation_id"]
                return DelegationResponse(
                    accepted=True,
                    delegation_id=delegation_id,
                )
            except Exception as e:
                return DelegationResponse(accepted=False, error=str(e))

        @app.post("/trustchain/revoke")
        async def revoke_delegation(request: RevocationRequest) -> Dict[str, Any]:
            """Revoke a delegation."""
            try:
                block = node.protocol.create_revocation(request.delegation_id)
                return {
                    "revoked": True,
                    "delegation_id": request.delegation_id,
                    "block_hash": block.block_hash,
                }
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @app.get("/trustchain/delegations/{pubkey}")
        async def get_delegations(pubkey: str) -> List[Dict[str, Any]]:
            """Get all delegations for a delegator."""
            if not node.delegation_store:
                return []
            delegations = node.delegation_store.get_delegations_by_delegator(pubkey)
            return [
                {
                    "delegation_id": d.delegation_id,
                    "delegate_pubkey": d.delegate_pubkey,
                    "scope": d.scope,
                    "max_depth": d.max_depth,
                    "expires_at": d.expires_at,
                    "revoked": d.revoked,
                    "is_active": d.is_active,
                }
                for d in delegations
            ]

        @app.get("/trustchain/delegation/{delegation_id}")
        async def get_delegation(delegation_id: str) -> Dict[str, Any]:
            """Get a specific delegation by ID."""
            if not node.delegation_store:
                raise HTTPException(status_code=404, detail="No delegation store")
            d = node.delegation_store.get_delegation(delegation_id)
            if d is None:
                raise HTTPException(status_code=404, detail="Delegation not found")
            return {
                "delegation_id": d.delegation_id,
                "delegator_pubkey": d.delegator_pubkey,
                "delegate_pubkey": d.delegate_pubkey,
                "scope": d.scope,
                "max_depth": d.max_depth,
                "issued_at": d.issued_at,
                "expires_at": d.expires_at,
                "revoked": d.revoked,
                "is_active": d.is_active,
            }

        @app.get("/trustchain/identity/{pubkey}")
        async def resolve_identity(pubkey: str) -> Dict[str, Any]:
            """Resolve a pubkey to its current active identity (following successions)."""
            if not node.delegation_store:
                return {"pubkey": pubkey, "current": pubkey, "successions": 0}
            current = node.delegation_store.resolve_current_identity(pubkey)
            # Count hops
            hops = 0
            p = pubkey
            while p != current:
                s = node.delegation_store.get_successor(p)
                if s is None:
                    break
                p = s
                hops += 1
            return {"pubkey": pubkey, "current": current, "successions": hops}

        # --- Rust-compatible path aliases ---
        # These match the Rust trustchain-node HTTP API so TrustChainNode
        # can serve as a drop-in test double for the Rust sidecar.

        class ReceiveProposalRequest(BaseModel):
            proposal: HalfBlockModel

        @app.post("/receive_proposal")
        async def rust_receive_proposal(request: ReceiveProposalRequest) -> Dict[str, Any]:
            """Rust-compat: POST /receive_proposal {proposal: {...}}"""
            try:
                proposal = request.proposal.to_halfblock()
                node.protocol.receive_proposal(proposal)
                agreement = node.protocol.create_agreement(proposal)
                return {
                    "accepted": True,
                    "agreement": HalfBlockModel.from_halfblock(agreement).model_dump(),
                    "error": None,
                }
            except Exception as e:
                logger.warning("Proposal rejected: %s", e)
                return {"accepted": False, "agreement": None, "error": str(e)}

        class ReceiveAgreementRequest(BaseModel):
            agreement: HalfBlockModel

        @app.post("/receive_agreement")
        async def rust_receive_agreement(request: ReceiveAgreementRequest) -> Dict[str, Any]:
            """Rust-compat: POST /receive_agreement {agreement: {...}}"""
            try:
                agreement = request.agreement.to_halfblock()
                node.protocol.receive_agreement(agreement)
                return {"accepted": True, "error": None}
            except Exception as e:
                return {"accepted": False, "error": str(e)}

        @app.get("/status")
        async def rust_status() -> Dict[str, Any]:
            """Rust-compat: GET /status"""
            return (await status()).model_dump()

        @app.get("/healthz")
        async def healthz() -> Dict[str, Any]:
            """Health check."""
            return {"status": "ok", "public_key": node.pubkey}

        @app.get("/chain/{pubkey}")
        async def rust_chain(pubkey: str) -> Dict[str, Any]:
            """Rust-compat: GET /chain/{pubkey}"""
            blocks = node.store.get_chain(pubkey)
            return {"blocks": [HalfBlockModel.from_halfblock(b).model_dump() for b in blocks]}

        @app.get("/block/{pubkey}/{seq}")
        async def rust_block(pubkey: str, seq: int) -> Dict[str, Any]:
            """Rust-compat: GET /block/{pubkey}/{seq}"""
            block = node.store.get_block(pubkey, seq)
            if block is None:
                raise HTTPException(status_code=404, detail="Block not found")
            return {"block": HalfBlockModel.from_halfblock(block).model_dump()}

        @app.get("/crawl/{pubkey}")
        async def rust_crawl(pubkey: str, start_seq: int = 1) -> Dict[str, Any]:
            """Rust-compat: GET /crawl/{pubkey}"""
            blocks = node.store.crawl(pubkey, start_seq)
            return {"blocks": [HalfBlockModel.from_halfblock(b).model_dump() for b in blocks]}

        return app

    async def transact(
        self, peer_pubkey: str, transaction: Dict[str, Any]
    ) -> Tuple[HalfBlock, Optional[HalfBlock]]:
        """Full transaction: create proposal, send to peer, get agreement back.

        Returns (proposal, agreement) tuple. Agreement may be None if peer
        rejects or is unreachable.
        """
        peer_url = self.peers.get(peer_pubkey)
        if not peer_url:
            raise ValueError(f"Unknown peer: {peer_pubkey[:16]}...")

        # Create and store our proposal
        proposal = self.protocol.create_proposal(peer_pubkey, transaction)

        # Send to peer and get agreement
        accepted, agreement, error = await self.client.send_proposal(
            peer_url, proposal
        )

        if accepted and agreement:
            # Validate and store the agreement
            self.protocol.receive_agreement(agreement)
            return proposal, agreement

        logger.warning(
            "Transaction with %s failed: %s",
            peer_pubkey[:16],
            error or "rejected",
        )
        return proposal, None

    async def start(self) -> None:
        """Start the HTTP server as a background task.

        Returns immediately. The server runs in the background until stop() is called.
        Uses Hypercorn (HTTP/3) when use_http3=True, otherwise uvicorn (HTTP/1.1).
        """
        if self.use_http3:
            await self._start_hypercorn()
        else:
            await self._start_uvicorn()

    async def _start_uvicorn(self) -> None:
        """Start with uvicorn (HTTP/1.1, default)."""
        import uvicorn

        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info",
        )
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve())

    async def _start_hypercorn(self) -> None:
        """Start with Hypercorn (HTTP/2 + HTTP/3).

        Hypercorn serves the same FastAPI app over HTTP/2 and HTTP/3 (QUIC).
        TLS certificates are auto-generated from the node's Ed25519 identity.
        """
        from hypercorn.asyncio import serve as hypercorn_serve
        from hypercorn.config import Config as HypercornConfig

        from trustchain.transport.tls import generate_self_signed_cert

        # Generate TLS cert from identity
        cert_path, key_path = generate_self_signed_cert(self.identity)

        config = HypercornConfig()
        config.bind = [f"{self.host}:{self.port}"]
        config.certfile = cert_path
        config.keyfile = key_path
        config.loglevel = "info"

        self._shutdown_event = asyncio.Event()
        self._serve_task = asyncio.create_task(
            hypercorn_serve(
                self.app,
                config,
                shutdown_trigger=self._shutdown_event.wait,
            )
        )

    async def serve(self) -> None:
        """Start the HTTP server and block until shutdown (for standalone use)."""
        if self.use_http3:
            from hypercorn.asyncio import serve as hypercorn_serve
            from hypercorn.config import Config as HypercornConfig
            from trustchain.transport.tls import generate_self_signed_cert

            cert_path, key_path = generate_self_signed_cert(self.identity)
            config = HypercornConfig()
            config.bind = [f"{self.host}:{self.port}"]
            config.certfile = cert_path
            config.keyfile = key_path
            config.loglevel = "info"
            await hypercorn_serve(self.app, config)
        else:
            import uvicorn
            config = uvicorn.Config(
                self.app, host=self.host, port=self.port, log_level="info"
            )
            self._server = uvicorn.Server(config)
            await self._server.serve()

    async def stop(self) -> None:
        """Stop the HTTP server and close the client."""
        if self._shutdown_event:
            self._shutdown_event.set()
        if self._server:
            self._server.should_exit = True
        if hasattr(self, "_serve_task") and self._serve_task:
            try:
                await self._serve_task
            except Exception:
                pass
            self._serve_task = None
        await self.client.close()
