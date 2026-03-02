"""LangChain/LangGraph integration for TrustChain.

Usage::

    from trustchain.integrations.langchain import TrustChainCallbackHandler, tools_to_langchain

    # Callback handler — records interactions as trust blocks
    handler = TrustChainCallbackHandler()
    app.invoke(input, config={"callbacks": [handler]})

    # Convert trust tools to LangChain tools
    from trustchain import trust_tools
    lc_tools = tools_to_langchain(trust_tools())

Install: ``pip install trustchain-py[langchain]``
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID


def _ensure_langchain() -> Any:
    """Lazy import langchain_core."""
    try:
        import langchain_core  # noqa: F811
        return langchain_core
    except ImportError:
        raise ImportError(
            "langchain_core is required for this integration.\n"
            "Install with: pip install trustchain-py[langchain]"
        )


class TrustChainCallbackHandler:
    """LangChain callback handler that records tool interactions as trust blocks.

    Implements the minimal callback interface (no base class import required)
    so that it works without langchain_core installed at import time.
    """

    def __init__(self, *, auto_init: bool = True) -> None:
        self._auto_init = auto_init
        self._sidecar: Any = None
        self._pending_tools: dict[str, dict[str, Any]] = {}

    def _get_sidecar(self) -> Any:
        if self._sidecar is not None:
            return self._sidecar
        from trustchain.sidecar import _instance, init
        if _instance is not None and _instance.is_running:
            self._sidecar = _instance
        elif self._auto_init:
            self._sidecar = init()
        return self._sidecar

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts executing."""
        tool_name = serialized.get("name", "unknown")
        key = str(run_id) if run_id else tool_name
        self._pending_tools[key] = {
            "tool": tool_name,
            "input": input_str,
        }

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes. Records the interaction."""
        key = str(run_id) if run_id else None
        tool_info = self._pending_tools.pop(key, None) if key else None

        sidecar = self._get_sidecar()
        if sidecar is None:
            return

        # Record as a checkpoint (self-signed block documenting the interaction)
        try:
            sidecar._post("/checkpoint", {
                "transaction": {
                    "type": "tool_call",
                    "tool": tool_info["tool"] if tool_info else "unknown",
                    "input_hash": str(hash(tool_info["input"])) if tool_info else "",
                    "output_hash": str(hash(output)),
                    "source": "langchain",
                },
            })
        except Exception:
            pass  # Best-effort — don't break the agent pipeline

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors. Clean up pending state."""
        key = str(run_id) if run_id else None
        if key:
            self._pending_tools.pop(key, None)


def tools_to_langchain(tools: list[dict[str, Any]]) -> list[Any]:
    """Convert trust_tools() output to LangChain StructuredTool instances.

    Example::

        from trustchain import trust_tools
        from trustchain.integrations.langchain import tools_to_langchain

        lc_tools = tools_to_langchain(trust_tools())
        agent = create_react_agent(model, lc_tools)
    """
    _ensure_langchain()
    from langchain_core.tools import StructuredTool

    lc_tools = []
    for tool_def in tools:
        # Build a simple pydantic-free tool
        fn = tool_def["fn"]
        lc_tools.append(
            StructuredTool.from_function(
                func=fn,
                name=tool_def["name"],
                description=tool_def["description"],
            )
        )
    return lc_tools
