"""Tests for audit module — schemas, event types, and @audited decorator."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from trustchain.audit import (
    AuditLevel,
    EventType,
    SchemaId,
    audited,
    default_events,
    validate_transaction,
)
from trustchain.halfblock import BlockType


# ---------------------------------------------------------------------------
# BlockType.AUDIT
# ---------------------------------------------------------------------------

class TestBlockTypeAudit:
    def test_audit_value(self):
        assert BlockType.AUDIT.value == "audit"

    def test_audit_round_trip(self):
        assert BlockType("audit") is BlockType.AUDIT

    def test_audit_in_members(self):
        assert "AUDIT" in BlockType.__members__


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_base_schema_valid(self):
        validate_transaction(SchemaId.BASE, {"action": "test", "outcome": "ok"})

    def test_base_schema_missing_action(self):
        with pytest.raises(ValueError, match="action"):
            validate_transaction(SchemaId.BASE, {"outcome": "ok"})

    def test_base_schema_missing_outcome(self):
        with pytest.raises(ValueError, match="outcome"):
            validate_transaction(SchemaId.BASE, {"action": "test"})

    def test_ai_act_schema_valid(self):
        validate_transaction(SchemaId.AI_ACT, {
            "action": "query",
            "outcome": "completed",
            "model": "gpt-4",
            "input_hash": "abc123",
            "output_hash": "def456",
        })

    def test_ai_act_schema_missing_model(self):
        with pytest.raises(ValueError, match="model"):
            validate_transaction(SchemaId.AI_ACT, {
                "action": "query",
                "outcome": "ok",
            })

    def test_aiuc1_schema_valid(self):
        validate_transaction(SchemaId.AIUC1, {
            "action": "process",
            "outcome": "completed",
            "policy_id": "POL-001",
            "compliance_status": "compliant",
        })

    def test_aiuc1_schema_missing_fields(self):
        with pytest.raises(ValueError, match="policy_id"):
            validate_transaction(SchemaId.AIUC1, {
                "action": "x",
                "outcome": "y",
            })

    def test_string_schema_id(self):
        validate_transaction("base", {"action": "test", "outcome": "ok"})

    def test_unknown_schema(self):
        with pytest.raises(ValueError, match="Unknown schema"):
            validate_transaction("nonexistent", {"action": "x"})


# ---------------------------------------------------------------------------
# AuditLevel & EventType
# ---------------------------------------------------------------------------

class TestAuditLevel:
    def test_values(self):
        assert AuditLevel.MINIMAL.value == "minimal"
        assert AuditLevel.STANDARD.value == "standard"
        assert AuditLevel.COMPREHENSIVE.value == "comprehensive"

    def test_from_string(self):
        assert AuditLevel("standard") is AuditLevel.STANDARD


class TestEventType:
    def test_all_variants(self):
        assert len(EventType) == 7

    def test_values(self):
        assert EventType.TOOL_CALL.value == "tool_call"
        assert EventType.LLM_DECISION.value == "llm_decision"
        assert EventType.ERROR.value == "error"


class TestDefaultEvents:
    def test_minimal_events(self):
        events = default_events(AuditLevel.MINIMAL)
        assert EventType.TOOL_CALL in events
        assert EventType.ERROR in events
        assert EventType.LLM_DECISION not in events

    def test_standard_events(self):
        events = default_events(AuditLevel.STANDARD)
        assert EventType.TOOL_CALL in events
        assert EventType.LLM_DECISION in events
        assert EventType.RAW_HTTP not in events

    def test_comprehensive_events(self):
        events = default_events(AuditLevel.COMPREHENSIVE)
        assert events == set(EventType)

    def test_string_level(self):
        events = default_events("minimal")
        assert EventType.TOOL_CALL in events


# ---------------------------------------------------------------------------
# @audited decorator
# ---------------------------------------------------------------------------

class TestAuditedDecorator:
    def _mock_sidecar(self):
        sidecar = MagicMock()
        sidecar.audit = MagicMock(return_value={"block_hash": "abc"})
        return sidecar

    def test_sync_records_entry_and_exit(self):
        sidecar = self._mock_sidecar()

        with patch("trustchain.sidecar._instance", sidecar):
            @audited
            def my_func(x):
                return x * 2

            result = my_func(5)

        assert result == 10
        assert sidecar.audit.call_count == 2
        # First call: entry
        entry_tx = sidecar.audit.call_args_list[0][0][0]
        assert entry_tx["status"] == "started"
        assert entry_tx["event_type"] == "tool_call"
        # Second call: exit
        exit_tx = sidecar.audit.call_args_list[1][0][0]
        assert exit_tx["status"] == "completed"
        assert "duration_ms" in exit_tx

    def test_sync_records_error(self):
        sidecar = self._mock_sidecar()

        with patch("trustchain.sidecar._instance", sidecar):
            @audited
            def failing_func():
                raise ValueError("boom")

            with pytest.raises(ValueError, match="boom"):
                failing_func()

        assert sidecar.audit.call_count == 2
        error_tx = sidecar.audit.call_args_list[1][0][0]
        assert error_tx["status"] == "error"
        assert error_tx["event_type"] == "error"
        assert "boom" in error_tx["error"]

    def test_async_records_entry_and_exit(self):
        sidecar = self._mock_sidecar()

        with patch("trustchain.sidecar._instance", sidecar):
            @audited
            async def async_func(x):
                return x + 1

            result = asyncio.run(async_func(10))

        assert result == 11
        assert sidecar.audit.call_count == 2

    def test_decorator_with_args(self):
        sidecar = self._mock_sidecar()

        with patch("trustchain.sidecar._instance", sidecar):
            @audited(event_type="llm_decision")
            def llm_call():
                return "response"

            llm_call()

        entry_tx = sidecar.audit.call_args_list[0][0][0]
        assert entry_tx["event_type"] == "llm_decision"

    def test_no_sidecar_raises(self):
        with patch("trustchain.sidecar._instance", None):
            @audited
            def func():
                pass

            with pytest.raises(RuntimeError, match="running sidecar"):
                func()

    def test_preserves_function_name(self):
        @audited
        def original_name():
            pass

        assert original_name.__name__ == "original_name"


# ---------------------------------------------------------------------------
# TrustChainProtocol.create_audit
# ---------------------------------------------------------------------------

class TestProtocolCreateAudit:
    """Tests for in-process audit block creation via TrustChainProtocol."""

    def _make_protocol(self):
        from trustchain.blockstore import MemoryBlockStore
        from trustchain.identity import Identity as Id
        from trustchain.protocol import TrustChainProtocol

        identity = Id()
        store = MemoryBlockStore()
        protocol = TrustChainProtocol(identity, store)
        return protocol, identity, store

    def test_protocol_create_audit(self):
        """Audit block has correct block_type and is self-referencing."""
        protocol, identity, _ = self._make_protocol()
        tx = {"event_type": "tool_call", "action": "test", "outcome": "completed"}
        block = protocol.create_audit(tx)

        assert block.block_type == BlockType.AUDIT
        assert block.public_key == identity.pubkey_hex
        assert block.link_public_key == identity.pubkey_hex  # self-referencing
        assert block.link_sequence_number == 0
        assert block.sequence_number == 1
        assert block.transaction == tx

    def test_protocol_create_audit_chain_continuity(self):
        """Audit blocks chain correctly after proposals."""
        protocol, identity, store = self._make_protocol()

        # Create a proposal first
        from trustchain.identity import Identity as Id
        other = Id()
        proposal = protocol.create_proposal(other.pubkey_hex, {"outcome": "ok"})

        # Now create an audit block
        audit = protocol.create_audit({"action": "check", "outcome": "ok"})

        assert audit.sequence_number == 2
        assert audit.previous_hash == proposal.block_hash

    def test_protocol_create_audit_signature_valid(self):
        """Audit block signature passes verification."""
        from trustchain.halfblock import verify_block

        protocol, _, _ = self._make_protocol()
        block = protocol.create_audit({"action": "test", "outcome": "ok"})

        assert verify_block(block)
