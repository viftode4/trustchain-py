"""Block storage for TrustChain v2.

Provides MemoryBlockStore (for tests) and SQLiteBlockStore (for production).
Each node stores both its own half-blocks and received counterparty half-blocks.
"""

from __future__ import annotations

import json
import sqlite3
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from trustchain.delegation import DelegationRecord, DelegationStore
from trustchain.halfblock import GENESIS_HASH, HalfBlock


class BlockStore(ABC):
    """Abstract base class for half-block storage."""

    @abstractmethod
    def add_block(self, block: HalfBlock) -> None:
        """Store a half-block. Raises on duplicate (pubkey, seq)."""

    @abstractmethod
    def get_block(self, pubkey: str, seq: int) -> Optional[HalfBlock]:
        """Retrieve a specific block by owner pubkey and sequence number."""

    @abstractmethod
    def get_chain(self, pubkey: str) -> List[HalfBlock]:
        """Get all blocks for an agent, sorted by sequence number ascending."""

    @abstractmethod
    def get_linked_block(self, block: HalfBlock) -> Optional[HalfBlock]:
        """Find the counterparty half-block linked to the given block.

        For a PROPOSAL: find the AGREEMENT from link_public_key that
            has link_sequence_number == block.sequence_number.
        For an AGREEMENT: find the PROPOSAL at
            (block.link_public_key, block.link_sequence_number).
        """

    @abstractmethod
    def get_latest_seq(self, pubkey: str) -> int:
        """Get the highest sequence number for a given agent.

        Returns 0 if no blocks exist (sequences start at 1).
        """

    @abstractmethod
    def get_head_hash(self, pubkey: str) -> str:
        """Get the block_hash of the latest block for an agent.

        Returns GENESIS_HASH if no blocks exist.
        """

    @abstractmethod
    def crawl(self, pubkey: str, start_seq: int = 1) -> List[HalfBlock]:
        """Retrieve blocks for an agent starting from start_seq, sorted ascending."""

    @abstractmethod
    def get_all_pubkeys(self) -> List[str]:
        """Return all unique public keys that have blocks in the store."""

    @abstractmethod
    def get_block_count(self) -> int:
        """Return total number of blocks in the store."""


class MemoryBlockStore(BlockStore):
    """In-memory block store for testing."""

    def __init__(self) -> None:
        # Keyed by (public_key, sequence_number)
        self._blocks: Dict[tuple, HalfBlock] = {}

    def add_block(self, block: HalfBlock) -> None:
        key = (block.public_key, block.sequence_number)
        if key in self._blocks:
            raise ValueError(
                f"Duplicate block: ({block.public_key[:16]}..., seq={block.sequence_number})"
            )
        self._blocks[key] = block

    def get_block(self, pubkey: str, seq: int) -> Optional[HalfBlock]:
        return self._blocks.get((pubkey, seq))

    def get_chain(self, pubkey: str) -> List[HalfBlock]:
        blocks = [b for (pk, _), b in self._blocks.items() if pk == pubkey]
        blocks.sort(key=lambda b: b.sequence_number)
        return blocks

    def get_linked_block(self, block: HalfBlock) -> Optional[HalfBlock]:
        if block.block_type == "proposal":
            # Find agreement from counterparty that links back to this proposal
            for b in self._blocks.values():
                if (
                    b.public_key == block.link_public_key
                    and b.block_type == "agreement"
                    and b.link_public_key == block.public_key
                    and b.link_sequence_number == block.sequence_number
                ):
                    return b
            return None
        else:
            # Agreement: find the proposal it links to
            return self.get_block(block.link_public_key, block.link_sequence_number)

    def get_latest_seq(self, pubkey: str) -> int:
        seqs = [
            b.sequence_number for (pk, _), b in self._blocks.items() if pk == pubkey
        ]
        return max(seqs) if seqs else 0

    def get_head_hash(self, pubkey: str) -> str:
        latest_seq = self.get_latest_seq(pubkey)
        if latest_seq == 0:
            return GENESIS_HASH
        block = self.get_block(pubkey, latest_seq)
        return block.block_hash if block else GENESIS_HASH

    def crawl(self, pubkey: str, start_seq: int = 1) -> List[HalfBlock]:
        blocks = [
            b
            for (pk, _), b in self._blocks.items()
            if pk == pubkey and b.sequence_number >= start_seq
        ]
        blocks.sort(key=lambda b: b.sequence_number)
        return blocks

    def get_all_pubkeys(self) -> List[str]:
        return list({pk for pk, _ in self._blocks.keys()})

    def get_block_count(self) -> int:
        return len(self._blocks)


class SQLiteBlockStore(BlockStore, DelegationStore):
    """SQLite-backed block store for production use.

    Each node has its own database file. Stores both own blocks and
    received counterparty blocks for cross-chain verification.
    Also implements DelegationStore for delegation/succession/revocation.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                public_key TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                link_public_key TEXT NOT NULL,
                link_sequence_number INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                block_type TEXT NOT NULL,
                tx_data TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                "timestamp" INTEGER NOT NULL,
                insert_time REAL NOT NULL,
                PRIMARY KEY (public_key, sequence_number)
            );
            CREATE INDEX IF NOT EXISTS idx_link
                ON blocks(link_public_key, link_sequence_number);
            CREATE INDEX IF NOT EXISTS idx_hash
                ON blocks(block_hash);
            CREATE INDEX IF NOT EXISTS idx_block_type
                ON blocks(block_type);

            CREATE TABLE IF NOT EXISTS delegations (
                delegation_id TEXT PRIMARY KEY,
                delegator_pubkey TEXT NOT NULL,
                delegate_pubkey TEXT NOT NULL,
                scope TEXT NOT NULL,
                max_depth INTEGER NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                delegation_block_hash TEXT NOT NULL,
                agreement_block_hash TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revocation_block_hash TEXT,
                revoked_at REAL,
                parent_delegation_id TEXT,
                FOREIGN KEY (parent_delegation_id) REFERENCES delegations(delegation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_delegations_delegator
                ON delegations(delegator_pubkey);
            CREATE INDEX IF NOT EXISTS idx_delegations_delegate
                ON delegations(delegate_pubkey);

            CREATE TABLE IF NOT EXISTS successions (
                old_pubkey TEXT PRIMARY KEY,
                new_pubkey TEXT NOT NULL UNIQUE,
                succession_block_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revocations (
                delegation_id TEXT PRIMARY KEY,
                revocation_block_hash TEXT NOT NULL,
                revoked_at REAL NOT NULL,
                FOREIGN KEY (delegation_id) REFERENCES delegations(delegation_id)
            );
            """
        )
        self._conn.commit()

    def _row_to_block(self, row: sqlite3.Row) -> HalfBlock:
        return HalfBlock(
            public_key=row["public_key"],
            sequence_number=row["sequence_number"],
            link_public_key=row["link_public_key"],
            link_sequence_number=row["link_sequence_number"],
            previous_hash=row["previous_hash"],
            signature=row["signature"],
            block_type=row["block_type"],
            transaction=json.loads(row["tx_data"]),
            block_hash=row["block_hash"],
            timestamp=int(row["timestamp"]),
        )

    def add_block(self, block: HalfBlock) -> None:
        try:
            self._conn.execute(
                """INSERT INTO blocks
                   (public_key, sequence_number, link_public_key,
                    link_sequence_number, previous_hash, signature,
                    block_type, tx_data, block_hash, "timestamp", insert_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    block.public_key,
                    block.sequence_number,
                    block.link_public_key,
                    block.link_sequence_number,
                    block.previous_hash,
                    block.signature,
                    block.block_type,
                    json.dumps(block.transaction, sort_keys=True),
                    block.block_hash,
                    block.timestamp,
                    time.time(),
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(
                f"Duplicate block: ({block.public_key[:16]}..., seq={block.sequence_number})"
            )

    def get_block(self, pubkey: str, seq: int) -> Optional[HalfBlock]:
        row = self._conn.execute(
            "SELECT * FROM blocks WHERE public_key = ? AND sequence_number = ?",
            (pubkey, seq),
        ).fetchone()
        return self._row_to_block(row) if row else None

    def get_chain(self, pubkey: str) -> List[HalfBlock]:
        rows = self._conn.execute(
            "SELECT * FROM blocks WHERE public_key = ? ORDER BY sequence_number ASC",
            (pubkey,),
        ).fetchall()
        return [self._row_to_block(r) for r in rows]

    def get_linked_block(self, block: HalfBlock) -> Optional[HalfBlock]:
        if block.block_type == "proposal":
            row = self._conn.execute(
                """SELECT * FROM blocks
                   WHERE public_key = ? AND block_type = 'agreement'
                     AND link_public_key = ? AND link_sequence_number = ?""",
                (block.link_public_key, block.public_key, block.sequence_number),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM blocks WHERE public_key = ? AND sequence_number = ?",
                (block.link_public_key, block.link_sequence_number),
            ).fetchone()
        return self._row_to_block(row) if row else None

    def get_latest_seq(self, pubkey: str) -> int:
        row = self._conn.execute(
            "SELECT MAX(sequence_number) as max_seq FROM blocks WHERE public_key = ?",
            (pubkey,),
        ).fetchone()
        return row["max_seq"] if row and row["max_seq"] is not None else 0

    def get_head_hash(self, pubkey: str) -> str:
        latest_seq = self.get_latest_seq(pubkey)
        if latest_seq == 0:
            return GENESIS_HASH
        block = self.get_block(pubkey, latest_seq)
        return block.block_hash if block else GENESIS_HASH

    def crawl(self, pubkey: str, start_seq: int = 1) -> List[HalfBlock]:
        rows = self._conn.execute(
            """SELECT * FROM blocks
               WHERE public_key = ? AND sequence_number >= ?
               ORDER BY sequence_number ASC""",
            (pubkey, start_seq),
        ).fetchall()
        return [self._row_to_block(r) for r in rows]

    def get_all_pubkeys(self) -> List[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT public_key FROM blocks"
        ).fetchall()
        return [r["public_key"] for r in rows]

    def get_block_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM blocks").fetchone()
        return row["cnt"]

    # --- DelegationStore implementation ---

    def add_delegation(self, delegation: DelegationRecord) -> None:
        try:
            self._conn.execute(
                """INSERT INTO delegations
                   (delegation_id, delegator_pubkey, delegate_pubkey, scope,
                    max_depth, issued_at, expires_at, delegation_block_hash,
                    agreement_block_hash, revoked, revocation_block_hash,
                    revoked_at, parent_delegation_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    delegation.delegation_id,
                    delegation.delegator_pubkey,
                    delegation.delegate_pubkey,
                    json.dumps(delegation.scope),
                    delegation.max_depth,
                    delegation.issued_at,
                    delegation.expires_at,
                    delegation.delegation_block_hash,
                    delegation.agreement_block_hash,
                    1 if delegation.revoked else 0,
                    delegation.revocation_block_hash,
                    delegation.revoked_at,
                    delegation.parent_delegation_id,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"Duplicate delegation_id: {delegation.delegation_id}")

    def _row_to_delegation(self, row: sqlite3.Row) -> DelegationRecord:
        return DelegationRecord(
            delegation_id=row["delegation_id"],
            delegator_pubkey=row["delegator_pubkey"],
            delegate_pubkey=row["delegate_pubkey"],
            scope=json.loads(row["scope"]),
            max_depth=row["max_depth"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            delegation_block_hash=row["delegation_block_hash"],
            agreement_block_hash=row["agreement_block_hash"],
            revoked=bool(row["revoked"]),
            revocation_block_hash=row["revocation_block_hash"],
            revoked_at=row["revoked_at"],
            parent_delegation_id=row["parent_delegation_id"],
        )

    def get_delegation(self, delegation_id: str) -> Optional[DelegationRecord]:
        row = self._conn.execute(
            "SELECT * FROM delegations WHERE delegation_id = ?",
            (delegation_id,),
        ).fetchone()
        return self._row_to_delegation(row) if row else None

    def get_delegations_by_delegator(self, delegator_pubkey: str) -> List[DelegationRecord]:
        rows = self._conn.execute(
            "SELECT * FROM delegations WHERE delegator_pubkey = ?",
            (delegator_pubkey,),
        ).fetchall()
        return [self._row_to_delegation(r) for r in rows]

    def get_delegation_by_delegate(self, delegate_pubkey: str) -> Optional[DelegationRecord]:
        now = int(time.time() * 1000)
        row = self._conn.execute(
            """SELECT * FROM delegations
               WHERE delegate_pubkey = ? AND revoked = 0 AND expires_at > ?
               ORDER BY issued_at DESC LIMIT 1""",
            (delegate_pubkey, now),
        ).fetchone()
        return self._row_to_delegation(row) if row else None

    def get_active_delegation_count(self, delegator_pubkey: str) -> int:
        now = int(time.time() * 1000)
        row = self._conn.execute(
            """SELECT COUNT(*) as cnt FROM delegations
               WHERE delegator_pubkey = ? AND revoked = 0 AND expires_at > ?""",
            (delegator_pubkey, now),
        ).fetchone()
        return row["cnt"]

    def revoke_delegation(self, delegation_id: str, revocation_block_hash: str) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            """UPDATE delegations SET revoked = 1, revocation_block_hash = ?, revoked_at = ?
               WHERE delegation_id = ?""",
            (revocation_block_hash, now, delegation_id),
        )
        self._conn.execute(
            """INSERT OR IGNORE INTO revocations (delegation_id, revocation_block_hash, revoked_at)
               VALUES (?, ?, ?)""",
            (delegation_id, revocation_block_hash, now),
        )
        self._conn.commit()

    def is_revoked(self, delegation_id: str) -> bool:
        row = self._conn.execute(
            "SELECT revoked FROM delegations WHERE delegation_id = ?",
            (delegation_id,),
        ).fetchone()
        return bool(row["revoked"]) if row else False

    def is_delegate(self, pubkey: str) -> bool:
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM delegations WHERE delegate_pubkey = ?",
            (pubkey,),
        ).fetchone()
        return row["cnt"] > 0

    def add_succession(self, old_pubkey: str, new_pubkey: str, succession_block_hash: str) -> None:
        try:
            self._conn.execute(
                """INSERT INTO successions (old_pubkey, new_pubkey, succession_block_hash, created_at)
                   VALUES (?, ?, ?, ?)""",
                (old_pubkey, new_pubkey, succession_block_hash, int(time.time() * 1000)),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"Succession already exists for {old_pubkey[:16]}...")

    def get_successor(self, old_pubkey: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT new_pubkey FROM successions WHERE old_pubkey = ?",
            (old_pubkey,),
        ).fetchone()
        return row["new_pubkey"] if row else None

    def get_predecessor(self, new_pubkey: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT old_pubkey FROM successions WHERE new_pubkey = ?",
            (new_pubkey,),
        ).fetchone()
        return row["old_pubkey"] if row else None

    def resolve_current_identity(self, pubkey: str) -> str:
        current = pubkey
        seen: set[str] = {current}
        while True:
            row = self._conn.execute(
                "SELECT new_pubkey FROM successions WHERE old_pubkey = ?",
                (current,),
            ).fetchone()
            if row is None:
                break
            current = row["new_pubkey"]
            if current in seen:
                break  # cycle protection
            seen.add(current)
        return current

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __del__(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
