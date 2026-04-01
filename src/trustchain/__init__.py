# === Identity ===
from trustchain.identity import Identity

# === v1 compat (deprecated) ===
from trustchain.record import InteractionRecord, create_record, verify_record
from trustchain.store import FileRecordStore, RecordStore
from trustchain.block import Block
from trustchain.block import HalfBlock as V1HalfBlock  # v1 read-only projection
from trustchain.block import GENESIS_HASH

# === v2 core ===
from trustchain.halfblock import (
    HalfBlock,
    BlockType,
    compute_block_hash,
    create_half_block,
    sign_block,
    verify_block,
)
from trustchain.halfblock import GENESIS_HASH  # re-export (same value)
from trustchain.blockstore import BlockStore, MemoryBlockStore, SQLiteBlockStore
from trustchain.protocol import TrustChainProtocol

# === Chain & validation ===
from trustchain.chain import PersonalChain, compute_chain_integrity, validate_chain_for

# === Trust scoring ===
from trustchain.trust import (
    TrustEngine,
    # v1 compat
    compute_chain_trust,
    compute_trust,
    compute_transitive_trust,
    compute_trust_with_decay,
    is_sybil_cluster,
)

# === Crawling & DAG ===
from trustchain.crawler import (
    BlockStoreCrawler,
    ChainCrawler,
    CrossChainLink,
    DAGView,
    HTTPCrawler,
    TamperingReport,
)

# === NetFlow (Sybil resistance) ===
from trustchain.netflow import NetFlowTrust

# === Transport Layer ===
from trustchain.transport.base import MessageType, Transport, TransportError, TransportMessage
from trustchain.transport.http import HTTPTransport

# === HTTPS Transport ===
from trustchain.api import TrustChainClient, TrustChainNode

# === Consensus ===
from trustchain.consensus import CHECOConsensus

# === Delegation ===
from trustchain.delegation import (
    DelegationCertificate,
    DelegationRecord,
    DelegationStore,
    MemoryDelegationStore,
)

# === Exceptions ===
from trustchain.exceptions import (
    AgreementError,
    ChainError,
    CheckpointError,
    DelegationError,
    DuplicateSequenceError,
    EntanglementError,
    InvalidBlockError,
    NetFlowError,
    OrphanBlockError,
    PrevHashMismatchError,
    ProposalError,
    RevocationError,
    SequenceGapError,
    SignatureError,
    SuccessionError,
)

# === Sidecar SDK (zero-config) ===
from trustchain.sidecar import (
    init, init_delegate, protect, TrustChainSidecar,
    with_trust, download_binary,
)

# === Audit (single-player mode) ===
from trustchain.audit import (
    AuditLevel,
    EventType,
    SchemaId,
    audited,
    default_events,
    validate_transaction,
)

# === Behavioral detection (change detection + selective scamming) ===
from trustchain.behavioral import (
    BehavioralConfig,
    BehavioralAnalysis,
    SelectiveTargetingResult,
    failure_rate,
    detect_behavioral_change,
    detect_selective_targeting,
)

# === Collusion ring detection ===
from trustchain.collusion import (
    CollusionConfig,
    CollusionSignals,
    has_reciprocity_anomaly,
    peer_concentration,
    detect_collusion,
)

# === Tiers (progressive unlocking) ===
from trustchain.tiers import TrustTier, compute_tier, max_transaction_value

# === Thresholds (decision trust) ===
from trustchain.thresholds import min_trust_threshold, risk_threshold, required_deposit

# === Sanctions (graduated penalties) ===
from trustchain.sanctions import (
    ViolationSeverity,
    SanctionConfig,
    Violation,
    SanctionResult,
    classify_violation,
    compute_penalty,
    compute_sanctions,
)

# === Correlation penalty (delegation trees) ===
from trustchain.correlation import (
    CorrelationConfig,
    delegation_tree_penalty,
    delegator_penalty,
    compute_delegator_correlation_penalty,
)

# === Forgiveness / trust recovery ===
from trustchain.forgiveness import (
    ForgivenessConfig,
    RecoverySeverity,
    apply_forgiveness,
    recovery_ceiling,
    asymmetric_decay_weight,
)

# === Sealed rating (commit-reveal) ===
from trustchain.sealed_rating import (
    SealedRatingConfig,
    RatingCommitment,
    RatingReveal,
    create_commitment,
    verify_reveal,
    extract_sealed_rating,
    effective_sealed_rating,
)

# === Trust tools (framework-agnostic) ===
from trustchain.tools import trust_tools
