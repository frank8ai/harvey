"""Controlled Discovery module for Harvey.
Provides policy engine, allowlist checking, robots.txt gating,
egress limiter, hard budget ledger, audit logging, receipts,
and unified fail-closed outbound security gateway.
"""

from harvey.controlled_discovery.policy import (
    AccessPurpose,
    AuthorizationStatus,
    CompanyTargetScope,
    DecisionCode,
    NormalizedUrl,
    PolicyDecision,
    RedirectDecision,
    RobotsFetchStatus,
    SourcePolicyEngine,
    SourceStatus,
    TargetAllowlist,
)
from harvey.controlled_discovery.limiter import (
    EgressLimiter,
    EgressPermit,
    DomainPacingState,
    ResponseBodyMeter,
    MeteredStream,
)
from harvey.controlled_discovery.budget_ledger import (
    HardBudgetLedger,
    ReservationRequest,
    SettlementReport,
    BudgetBalance,
    ExecutionStatus,
    BudgetExhaustedError,
    BudgetAlreadySettledError,
    PricingSchedule,)
from harvey.controlled_discovery.audit import (
    AuditLogger,
    OutboundAuditEvent,
)
from harvey.controlled_discovery.receipt import (
    TrustedCollectionReceipt,
    ReceiptSigner,
    ReceiptVerifier,
)
from harvey.controlled_discovery.gateway import (
    ControlledEgressGateway,
    EgressResponse,
    EgressSecurityError,
)

__all__ = [
    "AccessPurpose",
    "AuthorizationStatus",
    "CompanyTargetScope",
    "DecisionCode",
    "NormalizedUrl",
    "PolicyDecision",
    "RedirectDecision",
    "RobotsFetchStatus",
    "SourcePolicyEngine",
    "SourceStatus",
    "TargetAllowlist",
    "EgressLimiter",
    "EgressPermit",
    "DomainPacingState",
    "ResponseBodyMeter",
    "MeteredStream",
    "HardBudgetLedger",
    "ReservationRequest",
    "SettlementReport",
    "BudgetBalance",
    "ExecutionStatus",
    "BudgetExhaustedError",
    "BudgetAlreadySettledError",
    "PricingSchedule",
    "AuditLogger",
    "OutboundAuditEvent",
    "TrustedCollectionReceipt",
    "ReceiptSigner",
    "ReceiptVerifier",
    "ControlledEgressGateway",
    "EgressResponse",
    "EgressSecurityError",
]
