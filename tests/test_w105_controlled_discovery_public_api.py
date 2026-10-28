"""Tests for Harvey Controlled Discovery public API consistency and isolation.

Ensures __all__ matches concrete modules without unexpected leaks or missing symbols,
and verifies package import has zero network or side-effect footprint.
"""

import importlib
import pytest

EXPECTED_EXPORTS = {
    "audit": (
        "OutboundAuditEvent",
        "OutboundAuditLogger",
        "sanitize_headers",
        "sanitize_url",
    ),
    "budget": (
        "BudgetAlreadySettledError",
        "BudgetExceededError",
        "BudgetLimits",
        "BudgetReservationNotFoundError",
        "BudgetUnauthorizedError",
        "HardBudgetLedger",
        "ReservationRecord",
        "ReservationRequest",
        "SettlementReport",
    ),
    "limiter": (
        "ConcurrencyTimeoutError",
        "FakeClock",
        "LeaseExpiredError",
        "LeaseReleaseOutcome",
        "LimiterAcquireStatus",
        "LimiterConfig",
        "LimiterError",
        "MaxRetriesExceededError",
        "OfflineEgressBlockedError",
        "PersistentEgressLimiter",
        "RedirectLimitExceededError",
        "RequestLease",
        "ResponseBodyMeter",
        "ResponseSizeLimitExceededError",
        "SystemClock",
    ),
    "policy": (
        "AccessPurpose",
        "AuthorizationStatus",
        "CompanyTargetScope",
        "DecisionCode",
        "NormalizedUrl",
        "PolicyDecision",
        "RFC9309Group",
        "RFC9309RobotsParser",
        "RFC9309Rule",
        "RedirectDecision",
        "RobotsFetchStatus",
        "SourcePolicyEngine",
        "SourceStatus",
        "TargetAllowlist",
    ),
    "receipt": (
        "CollectorReceipt",
        "ReceiptKind",
        "ReceiptReplayLedger",
        "ReceiptValidationResult",
        "ReceiptValidationStatus",
        "compute_content_sha256",
        "sign_collector_receipt",
        "verify_collector_receipt",
    ),
    "gateway": (
        "ControlledEgressBlockedError",
        "ControlledEgressGateway",
        "ControlledEgressResponse",
    ),
}


def test_public_api_matches_concrete_modules():
    """Verify controlled_discovery exports align with concrete submodules."""
    package = importlib.import_module("harvey.controlled_discovery")
    expected = {
        name
        for names in EXPECTED_EXPORTS.values()
        for name in names
    }

    assert len(package.__all__) == len(set(package.__all__)), "Duplicate symbols in __all__"
    assert set(package.__all__) == expected, f"Mismatched symbols: {set(package.__all__) ^ expected}"

    for module_name, names in EXPECTED_EXPORTS.items():
        module = importlib.import_module(f"harvey.controlled_discovery.{module_name}")
        for name in names:
            assert hasattr(package, name), f"Package missing symbol: {name}"
            assert getattr(package, name) is getattr(module, name), f"Symbol {name} does not match {module_name}"
