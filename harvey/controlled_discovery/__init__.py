"""Controlled Discovery module for Harvey.
Provides policy engine, allowlist checking, robots.txt gating,
and fail-closed source verification for experimental prospecting.
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
]
