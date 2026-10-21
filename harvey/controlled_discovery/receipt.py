"""Controlled Discovery Trusted Collector Receipt Contract & Verifier.

Defines the cryptographic receipt contract for data collection, strictly
distinguishing between:
- UNTRUSTED_IMPORTED_BUNDLE (third-party or user-supplied unverified data)
- OFFLINE_FIXTURE (static testing fixture; never masquerades as live collection)
- TRUSTED_COLLECTOR_RECEIPT (signed by an authorized collector boundary)

Security Invariants:
- Never trusts user-supplied 'verified=true' flags.
- Validates raw content SHA-256 against actual body bytes.
- Uses HMAC-SHA256 constant-time signature verification.
- Secret keys are NEVER stored in repo or hardcoded fixtures; passed via runtime injection.
- Offline fixtures are strictly prevented from claiming TRUSTED_COLLECTOR_RECEIPT status.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union


class ReceiptKind(str, Enum):
    UNTRUSTED_IMPORTED_BUNDLE = "UNTRUSTED_IMPORTED_BUNDLE"
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    TRUSTED_COLLECTOR_RECEIPT = "TRUSTED_COLLECTOR_RECEIPT"


class ReceiptValidationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED_SIGNATURE_MISMATCH = "REJECTED_SIGNATURE_MISMATCH"
    REJECTED_CONTENT_HASH_MISMATCH = "REJECTED_CONTENT_HASH_MISMATCH"
    REJECTED_MISSING_FIELDS = "REJECTED_MISSING_FIELDS"
    REJECTED_INVALID_KIND = "REJECTED_INVALID_KIND"
    OFFLINE_FIXTURE_ACKNOWLEDGED = "OFFLINE_FIXTURE_ACKNOWLEDGED"
    UNTRUSTED_BUNDLE_UNVERIFIED = "UNTRUSTED_BUNDLE_UNVERIFIED"


@dataclass(frozen=True)
class CollectorReceipt:
    """Cryptographic collection receipt model."""

    receipt_id: str
    kind: str  # Value from ReceiptKind
    run_id: str
    collector_id: str
    collected_url: str
    collected_at: str
    content_sha256: str
    permit_ref: str
    policy_decision_ref: str
    signature: str = ""
    key_id: str = ""
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CollectorReceipt:
        # Strip any unverified user claims like "verified=True"
        sanitized = {k: v for k, v in data.items() if k != "verified"}
        extra = sanitized.pop("extra_metadata", {})
        if not isinstance(extra, dict):
            extra = {}
        return cls(
            receipt_id=str(sanitized.get("receipt_id", "")),
            kind=str(sanitized.get("kind", ReceiptKind.UNTRUSTED_IMPORTED_BUNDLE.value)),
            run_id=str(sanitized.get("run_id", "")),
            collector_id=str(sanitized.get("collector_id", "")),
            collected_url=str(sanitized.get("collected_url", "")),
            collected_at=str(sanitized.get("collected_at", "")),
            content_sha256=str(sanitized.get("content_sha256", "")),
            permit_ref=str(sanitized.get("permit_ref", "")),
            policy_decision_ref=str(sanitized.get("policy_decision_ref", "")),
            signature=str(sanitized.get("signature", "")),
            key_id=str(sanitized.get("key_id", "")),
            extra_metadata=extra,
        )


@dataclass(frozen=True)
class ReceiptValidationResult:
    """Result of receipt verification."""

    is_trusted: bool
    status: ReceiptValidationStatus
    reason: str
    computed_content_sha256: str = ""


def compute_content_sha256(raw_bytes: bytes) -> str:
    """Compute hex SHA-256 for response payload bytes."""
    return hashlib.sha256(raw_bytes).hexdigest()


def _canonical_signing_string(
    receipt_id: str,
    kind: str,
    run_id: str,
    collector_id: str,
    collected_url: str,
    collected_at: str,
    content_sha256: str,
    permit_ref: str,
    policy_decision_ref: str,
    key_id: str,
) -> bytes:
    """Construct deterministic payload for HMAC signature."""
    canonical = "|".join(
        [
            receipt_id.strip(),
            kind.strip(),
            run_id.strip(),
            collector_id.strip(),
            collected_url.strip(),
            collected_at.strip(),
            content_sha256.strip().lower(),
            permit_ref.strip(),
            policy_decision_ref.strip(),
            key_id.strip(),
        ]
    )
    return canonical.encode("utf-8")


def sign_collector_receipt(
    run_id: str,
    collector_id: str,
    collected_url: str,
    raw_content_bytes: bytes,
    permit_ref: str,
    policy_decision_ref: str,
    secret_key: Union[bytes, str],
    key_id: str = "collector-key-v1",
    extra_metadata: Optional[Dict[str, Any]] = None,
    collected_at: Optional[str] = None,
    receipt_id: Optional[str] = None,
) -> CollectorReceipt:
    """Sign a new collection receipt at the authorized collector boundary.

    Notice: secret_key is never stored; it must be injected from secure runtime memory.
    """
    if not secret_key:
        raise ValueError("Cannot sign receipt without a valid secret key")

    key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    rid = receipt_id or f"rcp_{uuid.uuid4().hex[:16]}"
    ts = collected_at or datetime.now(timezone.utc).isoformat()
    c_sha = compute_content_sha256(raw_content_bytes)
    kind = ReceiptKind.TRUSTED_COLLECTOR_RECEIPT.value

    payload = _canonical_signing_string(
        receipt_id=rid,
        kind=kind,
        run_id=run_id,
        collector_id=collector_id,
        collected_url=collected_url,
        collected_at=ts,
        content_sha256=c_sha,
        permit_ref=permit_ref,
        policy_decision_ref=policy_decision_ref,
        key_id=key_id,
    )
    sig = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()

    return CollectorReceipt(
        receipt_id=rid,
        kind=kind,
        run_id=run_id,
        collector_id=collector_id,
        collected_url=collected_url,
        collected_at=ts,
        content_sha256=c_sha,
        permit_ref=permit_ref,
        policy_decision_ref=policy_decision_ref,
        signature=sig,
        key_id=key_id,
        extra_metadata=extra_metadata or {},
    )


def verify_collector_receipt(
    receipt: CollectorReceipt,
    secret_key: Union[bytes, str],
    raw_content_bytes: Optional[bytes] = None,
) -> ReceiptValidationResult:
    """Verify a collection receipt against the key and optional raw body content.

    Rules:
    - OFFLINE_FIXTURE is NEVER treated as trusted live collection.
    - UNTRUSTED_IMPORTED_BUNDLE is marked UNTRUSTED.
    - TRUSTED_COLLECTOR_RECEIPT must have valid signature and matching content hash.
    """
    # 1. Enforce Kind discrimination
    if receipt.kind == ReceiptKind.OFFLINE_FIXTURE.value:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.OFFLINE_FIXTURE_ACKNOWLEDGED,
            reason="Receipt is an offline fixture; cannot masquerade as trusted live collection",
        )

    if receipt.kind == ReceiptKind.UNTRUSTED_IMPORTED_BUNDLE.value:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.UNTRUSTED_BUNDLE_UNVERIFIED,
            reason="Receipt is an untrusted imported bundle; zero trust assumption",
        )

    if receipt.kind != ReceiptKind.TRUSTED_COLLECTOR_RECEIPT.value:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_INVALID_KIND,
            reason=f"Unknown receipt kind: {receipt.kind}",
        )

    # 2. Check essential fields
    if (
        not receipt.receipt_id
        or not receipt.run_id
        or not receipt.collector_id
        or not receipt.collected_url
        or not receipt.content_sha256
        or not receipt.permit_ref
        or not receipt.policy_decision_ref
        or not receipt.signature
        or not receipt.key_id
    ):
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_MISSING_FIELDS,
            reason="Required receipt fields missing or empty",
        )

    # 3. Check content SHA256 if raw bytes are provided
    computed_sha = ""
    if raw_content_bytes is not None:
        computed_sha = compute_content_sha256(raw_content_bytes)
        if computed_sha.lower() != receipt.content_sha256.strip().lower():
            return ReceiptValidationResult(
                is_trusted=False,
                status=ReceiptValidationStatus.REJECTED_CONTENT_HASH_MISMATCH,
                reason=f"Raw content SHA256 {computed_sha} does not match receipt SHA256 {receipt.content_sha256}",
                computed_content_sha256=computed_sha,
            )

    # 4. Verify HMAC signature
    key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    payload = _canonical_signing_string(
        receipt_id=receipt.receipt_id,
        kind=receipt.kind,
        run_id=receipt.run_id,
        collector_id=receipt.collector_id,
        collected_url=receipt.collected_url,
        collected_at=receipt.collected_at,
        content_sha256=receipt.content_sha256,
        permit_ref=receipt.permit_ref,
        policy_decision_ref=receipt.policy_decision_ref,
        key_id=receipt.key_id,
    )
    expected_sig = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, receipt.signature):
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_SIGNATURE_MISMATCH,
            reason="HMAC signature verification failed (tampered receipt or invalid key)",
            computed_content_sha256=computed_sha,
        )

    return ReceiptValidationResult(
        is_trusted=True,
        status=ReceiptValidationStatus.VERIFIED,
        reason="Cryptographic receipt verified successfully",
        computed_content_sha256=computed_sha,
    )
