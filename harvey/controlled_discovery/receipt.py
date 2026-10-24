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
- Uses unambiguous versioned canonical JSON to eliminate delimiter collision.
- Secret keys are NEVER stored in repo or hardcoded fixtures; passed via runtime injection.
- Offline fixtures are strictly prevented from claiming TRUSTED_COLLECTOR_RECEIPT status.
- Business-level replay defense: receipt idempotency, cross-run, cross-target, and key revocation checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Set, Union


class ReceiptKind(str, Enum):
    UNTRUSTED_IMPORTED_BUNDLE = "UNTRUSTED_IMPORTED_BUNDLE"
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    TRUSTED_COLLECTOR_RECEIPT = "TRUSTED_COLLECTOR_RECEIPT"


CANONICAL_SCHEMA_VERSION = "harvey-receipt-v2"


class ReceiptValidationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED_SIGNATURE_MISMATCH = "REJECTED_SIGNATURE_MISMATCH"
    REJECTED_CONTENT_HASH_MISMATCH = "REJECTED_CONTENT_HASH_MISMATCH"
    REJECTED_MISSING_FIELDS = "REJECTED_MISSING_FIELDS"
    REJECTED_INVALID_KIND = "REJECTED_INVALID_KIND"
    REJECTED_CONTENT_MISSING = "REJECTED_CONTENT_MISSING"
    REJECTED_KEY_REVOKED_OR_INACTIVE = "REJECTED_KEY_REVOKED_OR_INACTIVE"
    REJECTED_REPLAY_DUPLICATE_IMPORT = "REJECTED_REPLAY_DUPLICATE_IMPORT"
    REJECTED_REPLAY_RUN_MISMATCH = "REJECTED_REPLAY_RUN_MISMATCH"
    REJECTED_REPLAY_TARGET_MISMATCH = "REJECTED_REPLAY_TARGET_MISMATCH"
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
    target_id: str = ""
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
            target_id=str(sanitized.get("target_id", "")),
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
    content_verified: bool = False


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
    target_id: str = "",
) -> bytes:
    """Construct deterministic versioned payload for HMAC signature using canonical JSON.

    Eliminates delimiter injection / field collision by encoding fields with sorted keys,
    strict UTF-8 encoding, and separators without whitespace.
    """
    canonical_payload = {
        "collected_at": collected_at.strip(),
        "collected_url": collected_url.strip(),
        "collector_id": collector_id.strip(),
        "content_sha256": content_sha256.strip().lower(),
        "key_id": key_id.strip(),
        "kind": kind.strip(),
        "permit_ref": permit_ref.strip(),
        "policy_decision_ref": policy_decision_ref.strip(),
        "receipt_id": receipt_id.strip(),
        "run_id": run_id.strip(),
        "target_id": target_id.strip(),
        "version": CANONICAL_SCHEMA_VERSION,
    }
    return json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_collector_receipt(
    run_id: str,
    collector_id: str,
    collected_url: str,
    raw_content_bytes: bytes,
    permit_ref: str,
    policy_decision_ref: str,
    secret_key: Union[bytes, str],
    key_id: str = "collector-key-v1",
    target_id: str = "",
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
        target_id=target_id,
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
        target_id=target_id,
        signature=sig,
        key_id=key_id,
        extra_metadata=extra_metadata or {},
    )


def verify_collector_receipt(
    receipt: CollectorReceipt,
    secret_key: Union[bytes, str],
    raw_content_bytes: Optional[bytes] = None,
    require_content_reverification: bool = False,
    active_key_ids: Optional[Set[str]] = None,
    revoked_key_ids: Optional[Set[str]] = None,
) -> ReceiptValidationResult:
    """Verify a collection receipt against the key and optional raw body content.

    Rules:
    - OFFLINE_FIXTURE is NEVER treated as trusted live collection.
    - UNTRUSTED_IMPORTED_BUNDLE is marked UNTRUSTED.
    - TRUSTED_COLLECTOR_RECEIPT must have valid signature and matching content hash.
    - Key status is validated against active_key_ids and revoked_key_ids if provided.
    - When raw body content is missing, content_verified is False; if required, verification fails.
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

    # 1.1 Enforce Key Status (Active & Revocation checks)
    if revoked_key_ids and receipt.key_id in revoked_key_ids:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_KEY_REVOKED_OR_INACTIVE,
            reason=f"Key {receipt.key_id} is revoked",
        )
    if active_key_ids is not None and receipt.key_id not in active_key_ids:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_KEY_REVOKED_OR_INACTIVE,
            reason=f"Key {receipt.key_id} is not in active key set",
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
    content_is_verified = False
    if raw_content_bytes is not None:
        computed_sha = compute_content_sha256(raw_content_bytes)
        if computed_sha.lower() != receipt.content_sha256.strip().lower():
            return ReceiptValidationResult(
                is_trusted=False,
                status=ReceiptValidationStatus.REJECTED_CONTENT_HASH_MISMATCH,
                reason=f"Raw content SHA256 {computed_sha} does not match receipt SHA256 {receipt.content_sha256}",
                computed_content_sha256=computed_sha,
                content_verified=False,
            )
        content_is_verified = True
    elif require_content_reverification:
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_CONTENT_MISSING,
            reason="Raw content bytes missing; cannot claim content re-verification",
            content_verified=False,
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
        target_id=receipt.target_id,
    )
    expected_sig = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, receipt.signature):
        return ReceiptValidationResult(
            is_trusted=False,
            status=ReceiptValidationStatus.REJECTED_SIGNATURE_MISMATCH,
            reason="HMAC signature verification failed (tampered receipt or invalid key)",
            computed_content_sha256=computed_sha,
            content_verified=False,
        )

    return ReceiptValidationResult(
        is_trusted=True,
        status=ReceiptValidationStatus.VERIFIED,
        reason="Cryptographic receipt verified successfully",
        computed_content_sha256=computed_sha,
        content_verified=content_is_verified,
    )


class ReceiptReplayLedger:
    """SQLite-backed lightweight replay defense ledger for receipt import and usage.

    Reuses existing SQLite storage pattern without requiring a heavy PKI system:
    - Enforces receipt uniqueness (blocks duplicate receipt import).
    - Binds receipt to specific expected run_id (blocks cross-run reuse).
    - Binds receipt to specific expected target_id (blocks cross-target reuse).
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imported_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    collected_url TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_imported_receipt_run ON imported_receipts(run_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_imported_receipt_target ON imported_receipts(target_id)"
            )
            conn.execute("COMMIT")

    def check_and_record_receipt(
        self,
        receipt: CollectorReceipt,
        expected_run_id: Optional[str] = None,
        expected_target_id: Optional[str] = None,
    ) -> ReceiptValidationResult:
        """Verify replay constraints and record receipt into the local ledger.

        Checks:
        1. Cross-run reuse: if expected_run_id is supplied, receipt.run_id must match.
        2. Cross-target reuse: if expected_target_id is supplied and receipt has target_id, it must match.
        3. Duplicate import: receipt_id must not already exist in the ledger.
        """
        if expected_run_id and receipt.run_id != expected_run_id:
            return ReceiptValidationResult(
                is_trusted=False,
                status=ReceiptValidationStatus.REJECTED_REPLAY_RUN_MISMATCH,
                reason=f"Cross-run reuse detected: receipt.run_id '{receipt.run_id}' != expected '{expected_run_id}'",
            )

        if (
            expected_target_id
            and receipt.target_id
            and receipt.target_id != expected_target_id
        ):
            return ReceiptValidationResult(
                is_trusted=False,
                status=ReceiptValidationStatus.REJECTED_REPLAY_TARGET_MISMATCH,
                reason=f"Cross-target reuse detected: receipt.target_id '{receipt.target_id}' != expected '{expected_target_id}'",
            )

        now_ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT run_id, target_id FROM imported_receipts WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                )
                existing = cur.fetchone()
                if existing:
                    conn.execute("ROLLBACK")
                    return ReceiptValidationResult(
                        is_trusted=False,
                        status=ReceiptValidationStatus.REJECTED_REPLAY_DUPLICATE_IMPORT,
                        reason=f"Duplicate receipt import rejected: receipt_id '{receipt.receipt_id}' was already imported in run '{existing['run_id']}'",
                    )

                conn.execute(
                    """
                    INSERT INTO imported_receipts (
                        receipt_id, run_id, target_id, collector_id,
                        collected_url, content_sha256, imported_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        receipt.run_id,
                        receipt.target_id,
                        receipt.collector_id,
                        receipt.collected_url,
                        receipt.content_sha256,
                        now_ts,
                    ),
                )
                conn.execute("COMMIT")
                return ReceiptValidationResult(
                    is_trusted=True,
                    status=ReceiptValidationStatus.VERIFIED,
                    reason="Receipt successfully recorded with no replay violations",
                )
            except Exception:
                conn.execute("ROLLBACK")
                raise
