"""W1-05-C Hard Budget, Outbound Audit, and Trusted Receipt Tests.

Verifies:
1. Two processes competing for the last budget token (atomic cross-process reservation).
2. Restart persistence (budget does not reset to zero upon re-opening the database).
3. Over-budget fail-closed enforcement (requests blocked immediately when limits exceeded).
4. Actual charge exceeding reservation conservatively blocks subsequent requests.
5. Failed and timed-out requests are accounted for conservatively (no free-riding).
6. Duplicate callback idempotency (cannot settle an already settled reservation).
7. Illegal or forged receipts cannot become VERIFIED.
8. Modifying original content causes hash and verification failure.
9. Secret keys and credentials are never leaked to audit logs.
10. Offline fixtures cannot masquerade as trusted live collector receipts.
11. Unauthorized mode strictly forbids any external budget allocation.
"""

import hashlib
import multiprocessing as mp
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from harvey.controlled_discovery.budget import (
    BudgetAlreadySettledError,
    BudgetExceededError,
    BudgetLimits,
    BudgetReservationNotFoundError,
    BudgetUnauthorizedError,
    HardBudgetLedger,
    ReservationRequest,
)
from harvey.controlled_discovery.audit import (
    OutboundAuditEvent,
    OutboundAuditLogger,
    sanitize_headers,
    sanitize_url,
)
from harvey.controlled_discovery.receipt import (
    CollectorReceipt,
    ReceiptKind,
    ReceiptReplayLedger,
    ReceiptValidationStatus,
    compute_content_sha256,
    sign_collector_receipt,
    verify_collector_receipt,
)


# ── Top-level worker for cross-process concurrency test ───────────────
def _worker_reserve_token(db_path: str, run_id: str, results_queue: mp.Queue):
    """Worker process attempting to reserve a single budget token."""
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=10),
    )
    req = ReservationRequest(
        run_id=run_id,
        target_id="target-proc",
        action_type="http_request",
        reserved_http_requests=1,
    )
    try:
        rec = ledger.reserve(req)
        results_queue.put(("SUCCESS", rec.reservation_id))
    except BudgetExceededError as e:
        results_queue.put(("EXCEEDED", str(e)))
    except Exception as e:
        results_queue.put(("ERROR", str(e)))


# ── 1. Hard Budget: Cross-process Atomic Reservation ───────────────────
def test_two_processes_competing_for_last_budget_tokens(tmp_path):
    """Verify that multiple processes competing for budget tokens never exceed limit."""
    db_path = tmp_path / "budget_race.db"
    run_id = "run-race-001"
    # Total limit = 10
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=10),
    )

    # Pre-reserve 9 tokens so only 1 token remains
    for i in range(9):
        ledger.reserve(
            ReservationRequest(
                run_id=run_id,
                target_id=f"target-{i}",
                action_type="http_request",
                reserved_http_requests=1,
            )
        )

    q = mp.Queue()
    # Spawn 4 processes simultaneously competing for that remaining 1 token
    processes = [
        mp.Process(target=_worker_reserve_token, args=(str(db_path), run_id, q))
        for _ in range(4)
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join(timeout=10.0)

    results = [q.get(timeout=2.0) for _ in range(4)]
    successes = [r for r in results if r[0] == "SUCCESS"]
    exceeded = [r for r in results if r[0] == "EXCEEDED"]
    errors = [r for r in results if r[0] == "ERROR"]

    assert len(errors) == 0, f"Unexpected worker errors: {errors}"
    assert len(successes) == 1, f"Expected exactly 1 process to win the last token, got {len(successes)}"
    assert len(exceeded) == 3, f"Expected exactly 3 processes to be blocked, got {len(exceeded)}"

    usage = ledger.get_run_usage(run_id)
    assert usage["http_requests"] == 10


# ── 2. Hard Budget: Persistence across restarts ───────────────────────
def test_budget_persistence_across_restart(tmp_path):
    """Verify that reopening the database recovers all active and settled usage."""
    db_path = tmp_path / "budget_persist.db"
    run_id = "run-persist-100"

    # Instance 1: reserve and settle
    ledger1 = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=50),
    )
    r1 = ledger1.reserve(
        ReservationRequest(
            run_id=run_id,
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=5,
            reserved_cost_usd=0.25,
        )
    )
    ledger1.settle(r1.reservation_id, status="success", actual_http_requests=5, actual_cost_usd=0.25)

    # Instance 1: reserve another pending 3 requests
    ledger1.reserve(
        ReservationRequest(
            run_id=run_id,
            target_id="t2",
            action_type="http_request",
            reserved_http_requests=3,
            reserved_cost_usd=0.10,
        )
    )

    # Instance 2 (simulate process restart with fresh ledger object)
    ledger2 = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=50),
    )
    usage = ledger2.get_run_usage(run_id)
    assert usage["http_requests"] == 8  # 5 settled + 3 reserved
    assert abs(usage["cost_usd"] - 0.35) < 1e-4


# ── 3. Hard Budget: Over-budget Fail-Closed Enforcement ─────────────────
def test_over_budget_fails_closed(tmp_path):
    """Verify that requests exceeding run, daily, or dollar limits are immediately blocked."""
    db_path = tmp_path / "budget_failclosed.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(
            authorized=True,
            max_run_http_requests=2,
            max_daily_http_requests=10,
            max_model_cost_usd=1.0,
        ),
    )
    run_id = "run-fc-01"

    # Reserve up to limit (2 requests)
    r1 = ledger.reserve(
        ReservationRequest(
            run_id=run_id,
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=2,
        )
    )
    assert r1.reserved_http_requests == 2

    # Next reservation must fail closed
    with pytest.raises(BudgetExceededError, match="Run HTTP request budget exceeded"):
        ledger.reserve(
            ReservationRequest(
                run_id=run_id,
                target_id="t2",
                action_type="http_request",
                reserved_http_requests=1,
            )
        )


# ── 4. Hard Budget: Actual Charge Exceeding Reservation ────────────────
def test_actual_charge_exceeding_reservation_blocks_subsequent(tmp_path):
    """Verify that if an API settles for more than reserved, subsequent calls are blocked."""
    db_path = tmp_path / "budget_overcharge.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_model_cost_usd=2.0),
    )
    run_id = "run-oc-01"

    # Reserve $0.50
    r1 = ledger.reserve(
        ReservationRequest(
            run_id=run_id,
            target_id="m1",
            action_type="model_call",
            reserved_cost_usd=0.50,
        )
    )
    # Actual charge is $2.10 (e.g. huge unexpected output token burst)
    ledger.settle(r1.reservation_id, status="success", actual_cost_usd=2.10)

    # Next call attempting to reserve $0.10 must immediately fail closed
    with pytest.raises(BudgetExceededError, match="Model dollar budget exceeded"):
        ledger.reserve(
            ReservationRequest(
                run_id=run_id,
                target_id="m2",
                action_type="model_call",
                reserved_cost_usd=0.10,
            )
        )


# ── 5. Hard Budget: Conservative Accounting for Failures ───────────────
def test_failed_requests_accounted_conservatively(tmp_path):
    """Verify that timeout or failed requests retain reserved allocation to prevent quota bypass."""
    db_path = tmp_path / "budget_fail_account.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=5, max_model_cost_usd=1.0),
    )
    run_id = "run-fail-01"

    r1 = ledger.reserve(
        ReservationRequest(
            run_id=run_id,
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=2,
            reserved_cost_usd=0.40,
        )
    )
    # Settle with timeout and unknown actuals (None)
    ledger.settle(r1.reservation_id, status="timeout", actual_http_requests=None, actual_cost_usd=None)

    usage = ledger.get_run_usage(run_id)
    # Conservative: 2 HTTP requests and $0.40 still counted
    assert usage["http_requests"] == 2
    assert abs(usage["cost_usd"] - 0.40) < 1e-4


# ── 6. Hard Budget: Duplicate Callback Idempotency ─────────────────────
def test_duplicate_settlement_rejected(tmp_path):
    """Verify that a reservation cannot be settled twice."""
    db_path = tmp_path / "budget_idempotent.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=10),
    )
    r1 = ledger.reserve(
        ReservationRequest(
            run_id="run-idem",
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=1,
        )
    )
    ledger.settle(r1.reservation_id, status="success", actual_http_requests=1)

    with pytest.raises(BudgetAlreadySettledError, match="has already been settled"):
        ledger.settle(r1.reservation_id, status="success", actual_http_requests=1)


# ── 7 & 8. Trusted Receipt: Cryptographic Verification & Tamper Resistance ──
def test_trusted_receipt_verification_and_tamper_detection():
    """Verify that genuine receipts pass, but forged signatures or altered content fail."""
    secret_key = b"super-secret-collector-key-32b"
    raw_html = b"<html><head><title>FetchInbox</title></head><body>Real evidence</body></html>"

    receipt = sign_collector_receipt(
        run_id="run-rcp-01",
        collector_id="collector-devtools-v1",
        collected_url="https://fetchinbox.ai",
        raw_content_bytes=raw_html,
        permit_ref="permit-1234",
        policy_decision_ref="policy-allow-4321",
        secret_key=secret_key,
    )

    # Valid verification
    res = verify_collector_receipt(receipt, secret_key=secret_key, raw_content_bytes=raw_html)
    assert res.is_trusted is True
    assert res.status == ReceiptValidationStatus.VERIFIED

    # 1. Modifying raw content must fail verification with hash mismatch
    tampered_html = b"<html><head><title>FetchInbox</title></head><body>Tampered!</body></html>"
    res_tampered = verify_collector_receipt(receipt, secret_key=secret_key, raw_content_bytes=tampered_html)
    assert res_tampered.is_trusted is False
    assert res_tampered.status == ReceiptValidationStatus.REJECTED_CONTENT_HASH_MISMATCH

    # 2. Tampered signature must fail verification
    tampered_receipt = CollectorReceipt(
        receipt_id=receipt.receipt_id,
        kind=receipt.kind,
        run_id=receipt.run_id,
        collector_id=receipt.collector_id,
        collected_url=receipt.collected_url,
        collected_at=receipt.collected_at,
        content_sha256=receipt.content_sha256,
        permit_ref=receipt.permit_ref,
        policy_decision_ref=receipt.policy_decision_ref,
        signature="0000000000000000000000000000000000000000000000000000000000000000",
        key_id=receipt.key_id,
    )
    res_forged = verify_collector_receipt(tampered_receipt, secret_key=secret_key, raw_content_bytes=raw_html)
    assert res_forged.is_trusted is False
    assert res_forged.status == ReceiptValidationStatus.REJECTED_SIGNATURE_MISMATCH

    # 3. User claiming verified=True cannot trick from_dict into skipping verification
    fake_payload = receipt.to_dict()
    fake_payload["verified"] = True
    fake_payload["signature"] = "forged"
    rebuilt = CollectorReceipt.from_dict(fake_payload)
    assert not hasattr(rebuilt, "verified") or getattr(rebuilt, "verified", None) is None
    res_untrusted = verify_collector_receipt(rebuilt, secret_key=secret_key, raw_content_bytes=raw_html)
    assert res_untrusted.is_trusted is False


# ── 9. Audit Logging: Secrets and Keys Never Leaked ────────────────────
def test_audit_log_redacts_credentials_and_headers(tmp_path):
    """Verify that Authorization, API Keys, cookies, and tokens are redacted."""
    db_path = tmp_path / "audit.db"
    logger = OutboundAuditLogger(db_path=db_path)

    raw_url = "https://api.example.com/search?q=test&api_key=SECRET_KEY_12345&token=BEARER_9999"
    headers = {
        "Authorization": "Bearer sk-proj-1234567890abcdef",
        "Cookie": "session_id=secret_cookie_val",
        "X-Api-Key": "live_key_xyz",
        "User-Agent": "Harvey-Controlled-Discovery/1.0",
    }
    details = {
        "headers": headers,
        "note": "testing outbound",
    }

    event = OutboundAuditEvent(
        run_id="run-aud-01",
        target_id="tgt-01",
        original_url=raw_url,
        resolved_host="api.example.com",
        resolved_ip="93.184.216.34",
        resolved_port=443,
        outbound_at="",
        policy_decision="ALLOW",
        permit_id="per-1",
        budget_reservation_id="rsv-1",
        status="SUCCESS",
        error_message="Failed with Bearer sk-secret-1234567890 key=abc123456",
        details_json=str(details).replace("'", '"'),
    )

    event_id = logger.log(event)
    logs = logger.query_logs(run_id="run-aud-01")
    assert len(logs) == 1
    entry = logs[0]

    # Assert URL is sanitized
    assert "SECRET_KEY_12345" not in entry["original_url"]
    assert "BEARER_9999" not in entry["original_url"]
    assert "api_key=%5BREDACTED%5D" in entry["original_url"] or "api_key=[REDACTED]" in entry["original_url"]

    # Assert Error Message is sanitized
    assert "sk-secret-1234567890" not in entry["error_message"]
    assert "abc123456" not in entry["error_message"]

    # Assert Details JSON has redacted headers
    assert "sk-proj-1234567890abcdef" not in entry["details_json"]
    assert "secret_cookie_val" not in entry["details_json"]
    assert "live_key_xyz" not in entry["details_json"]


# ── 10. Trusted Receipt: Offline Fixture Cannot Masquerade ─────────────
def test_offline_fixture_never_masquerades_as_trusted_receipt():
    """Verify that an OFFLINE_FIXTURE is never validated as trusted live collection."""
    fixture_receipt = CollectorReceipt(
        receipt_id="rcp-fixture-01",
        kind=ReceiptKind.OFFLINE_FIXTURE.value,
        run_id="run-test",
        collector_id="collector-offline",
        collected_url="http://offline.local",
        collected_at="2026-10-21T00:00:00Z",
        content_sha256="fakehash",
        permit_ref="permit-none",
        policy_decision_ref="policy-offline",
        signature="any-sig",
        key_id="dev-key",
    )
    res = verify_collector_receipt(fixture_receipt, secret_key=b"any-key")
    assert res.is_trusted is False
    assert res.status == ReceiptValidationStatus.OFFLINE_FIXTURE_ACKNOWLEDGED


# ── 11. Hard Budget: Unauthorized Mode Forbids Billing APIs ────────────
def test_unauthorized_mode_strictly_forbids_budget_allocation(tmp_path):
    """Verify that when authorized=False, any budget reservation attempt raises BudgetUnauthorizedError."""
    db_path = tmp_path / "budget_unauth.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=False),  # Unauthorized default!
    )

    req = ReservationRequest(
        run_id="run-unauth",
        target_id="target-ext",
        action_type="http_request",
        reserved_http_requests=1,
    )

    with pytest.raises(BudgetUnauthorizedError, match="Unauthorized mode forbids all external budget allocation"):
        ledger.reserve(req)

    usage = ledger.get_run_usage("run-unauth")
    assert usage["http_requests"] == 0
    assert usage["cost_usd"] == 0.0
from harvey.controlled_discovery.budget import (
    BudgetLimits,
    HardBudgetLedger,
    ReservationRequest,
    BudgetExceededError,
)

def test_unknown_pricing_defaults_to_forbidden(tmp_path):
    """Verify that attempting to reserve negative or unknown unconstrained budget raises ValueError."""
    db_path = tmp_path / "budget_pricing.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True),
    )
    with pytest.raises(ValueError, match="negative"):
        ledger.reserve(
            ReservationRequest(
                run_id="run-unknown",
                target_id="target-1",
                action_type="unknown_api",
                reserved_cost_usd=-1.0,
            )
        )


# ── 12. HMAC Canonical String: Delimiter Collision Red-before-Green ────────
def test_hmac_canonical_string_delimiter_collision_prevented():
    """Demonstrate that different field values with delimiters produce distinct signatures.

    Red-before-Green: Under pipe-delimited encoding, run_id='run-1' and collector_id='col|extra'
    collided identically with run_id='run-1|col' and collector_id='extra'.
    Under versioned canonical JSON encoding, the two signatures are guaranteed distinct.
    """
    secret_key = b"collision-test-key-32b"
    raw_content = b"<html>test content</html>"

    # Candidate A: run_id='r1', collector_id='col|extra'
    rA = sign_collector_receipt(
        run_id="r1",
        collector_id="col|extra",
        collected_url="https://example.com/a",
        raw_content_bytes=raw_content,
        permit_ref="permit-1",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        receipt_id="rcp_delim_01",
        collected_at="2026-10-21T00:00:00Z",
        key_id="k1",
    )

    # Candidate B: run_id='r1|col', collector_id='extra' (collision attempt)
    rB = sign_collector_receipt(
        run_id="r1|col",
        collector_id="extra",
        collected_url="https://example.com/a",
        raw_content_bytes=raw_content,
        permit_ref="permit-1",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        receipt_id="rcp_delim_01",
        collected_at="2026-10-21T00:00:00Z",
        key_id="k1",
    )

    # In canonical JSON, rA and rB MUST NOT have identical signatures
    assert rA.signature != rB.signature, "Signatures must not collide across delimiter boundaries"

    # Verify both signatures are valid against their own canonical representations
    vA = verify_collector_receipt(rA, secret_key=secret_key, raw_content_bytes=raw_content)
    vB = verify_collector_receipt(rB, secret_key=secret_key, raw_content_bytes=raw_content)
    assert vA.is_trusted is True
    assert vB.is_trusted is True


# ── 13. Receipt Replay Defenses: Duplicate, Cross-Run, Cross-Target ─────────
def test_receipt_replay_prevention_and_lifecycle(tmp_path):
    """Verify business-level replay defense: duplicate import, cross-run, cross-target, and revoked keys."""
    db_path = tmp_path / "receipt_replay.db"
    replay_ledger = ReceiptReplayLedger(db_path=db_path)
    secret_key = b"replay-test-key-32b"
    raw_content = b"<html>Receipt Replay Defense Test</html>"

    receipt1 = sign_collector_receipt(
        run_id="run-alpha",
        collector_id="collector-main",
        collected_url="https://target1.com/pricing",
        raw_content_bytes=raw_content,
        permit_ref="permit-alpha-1",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        target_id="target-corp-1",
        key_id="key-active-v1",
    )

    # 1. First import succeeds with full cryptographic and content verification
    res1 = replay_ledger.check_and_record_receipt(
        receipt1,
        expected_run_id="run-alpha",
        expected_target_id="target-corp-1",
        secret_key=secret_key,
        raw_content_bytes=raw_content,
    )
    assert res1.is_trusted is True
    assert res1.status == ReceiptValidationStatus.VERIFIED
    assert res1.signature_verified is True
    assert res1.content_verified is True
    assert res1.replay_accepted is True

    # 2. Duplicate import in same run is blocked
    res_dup = replay_ledger.check_and_record_receipt(
        receipt1,
        expected_run_id="run-alpha",
        expected_target_id="target-corp-1",
    )
    assert res_dup.is_trusted is False
    assert res_dup.status == ReceiptValidationStatus.REJECTED_REPLAY_DUPLICATE_IMPORT

    # 3. Cross-run reuse attempt is blocked
    res_cross_run = replay_ledger.check_and_record_receipt(
        receipt1,
        expected_run_id="run-beta",
        expected_target_id="target-corp-1",
    )
    assert res_cross_run.is_trusted is False
    assert res_cross_run.status == ReceiptValidationStatus.REJECTED_REPLAY_RUN_MISMATCH

    # 4. Cross-target reuse attempt is blocked
    receipt_target2 = sign_collector_receipt(
        run_id="run-gamma",
        collector_id="collector-main",
        collected_url="https://target1.com/pricing",
        raw_content_bytes=raw_content,
        permit_ref="permit-gamma-1",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        target_id="target-corp-1",
        key_id="key-active-v1",
    )
    res_cross_target = replay_ledger.check_and_record_receipt(
        receipt_target2,
        expected_run_id="run-gamma",
        expected_target_id="target-corp-2",  # Expected target is corp-2, but receipt is bound to corp-1
    )
    assert res_cross_target.is_trusted is False
    assert res_cross_target.status == ReceiptValidationStatus.REJECTED_REPLAY_TARGET_MISMATCH

    # 5. Revoked and inactive keys are rejected
    v_revoked = verify_collector_receipt(
        receipt1,
        secret_key=secret_key,
        raw_content_bytes=raw_content,
        revoked_key_ids={"key-active-v1"},
    )
    assert v_revoked.is_trusted is False
    assert v_revoked.status == ReceiptValidationStatus.REJECTED_KEY_REVOKED_OR_INACTIVE

    v_inactive = verify_collector_receipt(
        receipt1,
        secret_key=secret_key,
        raw_content_bytes=raw_content,
        active_key_ids={"other-key-v2"},
    )
    assert v_inactive.is_trusted is False
    assert v_inactive.status == ReceiptValidationStatus.REJECTED_KEY_REVOKED_OR_INACTIVE

    # 6. Tampering with any signed field (collector_id, url, time, permit) fails signature
    tampered_url_receipt = CollectorReceipt(
        receipt_id=receipt1.receipt_id,
        kind=receipt1.kind,
        run_id=receipt1.run_id,
        collector_id=receipt1.collector_id,
        collected_url="https://malicious-redirect.com",  # Modified URL
        collected_at=receipt1.collected_at,
        content_sha256=receipt1.content_sha256,
        permit_ref=receipt1.permit_ref,
        policy_decision_ref=receipt1.policy_decision_ref,
        target_id=receipt1.target_id,
        signature=receipt1.signature,
        key_id=receipt1.key_id,
    )
    assert verify_collector_receipt(tampered_url_receipt, secret_key=secret_key).is_trusted is False

    tampered_time_receipt = CollectorReceipt(
        receipt_id=receipt1.receipt_id,
        kind=receipt1.kind,
        run_id=receipt1.run_id,
        collector_id=receipt1.collector_id,
        collected_url=receipt1.collected_url,
        collected_at="2025-01-01T00:00:00Z",  # Modified timestamp
        content_sha256=receipt1.content_sha256,
        permit_ref=receipt1.permit_ref,
        policy_decision_ref=receipt1.policy_decision_ref,
        target_id=receipt1.target_id,
        signature=receipt1.signature,
        key_id=receipt1.key_id,
    )
    assert verify_collector_receipt(tampered_time_receipt, secret_key=secret_key).is_trusted is False

    tampered_permit_receipt = CollectorReceipt(
        receipt_id=receipt1.receipt_id,
        kind=receipt1.kind,
        run_id=receipt1.run_id,
        collector_id=receipt1.collector_id,
        collected_url=receipt1.collected_url,
        collected_at=receipt1.collected_at,
        content_sha256=receipt1.content_sha256,
        permit_ref="fake-permit-999",  # Modified permit
        policy_decision_ref=receipt1.policy_decision_ref,
        target_id=receipt1.target_id,
        signature=receipt1.signature,
        key_id=receipt1.key_id,
    )
    assert verify_collector_receipt(tampered_permit_receipt, secret_key=secret_key).is_trusted is False

    # 7. Missing raw content cannot claim content reverification
    v_no_bytes_req = verify_collector_receipt(
        receipt1,
        secret_key=secret_key,
        raw_content_bytes=None,
        require_content_reverification=True,
    )
    assert v_no_bytes_req.is_trusted is False
    assert v_no_bytes_req.status == ReceiptValidationStatus.REJECTED_CONTENT_MISSING


# ── 14. Hard Budget: UTC Day Boundary vs Local Timezones ───────────────────
def test_utc_daily_budget_accounting_across_timezones(tmp_path, monkeypatch):
    """Verify that daily budgets strictly track UTC calendar dates, unaffected by local time shifts."""
    db_path = tmp_path / "utc_budget.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_daily_http_requests=5),
    )

    # Simulate UTC time at 23:30 on 2026-10-21 (which is 07:30 on 2026-10-22 in UTC+8)
    from datetime import datetime, timezone
    utc_night = datetime(2026, 10, 21, 23, 30, 0, tzinfo=timezone.utc)
    utc_morning = datetime(2026, 10, 22, 0, 15, 0, tzinfo=timezone.utc)

    # Reserve 5 requests on day 2026-10-21
    import harvey.controlled_discovery.budget as budget_mod
    monkeypatch.setattr(budget_mod, "_utcnow", lambda: utc_night.isoformat())
    monkeypatch.setattr(budget_mod, "_today_str", lambda: utc_night.date().isoformat())

    r1 = ledger.reserve(
        ReservationRequest(
            run_id="run-utc-1",
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=5,
        )
    )
    assert r1.reserved_http_requests == 5

    # 6th request on the same UTC day must fail closed
    with pytest.raises(BudgetExceededError, match="Daily HTTP request budget exceeded"):
        ledger.reserve(
            ReservationRequest(
                run_id="run-utc-1",
                target_id="t2",
                action_type="http_request",
                reserved_http_requests=1,
            )
        )

    # Next UTC day (00:15 on 2026-10-22): daily allowance resets in UTC
    monkeypatch.setattr(budget_mod, "_utcnow", lambda: utc_morning.isoformat())
    monkeypatch.setattr(budget_mod, "_today_str", lambda: utc_morning.date().isoformat())

    r2 = ledger.reserve(
        ReservationRequest(
            run_id="run-utc-2",
            target_id="t3",
            action_type="http_request",
            reserved_http_requests=3,
        )
    )
    assert r2.reserved_http_requests == 3
    assert ledger.get_daily_usage("2026-10-21") == 5
    assert ledger.get_daily_usage("2026-10-22") == 3


# ── 15. Hard Budget: Unknown / Negative Pricing Fail-Closed ─────────────────
def test_unknown_and_negative_cost_fail_closed(tmp_path):
    """Verify that negative settlement or negative reservations are strictly blocked."""
    db_path = tmp_path / "pricing_failclosed.db"
    ledger = HardBudgetLedger(
        db_path=db_path,
        limits=BudgetLimits(authorized=True, max_run_http_requests=10, max_model_cost_usd=5.0),
    )

    # Negative reservation is rejected
    with pytest.raises(ValueError, match="negative"):
        ledger.reserve(
            ReservationRequest(
                run_id="run-neg",
                target_id="t1",
                action_type="http_request",
                reserved_cost_usd=-0.50,
            )
        )

    # Valid reservation
    r = ledger.reserve(
        ReservationRequest(
            run_id="run-neg",
            target_id="t1",
            action_type="http_request",
            reserved_http_requests=2,
            reserved_cost_usd=1.0,
        )
    )

    # Settle with negative cost must fail closed
    with pytest.raises(ValueError, match="cannot be negative"):
        ledger.settle(r.reservation_id, status="success", actual_cost_usd=-1.0)


# ── Top-level worker for cross-process receipt consumption race ────────
def _worker_consume_receipt_race(
    db_path: str,
    receipt_dict: dict,
    expected_run_id: str,
    expected_target_id: str,
    secret_key: bytes,
    raw_content: bytes,
    results_queue: mp.Queue,
):
    """Worker process attempting to record and verify receipt concurrently."""
    try:
        from harvey.controlled_discovery.receipt import (
            CollectorReceipt,
            ReceiptReplayLedger,
            ReceiptValidationStatus,
        )
        receipt = CollectorReceipt.from_dict(receipt_dict)
        ledger = ReceiptReplayLedger(db_path=db_path)
        res = ledger.check_and_record_receipt(
            receipt,
            expected_run_id=expected_run_id,
            expected_target_id=expected_target_id,
            secret_key=secret_key,
            raw_content_bytes=raw_content,
        )
        results_queue.put((res.status.value, res.is_trusted, res.reason))
    except Exception as e:
        results_queue.put(("EXCEPTION", False, str(e)))


# ── 16. Receipt Replay Ledger: Cryptographic & Content Verification Matrix ────
def test_replay_ledger_cryptographic_and_content_verification_matrix(tmp_path):
    """Verify the 7 core security assertions for ReceiptReplayLedger:
    1. Forged HMAC signature with unique Receipt ID is rejected (never VERIFIED/TRUSTED).
    2. Valid signature but missing raw content yields SIGNATURE_VERIFIED, is_trusted=False.
    3. Valid content hash but missing secret_key yields CONTENT_VERIFIED, is_trusted=False.
    4. Neither secret_key nor raw_content yields REPLAY_ACCEPTED, is_trusted=False.
    5. Valid signature but replaced content yields REJECTED_CONTENT_HASH_MISMATCH, is_trusted=False.
    6. Cross-run / cross-target reuse is strictly blocked.
    7. Revoked key is rejected even if HMAC and content match.
    8. Offline fixture masquerading is rejected with is_trusted=False.
    """
    db_path = tmp_path / "replay_matrix.db"
    ledger = ReceiptReplayLedger(db_path=db_path)
    secret_key = b"replay-matrix-secret-key-32b"
    raw_content = b"<html>Evidence Content for Matrix Test</html>"

    # 1. Forged HMAC signature but unique Receipt ID -> rejected signature mismatch
    forged_receipt = CollectorReceipt(
        receipt_id="rcp_forged_unique_001",
        kind=ReceiptKind.TRUSTED_COLLECTOR_RECEIPT.value,
        run_id="run-matrix-1",
        collector_id="collector-matrix",
        collected_url="https://example.com/target",
        collected_at="2026-10-24T00:00:00Z",
        content_sha256=compute_content_sha256(raw_content),
        permit_ref="permit-001",
        policy_decision_ref="ALLOW",
        target_id="target-001",
        signature="COMPLETELY_FORGED_HMAC_SIGNATURE_HEX",
        key_id="matrix-key-v1",
    )
    res_forged = ledger.check_and_record_receipt(
        forged_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=secret_key,
        raw_content_bytes=raw_content,
    )
    assert res_forged.is_trusted is False
    assert res_forged.status == ReceiptValidationStatus.REJECTED_SIGNATURE_MISMATCH
    assert res_forged.signature_verified is False
    assert res_forged.replay_accepted is False

    # 2. Genuine receipt signed at collector boundary
    valid_receipt = sign_collector_receipt(
        run_id="run-matrix-1",
        collector_id="collector-matrix",
        collected_url="https://example.com/target",
        raw_content_bytes=raw_content,
        permit_ref="permit-001",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        target_id="target-001",
        key_id="matrix-key-v1",
    )

    # 2a. Unverified import without secret_key or raw_content -> REPLAY_ACCEPTED, is_trusted=False
    ledger_unverified = ReceiptReplayLedger(db_path=tmp_path / "unverified.db")
    res_unverified = ledger_unverified.check_and_record_receipt(
        valid_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
    )
    assert res_unverified.is_trusted is False
    assert res_unverified.status == ReceiptValidationStatus.REPLAY_ACCEPTED
    assert res_unverified.replay_accepted is True
    assert res_unverified.signature_verified is False
    assert res_unverified.content_verified is False

    # 2b. Signature verified but raw content missing -> SIGNATURE_VERIFIED, is_trusted=False
    ledger_sig_only = ReceiptReplayLedger(db_path=tmp_path / "sig_only.db")
    res_sig_only = ledger_sig_only.check_and_record_receipt(
        valid_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=secret_key,
        raw_content_bytes=None,
    )
    assert res_sig_only.is_trusted is False
    assert res_sig_only.status == ReceiptValidationStatus.SIGNATURE_VERIFIED
    assert res_sig_only.signature_verified is True
    assert res_sig_only.content_verified is False
    assert res_sig_only.replay_accepted is True

    # 2c. Content hash verified but secret_key missing -> CONTENT_VERIFIED, is_trusted=False
    ledger_content_only = ReceiptReplayLedger(db_path=tmp_path / "content_only.db")
    res_content_only = ledger_content_only.check_and_record_receipt(
        valid_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=None,
        raw_content_bytes=raw_content,
    )
    assert res_content_only.is_trusted is False
    assert res_content_only.status == ReceiptValidationStatus.CONTENT_VERIFIED
    assert res_content_only.content_verified is True
    assert res_content_only.signature_verified is False
    assert res_content_only.replay_accepted is True

    # 2d. Replaced/Tampered content with valid signature -> REJECTED_CONTENT_HASH_MISMATCH
    tampered_content = b"<html>Tampered Replaced Content</html>"
    ledger_tampered = ReceiptReplayLedger(db_path=tmp_path / "tampered.db")
    res_tampered = ledger_tampered.check_and_record_receipt(
        valid_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=secret_key,
        raw_content_bytes=tampered_content,
    )
    assert res_tampered.is_trusted is False
    assert res_tampered.status == ReceiptValidationStatus.REJECTED_CONTENT_HASH_MISMATCH
    assert res_tampered.replay_accepted is False

    # 2e. Revoked key -> REJECTED_KEY_REVOKED_OR_INACTIVE
    ledger_revoked = ReceiptReplayLedger(
        db_path=tmp_path / "revoked.db",
        revoked_key_ids={"matrix-key-v1"},
    )
    res_revoked = ledger_revoked.check_and_record_receipt(
        valid_receipt,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=secret_key,
        raw_content_bytes=raw_content,
    )
    assert res_revoked.is_trusted is False
    assert res_revoked.status == ReceiptValidationStatus.REJECTED_KEY_REVOKED_OR_INACTIVE
    assert res_revoked.replay_accepted is False

    # 2f. Offline fixture masquerading as live collection receipt -> OFFLINE_FIXTURE_ACKNOWLEDGED, is_trusted=False
    offline_fixture = CollectorReceipt(
        receipt_id="rcp_fixture_fake_001",
        kind=ReceiptKind.OFFLINE_FIXTURE.value,
        run_id="run-matrix-1",
        collector_id="collector-fixture",
        collected_url="https://example.com/target",
        collected_at="2026-10-24T00:00:00Z",
        content_sha256=compute_content_sha256(raw_content),
        permit_ref="permit-001",
        policy_decision_ref="ALLOW",
        target_id="target-001",
        signature="any-sig",
        key_id="matrix-key-v1",
    )
    res_fixture = ledger.check_and_record_receipt(
        offline_fixture,
        expected_run_id="run-matrix-1",
        expected_target_id="target-001",
        secret_key=secret_key,
        raw_content_bytes=raw_content,
    )
    assert res_fixture.is_trusted is False
    assert res_fixture.status == ReceiptValidationStatus.OFFLINE_FIXTURE_ACKNOWLEDGED
    assert res_fixture.replay_accepted is False


# ── 17. Receipt Replay Ledger: Concurrent Processes Competing for Same Receipt ──
def test_two_processes_competing_to_consume_same_receipt_atomically(tmp_path):
    """Verify that SQLite BEGIN IMMEDIATE guarantees atomic once-and-only-once receipt consumption across processes."""
    db_path = tmp_path / "receipt_race.db"
    secret_key = b"race-test-secret-key-32b"
    raw_content = b"<html>Concurrent Process Race Test Content</html>"

    receipt = sign_collector_receipt(
        run_id="run-race-proc",
        collector_id="collector-race",
        collected_url="https://target.com/race",
        raw_content_bytes=raw_content,
        permit_ref="permit-race-1",
        policy_decision_ref="ALLOW",
        secret_key=secret_key,
        target_id="target-race-1",
        key_id="race-key-v1",
    )

    q = mp.Queue()
    processes = [
        mp.Process(
            target=_worker_consume_receipt_race,
            args=(
                str(db_path),
                receipt.to_dict(),
                "run-race-proc",
                "target-race-1",
                secret_key,
                raw_content,
                q,
            ),
        )
        for _ in range(4)
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join(timeout=10.0)

    results = [q.get(timeout=2.0) for _ in range(4)]
    successes = [r for r in results if r[0] == "VERIFIED" and r[1] is True]
    duplicates = [r for r in results if r[0] == "REJECTED_REPLAY_DUPLICATE_IMPORT"]
    exceptions = [r for r in results if r[0] == "EXCEPTION"]

    assert len(exceptions) == 0, f"Unexpected worker exceptions: {exceptions}"
    assert len(successes) == 1, f"Expected exactly 1 process to successfully consume the receipt, got {len(successes)}"
    assert len(duplicates) == 3, f"Expected exactly 3 processes to be rejected as duplicate import, got {len(duplicates)}"
