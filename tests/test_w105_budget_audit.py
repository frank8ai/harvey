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
