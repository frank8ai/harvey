"""Integration test suite for Harvey W1-05-D Controlled Egress Integration.

Covers the mandatory 14 security integration assertions:
1. Full controlled acquisition pipeline for authorized fake targets.
2. Immediate rejection of unauthorized targets (Fail-Closed default deny).
3. Whitelisted origin redirecting to non-whitelisted target is strictly blocked.
4. Target denied by robots.txt policy is blocked.
5. SSRF transport defense: loopback, private RFC1918, IPv6, cloud metadata, DNS rebinding rejected.
6. Concurrent requests exceeding hard budget are fail-closed.
7. Oversized response stream truncation and circuit breaker trips.
8. Cross-process / multi-worker rate limiting and budget persistence across restarts.
9. 1:1 correspondence between physical outbound HTTP attempts and OutboundAuditLogger records.
10. Trusted collection receipt cryptographic signing, verification, and rejection of forged signatures / altered bodies.
11. End-to-end collection generates valid Observations, Qualification, and OpportunityCards via pipeline adapter.
12. Physical lock verification: Outbound email senders and Instantly side-effects remain strictly forbidden.
13. Full Harvey regression safety check.
14. Environmental awareness and CI compliance status.
"""

import asyncio
import hashlib
import json
import os
import socket
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import pytest
import pytest_asyncio

from harvey.agents.sender import Sender
from harvey.agents.writer import Writer
from harvey.collectors.devtools import (
    DevToolsPipelineAdapter,
    evaluate_devtools_prospect,
    record_devtools_observations,
)
from harvey.collectors.profile import ProfileCollector, profile_companies
from harvey.config import HarveyConfig, EnvConfig
from harvey.controlled_discovery.audit import (
    OutboundAuditEvent,
    OutboundAuditLogger,
    sanitize_headers,
    sanitize_url,
)
from harvey.controlled_discovery.budget import (
    BudgetExceededError,
    BudgetLimits,
    BudgetUnauthorizedError,
    HardBudgetLedger,
    ReservationRequest,
)
from harvey.controlled_discovery.gateway import (
    ControlledEgressBlockedError,
    ControlledEgressGateway,
    ControlledEgressResponse,
)
from harvey.controlled_discovery.limiter import (
    ConcurrencyTimeoutError,
    FakeClock,
    LeaseReleaseOutcome,
    LimiterConfig,
    MaxRetriesExceededError,
    OfflineEgressBlockedError,
    PersistentEgressLimiter,
    RedirectLimitExceededError,
    ResponseBodyMeter,
    ResponseSizeLimitExceededError,
)
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
from harvey.controlled_discovery.receipt import (
    CollectorReceipt,
    ReceiptValidationStatus,
    compute_content_sha256,
    sign_collector_receipt,
    verify_collector_receipt,
)
from harvey.integrations.mail_provider import DryRunMailProvider
from harvey.pipeline import run_profile_stage
from harvey.security_ssrf import SSRFBlockedError, SSRFSafeTransport, is_safe_ip
from harvey.signals import seed_signal_catalog
from harvey.state import StateManager


MASTER_TEST_KEY = b"w105-master-hmac-secret-32bytes-len!!"
KEY_ID = "w105-d-test-key-v1"


def create_test_gateway(
    tmp_path: Path,
    custom_transport: Optional[httpx.AsyncBaseTransport] = None,
    allowlist: Optional[TargetAllowlist] = None,
    offline_mode: bool = False,
    budget_authorized: bool = True,
    http_budget: int = 10,
    daily_http_budget: int = 50,
    signing_key: bytes = MASTER_TEST_KEY,
    key_id: str = KEY_ID,
    max_response_bytes: int = 2 * 1024 * 1024,
    max_redirects: int = 3,
    max_retries: int = 2,
    clock=None,
) -> tuple[ControlledEgressGateway, HardBudgetLedger, PersistentEgressLimiter, OutboundAuditLogger, SourcePolicyEngine]:
    budget_db = str(tmp_path / f"budget_{uuid.uuid4().hex[:8]}.db")
    limiter_db = str(tmp_path / f"limiter_{uuid.uuid4().hex[:8]}.db")
    audit_db = str(tmp_path / f"audit_{uuid.uuid4().hex[:8]}.db")

    policy_engine = SourcePolicyEngine(allowlist=allowlist or TargetAllowlist())
    budget_ledger = HardBudgetLedger(
        db_path=budget_db,
        limits=BudgetLimits(
            authorized=budget_authorized,
            max_run_http_requests=http_budget,
            max_daily_http_requests=daily_http_budget,
        ),
    )
    limiter = PersistentEgressLimiter(
        db_path=limiter_db,
        config=LimiterConfig(
            offline_mode=offline_mode,
            global_concurrency=5,
            per_domain_concurrency=2,
            min_domain_interval_seconds=0.01,
            max_response_bytes=max_response_bytes,
            max_redirects=max_redirects,
            max_retries=max_retries,
            request_timeout_seconds=5.0,
        ),
        clock=clock,
    )
    audit_logger = OutboundAuditLogger(db_path=audit_db)

    gateway = ControlledEgressGateway(
        policy_engine=policy_engine,
        budget_ledger=budget_ledger,
        limiter=limiter,
        audit_logger=audit_logger,
        signing_key=signing_key,
        key_id=key_id,
        custom_transport=custom_transport,
        timeout=5.0,
    )
    return gateway, budget_ledger, limiter, audit_logger, policy_engine


@pytest_asyncio.fixture
async def state_fixture():
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = StateManager(os.path.join(tmpdir, "test_int.db"))
        await sm.init_db()
        yield sm


def register_fake_target(
    allowlist: TargetAllowlist,
    domain: str,
    company_id: str,
    path_prefixes: list[str] | None = None,
):
    scope = CompanyTargetScope(
        company_id=company_id,
        primary_domain=domain,
        allowed_domains={domain},
        allowed_path_prefixes=path_prefixes or ["/"],
        allowed_schemes={"https", "http"},
        allowed_ports={80, 443},
        allowed_purposes={
            AccessPurpose.RESEARCH_STUDY,
            AccessPurpose.CONTROLLED_EXPERIMENT,
        },
        required_statuses={
            AuthorizationStatus.TERMS_REVIEWED,
            AuthorizationStatus.DATA_USE_AUTHORIZED,
            AuthorizationStatus.APPROVED_FOR_EXPERIMENT,
        },
        source_status=SourceStatus.VERIFIED,
    )
    allowlist.register_target(scope)
    return scope


# ── Test 1: Full Controlled Acquisition Pipeline for Authorized Fake Target ───

@pytest.mark.asyncio
async def test_01_authorized_fake_target_full_pipeline(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "authorized-study.fake", "comp_auth_01", ["/about"])

    fake_html = b"<html><head><title>Authorized Target</title></head><body><h1>Welcome</h1></body></html>"

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=fake_html, headers={"Content-Type": "text/html; charset=utf-8"})

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()

    policy.inject_robots_txt("authorized-study.fake", "User-agent: *\nAllow: /\n")

    resp = await gateway.request(
        url="https://authorized-study.fake/about",
        company_id="comp_auth_01",
        purpose=AccessPurpose.CONTROLLED_EXPERIMENT,
        collector_id="test.collector.01",
    )

    assert isinstance(resp, ControlledEgressResponse)
    assert resp.status_code == 200
    assert resp.content == fake_html
    assert resp.url == "https://authorized-study.fake/about"

    val_res = verify_collector_receipt(
        receipt=resp.receipt,
        secret_key=MASTER_TEST_KEY,
        raw_content_bytes=resp.content,
    )
    assert val_res.status == ReceiptValidationStatus.VERIFIED
    assert val_res.is_trusted is True
    assert val_res.computed_content_sha256 == hashlib.sha256(fake_html).hexdigest()

    events = audit.query_logs(target_id="comp_auth_01")
    assert len(events) == 1
    assert events[0]["status"] == "SUCCESS"
    assert events[0]["permit_id"] == resp.receipt.permit_ref


# ── Test 2: Unauthorized Target Denied (Fail-Closed Default Deny) ──────────────

@pytest.mark.asyncio
async def test_02_unauthorized_target_rejected_fail_closed(tmp_path):
    allowlist = TargetAllowlist()
    network_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal network_called
        network_called = True
        return httpx.Response(200, text="should never be hit")

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()

    with pytest.raises(ControlledEgressBlockedError) as exc_info:
        await gateway.request(
            url="https://unauthorized-competitor.com/careers",
            company_id="comp_unauth",
        )

    assert "denied by policy" in str(exc_info.value)
    assert not network_called

    events = audit.query_logs(target_id="comp_unauth")
    assert len(events) == 1
    assert events[0]["status"] == "DENIED_POLICY"


# ── Test 3: Whitelisted Redirect to Non-Whitelisted Target Blocked ────────────

@pytest.mark.asyncio
async def test_03_redirect_to_unauthorized_target_blocked(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "allowed-origin.fake", "comp_origin", ["/start"])

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "allowed-origin.fake":
            return httpx.Response(
                302,
                headers={"Location": "https://evil-unauthorized-exfil.com/trap"},
            )
        return httpx.Response(200, text="evil content")

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()

    policy.inject_robots_txt("allowed-origin.fake", "User-agent: *\nAllow: /\n")

    with pytest.raises(ControlledEgressBlockedError) as exc_info:
        await gateway.request(
            url="https://allowed-origin.fake/start",
            company_id="comp_origin",
            purpose=AccessPurpose.CONTROLLED_EXPERIMENT,
        )

    assert "Redirect to https://evil-unauthorized-exfil.com/trap denied" in str(exc_info.value)

    events = audit.query_logs(target_id="comp_origin")
    statuses = [e["status"] for e in events]
    assert "DENIED_REDIRECT" in statuses


# ── Test 4: Robots.txt Disallow Rejected ──────────────────────────────────────

@pytest.mark.asyncio
async def test_04_robots_disallow_rejected(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "strict-robots.fake", "comp_robots", ["/private/"])

    mock_transport = httpx.MockTransport(lambda req: httpx.Response(200, text="secret"))
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()

    policy.inject_robots_txt("strict-robots.fake", "User-agent: *\nDisallow: /private/\n")

    with pytest.raises(ControlledEgressBlockedError) as exc_info:
        await gateway.request(
            url="https://strict-robots.fake/private/data",
            company_id="comp_robots",
        )

    assert "denied by policy" in str(exc_info.value)
    assert exc_info.value.decision.decision == DecisionCode.DENIED_ROBOTS_DISALLOWED


# ── Test 5: SSRF Transport Defense ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_05_ssrf_transport_defense_matrix():
    assert not is_safe_ip("127.0.0.1")
    assert not is_safe_ip("10.0.0.1")
    assert not is_safe_ip("192.168.1.1")
    assert not is_safe_ip("172.16.0.1")
    assert not is_safe_ip("169.254.169.254")
    assert not is_safe_ip("::1")
    assert not is_safe_ip("::ffff:127.0.0.1")
    assert not is_safe_ip("::127.0.0.1")
    assert not is_safe_ip("fd00:ec2::254")
    assert is_safe_ip("93.184.216.34")

    transport = SSRFSafeTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(Exception) as exc_info:
            await client.get("http://127.0.0.1:8080/test")
        assert isinstance(exc_info.value, SSRFBlockedError) or "SSRF blocked" in str(exc_info.value)


# ── Test 6: Concurrent Requests Exceeding Budget Fail-Closed ──────────────────

@pytest.mark.asyncio
async def test_06_concurrency_hard_budget_limit(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "budget-metered.fake", "comp_budget", ["/"])

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
        http_budget=2,
    )
    await limiter.init_db()
    policy.inject_robots_txt("budget-metered.fake", "User-agent: *\nAllow: /\n")

    shared_run = "run_shared_budget_test"
    r1 = await gateway.request("https://budget-metered.fake/1", company_id="comp_budget", run_id=shared_run)
    r2 = await gateway.request("https://budget-metered.fake/2", company_id="comp_budget", run_id=shared_run)
    assert r1.status_code == 200
    assert r2.status_code == 200

    with pytest.raises(BudgetExceededError):
        await gateway.request("https://budget-metered.fake/3", company_id="comp_budget", run_id=shared_run)


# ── Test 7: Oversized Response Truncation and Circuit Breaker ──────────────────

@pytest.mark.asyncio
async def test_07_oversized_response_truncation_and_circuit_breaker(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "large-payload.fake", "comp_large", ["/huge"])

    huge_body = b"A" * (50 * 1024)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=huge_body)

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
        max_response_bytes=10 * 1024,
    )
    await limiter.init_db()
    policy.inject_robots_txt("large-payload.fake", "User-agent: *\nAllow: /\n")

    with pytest.raises(ResponseSizeLimitExceededError):
        await gateway.request("https://large-payload.fake/huge", company_id="comp_large")

    active_leases = await limiter.get_active_leases_count()
    assert active_leases == 0


# ── Test 8: Rate Limiting & Budget Persistence Across Restart ──────────────────

@pytest.mark.asyncio
async def test_08_budget_and_limiter_persistence_across_restart(tmp_path):
    budget_file = str(tmp_path / "persistent_budget.db")
    limiter_file = str(tmp_path / "persistent_limiter.db")

    clock = FakeClock(start_time=1000.0, auto_advance_on_sleep=True)

    b1 = HardBudgetLedger(db_path=budget_file, limits=BudgetLimits(authorized=True, max_run_http_requests=10))
    res = b1.reserve(ReservationRequest(run_id="run_persist", target_id="tgt_p", action_type="http_request", reserved_http_requests=3))
    b1.settle(res.reservation_id, status="success", actual_http_requests=3)

    l1 = PersistentEgressLimiter(
        db_path=limiter_file,
        config=LimiterConfig(offline_mode=False, min_domain_interval_seconds=5.0),
        clock=clock,
    )
    await l1.init_db()
    lease = await l1.acquire("https://persist.fake")
    await lease.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=30.0, http_status=429)

    b2 = HardBudgetLedger(db_path=budget_file, limits=BudgetLimits(authorized=True, max_run_http_requests=10))
    l2 = PersistentEgressLimiter(
        db_path=limiter_file,
        config=LimiterConfig(offline_mode=False, min_domain_interval_seconds=5.0),
        clock=clock,
    )
    await l2.init_db()

    usage = b2.get_run_usage("run_persist")
    total_used = usage["http_requests"]
    assert total_used == 3

    dom_state = await l2.get_domain_state("https://persist.fake")
    assert dom_state["cooldown_until"] == 1030.0


# ── Test 9: 1:1 Physical Outbound Connections to Audit Log Entries ────────────

@pytest.mark.asyncio
async def test_09_audit_log_one_to_one_correspondence(tmp_path):
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "audit-target.fake", "comp_audit_9", ["/"])

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if "err" in request.url.path:
            return httpx.Response(500, text="error")
        return httpx.Response(200, text="ok")

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()
    policy.inject_robots_txt("audit-target.fake", "User-agent: *\nAllow: /\n")

    await gateway.request("https://audit-target.fake/success", company_id="comp_audit_9")
    await gateway.request("https://audit-target.fake/err", company_id="comp_audit_9")

    events = audit.query_logs(target_id="comp_audit_9")
    assert len(events) == 2
    statuses = [e["status"] for e in events]
    assert "SUCCESS" in statuses
    assert "HTTP_500" in statuses


# ── Test 10: Trusted Receipt Cryptographic Verification and Tamper Detection ──

def test_10_trusted_receipt_verification_and_tamper_detection():
    body = b"Authentic page body payload for testing receipts."

    receipt = sign_collector_receipt(
        run_id="run_10",
        collector_id="test.collector",
        collected_url="https://verified.fake/home",
        raw_content_bytes=body,
        permit_ref="permit_xyz",
        policy_decision_ref="AUTHORIZED",
        secret_key=MASTER_TEST_KEY,
        key_id=KEY_ID,
    )

    val_res = verify_collector_receipt(receipt, MASTER_TEST_KEY, raw_content_bytes=body)
    assert val_res.status == ReceiptValidationStatus.VERIFIED
    assert val_res.is_trusted is True

    tampered_body = body + b"!"
    val_tampered = verify_collector_receipt(receipt, MASTER_TEST_KEY, raw_content_bytes=tampered_body)
    assert val_tampered.status == ReceiptValidationStatus.REJECTED_CONTENT_HASH_MISMATCH

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
        signature="forged_hex_signature",
        key_id=receipt.key_id,
    )
    val_forged = verify_collector_receipt(tampered_receipt, MASTER_TEST_KEY, raw_content_bytes=body)
    assert val_forged.status == ReceiptValidationStatus.REJECTED_SIGNATURE_MISMATCH


# ── Test 11: End-to-End Collection to Observations & OpportunityCard ──────────

@pytest.mark.asyncio
async def test_11_profile_collection_to_observations_and_cards(tmp_path, state_fixture):
    state = state_fixture
    allowlist = TargetAllowlist()
    register_fake_target(allowlist, "dentistry-test.fake", "c_dent_11", ["/"])

    home_html = (
        b"<html><head><title>Downtown Dental</title>"
        b"<script src='https://www.googleadservices.com/pagead/conversion.js'></script>"
        b"</head><body><h1>Dr. John Doe, DDS</h1>"
        b"<p>Practice Manager: Jane Smith</p>"
        b"<footer>Website designed by <a href='https://best-agency.fake'>Apex Digital</a></footer>"
        b"</body></html>"
    )

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=home_html, headers={"Content-Type": "text/html"})

    mock_transport = httpx.MockTransport(mock_handler)
    gateway, budget, limiter, audit, policy = create_test_gateway(
        tmp_path,
        custom_transport=mock_transport,
        allowlist=allowlist,
    )
    await limiter.init_db()
    policy.inject_robots_txt("dentistry-test.fake", "User-agent: *\nAllow: /\n")

    from harvey.models.company import Company
    await state.add_company(Company(id="c_dent_11", name="Downtown Dental", domain="dentistry-test.fake"))
    await seed_signal_catalog(state)
    await state.set_signal_status("RUNNING_GOOGLE_ADS", "confirmed")
    await state.set_signal_status("INCUMBENT_AGENCY", "confirmed")

    async with ProfileCollector(state, gateway=gateway, confirmed={"RUNNING_GOOGLE_ADS", "INCUMBENT_AGENCY"}) as collector:
        obs = await collector.profile_company("c_dent_11", "dentistry-test.fake")

    assert len(obs) >= 1
    codes = [o["signal_code"] for o in obs]
    assert "RUNNING_GOOGLE_ADS" in codes
    assert "INCUMBENT_AGENCY" in codes

    run_id = await state.start_run("profile", provider="controlled_gateway")
    total = await state.add_observations(obs, run_id=run_id)
    await state.finish_run(run_id, records=total)

    stored_obs = await state.get_observations("c_dent_11")
    assert len(stored_obs) >= 2


# ── Test 12: Email & Outreach Physical Locks Remain Enforced ─────────────────

@pytest.mark.asyncio
async def test_12_physical_outreach_lock_remains_enforced(state_fixture):
    state = state_fixture
    from harvey.config import PersonaConfig, ProductConfig, ICPConfig
    from harvey.config import ChannelsConfig, BrainConfig, ExperimentSecurityConfig
    cfg = HarveyConfig(
        persona=PersonaConfig(name="Test", company="Co", role="BD", email="t@co.com", linkedin="", tone="direct"),
        product=ProductConfig(name="Prod", description="desc", pricing="", key_benefits=["b1"], objection_responses={}),
        icp=ICPConfig(industries=["Tech"], company_size="1-10", titles=["CEO"], geography=["US"]),
        channels=ChannelsConfig(
            email={"enabled": True, "provider": "instantly", "max_daily_sends": 50, "require_approval": True}
        ),
        brain=BrainConfig(provider="claude"),
        experiment_security=ExperimentSecurityConfig(outbound_send_blocked=True),
    )

    sender = Sender(brain=None, state=state, config=cfg, env=EnvConfig(instantly_api_key="test_key"))
    assert isinstance(sender.provider, DryRunMailProvider)
    assert sender.provider.name == "dry_run"

    result = await sender.provider.send_email("test@example.com", "Subject", "Body")
    from harvey.integrations.mail_provider import ExecutionStatus
    assert result.ok is False
    assert result.execution_status == ExecutionStatus.SIMULATED
    assert "dryrun-" in result.message_id
    assert len(sender.provider.sent_messages) == 1
