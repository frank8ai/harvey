"""
tests/test_w105_egress_limiter.py

Comprehensive verification suite for W1-05-B Persistent Egress Limiter,
Concurrency Coordinator, and Resource Circuit Breaker.

Covers:
1. Multi-process race competition (no over-granting).
2. Consecutive retries and deterministic exponential backoff.
3. Timeout handling on lease acquisition.
4. Asyncio task cancellation and automatic lease release.
5. Crash recovery and stale lease reclamation.
6. HTTP 429 Retry-After parsing and domain cooldown.
7. Global and per-domain concurrency limits.
8. Single-domain minimum request interval pacing.
9. Streaming response byte metering and early rejection.
10. Redirect limits and cross-domain tracking.
11. Idempotent release and auditable settlement ledger.
12. Offline mode fail-closed protection.
"""

import asyncio
import multiprocessing
import os
import sys
import tempfile
import time
from typing import List
import pytest

from harvey.controlled_discovery.limiter import (
    Clock,
    ConcurrencyTimeoutError,
    FakeClock,
    LeaseReleaseOutcome,
    LeaseExpiredError,
    LimiterConfig,
    LimiterError,
    MaxRetriesExceededError,
    OfflineEgressBlockedError,
    PersistentEgressLimiter,
    RedirectLimitExceededError,
    RequestLease,
    ResponseBodyMeter,
    ResponseSizeLimitExceededError,
    is_pid_alive,
    normalize_domain,
    parse_retry_after,
)


# ── 1. Offline Mode Protection ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_offline_mode_fails_closed(tmp_path):
    """Offline mode must strictly forbid acquiring network egress leases."""
    db_file = tmp_path / "offline_limiter.db"
    limiter = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=True))
    await limiter.init_db()

    with pytest.raises(OfflineEgressBlockedError, match="blocked in offline mode"):
        await limiter.acquire("https://example.com/api")


# ── 2. Concurrency: Global & Per-Domain ────────────────────────────────────────

@pytest.mark.asyncio
async def test_per_domain_concurrency_limit(tmp_path):
    """When per_domain_concurrency=1, second lease for same domain must wait or timeout."""
    db_file = tmp_path / "domain_conc.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=5,
        per_domain_concurrency=1,
        min_domain_interval_seconds=0.0,
        request_timeout_seconds=0.5,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    # Worker 1 acquires
    lease1 = await limiter.acquire("https://alpha.com/path1")
    assert lease1.domain == "alpha.com"
    assert await limiter.get_active_leases_count("alpha.com") == 1

    # Worker 2 attempts same domain with timeout
    with pytest.raises(ConcurrencyTimeoutError):
        await limiter.acquire("https://alpha.com/path2", timeout=0.1)

    # Worker 3 acquires different domain (beta.com) successfully because domain differs
    lease_beta = await limiter.acquire("https://beta.com/other", timeout=0.1)
    assert lease_beta.domain == "beta.com"

    # Worker 1 releases
    await lease1.release()
    assert await limiter.get_active_leases_count("alpha.com") == 0

    # Worker 2 now succeeds
    lease2 = await limiter.acquire("https://alpha.com/path2", timeout=0.5)
    assert lease2.domain == "alpha.com"
    await lease2.release()
    await lease_beta.release()


@pytest.mark.asyncio
async def test_global_concurrency_limit(tmp_path):
    """When global_concurrency=2, a 3rd concurrent request across any domains must block."""
    db_file = tmp_path / "global_conc.db"
    clock = FakeClock(start_time=500.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=2,
        per_domain_concurrency=2,
        min_domain_interval_seconds=0.0,
        request_timeout_seconds=0.5,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    lease1 = await limiter.acquire("https://d1.com")
    lease2 = await limiter.acquire("https://d2.com")
    assert await limiter.get_active_leases_count() == 2

    # 3rd acquire across any domain must timeout
    with pytest.raises(ConcurrencyTimeoutError):
        await limiter.acquire("https://d3.com", timeout=0.1)

    await lease1.release()
    assert await limiter.get_active_leases_count() == 1

    # Now d3.com can acquire
    lease3 = await limiter.acquire("https://d3.com", timeout=0.5)
    assert await limiter.get_active_leases_count() == 2
    await lease2.release()
    await lease3.release()


# ── 3. Single-Domain Minimum Request Interval (Pacing) ─────────────────────────

@pytest.mark.asyncio
async def test_min_domain_interval_pacing(tmp_path):
    """Subsequent requests to the same domain must respect min_domain_interval_seconds."""
    db_file = tmp_path / "interval_pacing.db"
    clock = FakeClock(start_time=1000.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=5,
        per_domain_concurrency=5,
        min_domain_interval_seconds=2.0,
        request_timeout_seconds=10.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    # Request 1 at T=1000.0
    lease1 = await limiter.acquire("https://fast-service.org")
    assert lease1.acquired_at == 1000.0
    await lease1.release()

    # Request 2 immediately tried
    # Since min_interval is 2.0s, FakeClock auto-advances sleep to T=1002.0
    lease2 = await limiter.acquire("https://fast-service.org")
    assert clock.now() >= 1002.0
    assert lease2.acquired_at >= 1002.0
    await lease2.release()


# ── 4. Retries and Exponential Backoff ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_max_retries_and_backoff_calculation(tmp_path):
    """Enforces max_retries limit and deterministic exponential backoff formula."""
    db_file = tmp_path / "retries.db"
    config = LimiterConfig(
        offline_mode=False,
        max_retries=3,
        base_retry_backoff_seconds=1.0,
        max_retry_backoff_seconds=30.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config)
    await limiter.init_db()

    # Verify backoff calculation
    assert limiter.calculate_backoff(1) == 0.0
    assert limiter.calculate_backoff(2) == 1.0   # 1.0 * 2^0
    assert limiter.calculate_backoff(3) == 2.0   # 1.0 * 2^1
    assert limiter.calculate_backoff(4) == 4.0   # 1.0 * 2^2
    assert limiter.calculate_backoff(10) == 30.0  # capped at 30.0

    # Attempt 1, 2, 3 succeed acquire
    l1 = await limiter.acquire("https://api.test", attempt=1)
    await l1.release(LeaseReleaseOutcome.FAILURE)

    l2 = await limiter.acquire("https://api.test", attempt=2, timeout=5.0)
    await l2.release(LeaseReleaseOutcome.FAILURE)

    l3 = await limiter.acquire("https://api.test", attempt=3, timeout=5.0)
    await l3.release(LeaseReleaseOutcome.FAILURE)

    # Attempt 4 exceeds max_retries (3)
    with pytest.raises(MaxRetriesExceededError) as exc_info:
        await limiter.acquire("https://api.test", attempt=4)
    assert exc_info.value.attempt == 4
    assert exc_info.value.max_retries == 3


# ── 5. HTTP 429 & Retry-After Handling ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_429_retry_after_cooldown(tmp_path):
    """Receiving 429 with Retry-After header sets domain cooldown."""
    db_file = tmp_path / "rate_limited_429.db"
    clock = FakeClock(start_time=2000.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        min_domain_interval_seconds=0.0,
        request_timeout_seconds=5.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    lease = await limiter.acquire("https://rate-limited.io")
    # Release with 429 and Retry-After 10 seconds
    await lease.release(
        outcome=LeaseReleaseOutcome.RATE_LIMITED,
        retry_after_seconds=10.0,
        http_status=429,
    )

    state = await limiter.get_domain_state("https://rate-limited.io")
    assert state["cooldown_until"] == 2010.0
    assert state["consecutive_failures"] == 1

    # Attempt immediately at T=2000.0 should timeout
    with pytest.raises(ConcurrencyTimeoutError):
        await limiter.acquire("https://rate-limited.io", timeout=0.1)

    # Advance clock past cooldown (T=2011.0)
    clock.advance(11.0)

    # Now acquire succeeds
    lease2 = await limiter.acquire("https://rate-limited.io", timeout=1.0)
    assert lease2.domain == "rate-limited.io"
    await lease2.release(LeaseReleaseOutcome.SUCCESS)

    state2 = await limiter.get_domain_state("https://rate-limited.io")
    assert state2["consecutive_failures"] == 0


def test_parse_retry_after_formats():
    """Verify numeric seconds and HTTP date formats for Retry-After."""
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after(45) == 45.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None

    # HTTP Date
    now_ts = 1700000000.0
    # 60 seconds in the future
    date_str = "Wed, 14 Nov 2023 22:14:20 GMT"
    parsed = parse_retry_after(date_str, now=now_ts)
    assert parsed is not None
    assert parsed >= 0.0


# ── 6. Task Cancellation & Context Manager Clean-Up ───────────────────────────

@pytest.mark.asyncio
async def test_task_cancellation_releases_lease(tmp_path):
    """When a task holding a lease is cancelled, __aexit__ safely releases it."""
    db_file = tmp_path / "cancel.db"
    config = LimiterConfig(offline_mode=False, global_concurrency=1, min_domain_interval_seconds=0.0)
    limiter = PersistentEgressLimiter(str(db_file), config)
    await limiter.init_db()

    lease_holder_started = asyncio.Event()

    async def long_running_task():
        async with await limiter.acquire("https://held.com") as lease:
            lease_holder_started.set()
            await asyncio.sleep(100.0)

    task = asyncio.create_task(long_running_task())
    await lease_holder_started.wait()
    assert await limiter.get_active_leases_count() == 1

    # Cancel the task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Capacity must be immediately restored to 0 active leases
    assert await limiter.get_active_leases_count() == 0

    # Another task can acquire without delay
    lease2 = await limiter.acquire("https://held.com", timeout=1.0)
    assert lease2 is not None
    await lease2.release()


# ── 7. Crash Recovery & Stale Lease Reclamation ───────────────────────────────

@pytest.mark.asyncio
async def test_crash_recovery_expired_leases(tmp_path):
    """Expired leases from crashed processes are automatically reclaimed."""
    db_file = tmp_path / "crash_recovery.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=1,
        lease_ttl_seconds=10.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    # Worker crashes: acquires lease and terminates without release
    lease = await limiter.acquire("https://crashed-worker.com")
    assert await limiter.get_active_leases_count() == 1

    # Next acquire at T=102.0 still blocked by active lease
    clock.advance(2.0)
    with pytest.raises(ConcurrencyTimeoutError):
        await limiter.acquire("https://crashed-worker.com", timeout=0.1)

    # Time advances past lease TTL (T=111.0 > 100 + 10)
    clock.advance(9.0)

    # Next acquire automatically deletes the dead lease and succeeds!
    surviving_lease = await limiter.acquire("https://crashed-worker.com", timeout=1.0)
    assert surviving_lease is not None
    assert surviving_lease.lease_id != lease.lease_id
    await surviving_lease.release()


@pytest.mark.asyncio
async def test_explicit_recover_stale_leases(tmp_path):
    """recover_stale_leases() method sweeps dead leases and returns deleted count."""
    db_file = tmp_path / "sweep.db"
    clock = FakeClock(start_time=10.0, auto_advance_on_sleep=True)
    config = LimiterConfig(offline_mode=False, global_concurrency=5, lease_ttl_seconds=5.0)
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    await limiter.acquire("https://a.com")
    await limiter.acquire("https://b.com")
    assert await limiter.get_active_leases_count() == 2

    # Advance clock past TTL
    clock.advance(6.0)

    reclaimed = await limiter.recover_stale_leases()
    assert reclaimed == 2
    assert await limiter.get_active_leases_count() == 0


# ── 8. Response Body Meter Contract ───────────────────────────────────────────

def test_response_body_meter_incremental():
    """ResponseBodyMeter enforces max bytes on chunks and raises immediately."""
    meter = ResponseBodyMeter(max_bytes=100)

    meter.update(40)
    assert meter.bytes_metered == 40
    assert meter.remaining_bytes == 60
    assert not meter.is_exceeded

    meter.update(b"x" * 50)
    assert meter.bytes_metered == 90
    assert meter.remaining_bytes == 10

    # Next 20 bytes pushes to 110 > 100 -> raises ResponseSizeLimitExceededError
    with pytest.raises(ResponseSizeLimitExceededError) as exc_info:
        meter.update(20)
    assert exc_info.value.bytes_read == 110
    assert exc_info.value.max_bytes == 100


@pytest.mark.asyncio
async def test_response_body_meter_async_stream():
    """ResponseBodyMeter meters async generator stream correctly."""
    meter = ResponseBodyMeter(max_bytes=50)

    async def fake_stream():
        yield b"1234567890"  # 10
        yield b"abcdefghij"  # 10
        yield b"KLMNOPQRST"  # 10
        yield b"0123456789" * 3  # 30 -> 60 total, exceeds!

    chunks = []
    with pytest.raises(ResponseSizeLimitExceededError):
        async for chunk in meter.meter_stream(fake_stream()):
            chunks.append(chunk)

    assert len(chunks) == 3
    assert sum(len(c) for c in chunks) == 30


# ── 9. Redirect Limit Contract & Domain Migration ─────────────────────────────

@pytest.mark.asyncio
async def test_redirect_limit_and_domain_tracking(tmp_path):
    """Enforces max redirects and updates lease domain tracking upon redirect."""
    db_file = tmp_path / "redirects.db"
    config = LimiterConfig(offline_mode=False, max_redirects=3)
    limiter = PersistentEgressLimiter(str(db_file), config)
    await limiter.init_db()

    lease = await limiter.acquire("https://initial.org")
    assert lease.domain == "initial.org"

    # Redirect 1, 2, 3
    r1 = await lease.record_redirect("https://redirect1.org/next")
    assert r1 == 1
    assert lease.domain == "redirect1.org"

    r2 = await lease.record_redirect("https://redirect2.org/next")
    assert r2 == 2
    assert lease.domain == "redirect2.org"

    r3 = await lease.record_redirect("https://redirect3.org/final")
    assert r3 == 3
    assert lease.domain == "redirect3.org"

    # 4th redirect exceeds max_redirects (3)
    with pytest.raises(RedirectLimitExceededError) as exc_info:
        await lease.record_redirect("https://too-far.org")
    assert exc_info.value.redirects == 4
    assert exc_info.value.max_redirects == 3

    await lease.release()


# ── 10. Audit Logging & Idempotent Settlement ─────────────────────────────────

@pytest.mark.asyncio
async def test_idempotent_release_and_audit_log(tmp_path):
    """Multiple release calls must be idempotent and recorded in audit log."""
    db_file = tmp_path / "audit_log.db"
    config = LimiterConfig(offline_mode=False)
    limiter = PersistentEgressLimiter(str(db_file), config)
    await limiter.init_db()

    lease = await limiter.acquire("https://audit-target.com")
    await lease.release(
        outcome=LeaseReleaseOutcome.SUCCESS,
        http_status=200,
        bytes_metered=1500,
    )

    # Secondary release call on same lease must be no-op
    await lease.release(outcome=LeaseReleaseOutcome.FAILURE)

    summary = await limiter.get_audit_summary("https://audit-target.com")
    assert summary["total_requests"] == 1
    assert summary["total_bytes_metered"] == 1500
    assert summary["success"] == 1
    assert summary["failure"] == 0


# ── 11. Multi-Process Contention (Fault Injection & True Cross-Process Safety) ─

def _mp_worker(db_path: str, domain: str, worker_id: int, result_queue: multiprocessing.Queue):
    """Isolated child process worker competing for egress lease against shared SQLite."""
    async def run():
        # Each process has its own limiter instance pointing to the same SQLite DB file
        config = LimiterConfig(
            offline_mode=False,
            global_concurrency=2,
            per_domain_concurrency=1,
            min_domain_interval_seconds=0.05,
            request_timeout_seconds=5.0,
        )
        limiter = PersistentEgressLimiter(db_path, config)
        await limiter.init_db()

        try:
            lease = await limiter.acquire(domain, timeout=4.0)
            # Hold lease briefly to force race condition
            await asyncio.sleep(0.1)
            # Query active leases inside process while holding
            active_domain = await limiter.get_active_leases_count(domain)
            active_global = await limiter.get_active_leases_count()
            await lease.release(outcome=LeaseReleaseOutcome.SUCCESS)
            result_queue.put({
                "worker_id": worker_id,
                "status": "success",
                "active_domain_during_hold": active_domain,
                "active_global_during_hold": active_global,
            })
        except Exception as e:
            result_queue.put({
                "worker_id": worker_id,
                "status": "error",
                "error": str(e),
            })

    asyncio.run(run())


def test_cross_process_concurrency_race_condition(tmp_path):
    """
    Spawns 4 separate OS processes competing simultaneously for leases.
    Proves per-domain concurrency (1) and global concurrency (2) invariants hold strictly.
    """
    db_file = str(tmp_path / "mp_race.db")

    # Pre-init db schema
    async def init():
        l = PersistentEgressLimiter(db_file, LimiterConfig(offline_mode=False))
        await l.init_db()
    asyncio.run(init())

    q = multiprocessing.Queue()
    processes = []
    # 2 workers target domain-A (must serialize to max 1 concurrent)
    # 2 workers target domain-B (must serialize to max 1 concurrent)
    # Overall max concurrent globally must not exceed 2
    targets = [
        ("domain-a.com", 1),
        ("domain-a.com", 2),
        ("domain-b.com", 3),
        ("domain-b.com", 4),
    ]

    for domain, wid in targets:
        p = multiprocessing.Process(target=_mp_worker, args=(db_file, domain, wid, q))
        p.start()
        processes.append(p)

    for p in processes:
        p.join(timeout=10.0)
        assert not p.is_alive(), "Worker process hung"

    results = []
    while not q.empty():
        results.append(q.get())

    assert len(results) == 4, f"Expected 4 worker results, got {len(results)}"
    for r in results:
        assert r["status"] == "success", f"Worker failed: {r}"
        # Domain concurrency invariant: must be exactly 1 while holding
        assert r["active_domain_during_hold"] <= 1, (
            f"Domain concurrency breached: {r['active_domain_during_hold']} > 1"
        )
        # Global concurrency invariant: must be <= 2 while holding
        assert r["active_global_during_hold"] <= 2, (
            f"Global concurrency breached: {r['active_global_during_hold']} > 2"
        )


# ── 12. Cross-Process Lease & Clock Safety Invariants (W1-05-B-R Hardening) ──

@pytest.mark.asyncio
async def test_auto_renewal_prevents_double_leasing(tmp_path):
    """
    Long request (> 30s TTL) under auto-renewal MUST keep lease alive.
    Other workers MUST NOT be able to acquire a 2nd concurrent permit.
    """
    db_file = tmp_path / "auto_renew.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=1,
        per_domain_concurrency=1,
        lease_ttl_seconds=30.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    async with await limiter.acquire("https://target.com") as l1:
        assert l1.expires_at == 130.0

        # Advance clock by 35s in simulated increments
        clock.advance(20.0)
        for _ in range(50):
            if l1.expires_at >= 150.0:
                break
            await asyncio.sleep(0.01)
        assert l1.expires_at >= 150.0  # renewed!

        clock.advance(15.0)
        for _ in range(50):
            if l1.expires_at >= 165.0:
                break
            await asyncio.sleep(0.01)
        assert l1.expires_at >= 165.0  # renewed again!

        # Worker 2 attempts acquire: MUST be blocked
        with pytest.raises(ConcurrencyTimeoutError):
            await limiter.acquire("https://target.com", timeout=0.1)

        assert await limiter.get_active_leases_count("target.com") == 1


@pytest.mark.asyncio
async def test_stale_expired_lease_cannot_release_or_corrupt_state(tmp_path):
    """
    When a worker loses its lease (e.g. paused/zombie past TTL), releasing it
    MUST be rejected from corrupting or resetting the domain's newer cooldown state.
    """
    db_file = tmp_path / "stale_release.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        lease_ttl_seconds=30.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    # Worker 1 acquires manually without auto-renew
    l1 = await limiter.acquire("https://target.com")

    # Clock jumps 35s ahead -> lease expires in DB
    clock.advance(35.0)

    # Worker 2 acquires and records 429 Retry-After: 120s
    l2 = await limiter.acquire("https://target.com")
    await l2.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=120.0, http_status=429)

    st_before = await limiter.get_domain_state("target.com")
    assert st_before["consecutive_failures"] == 1
    assert st_before["cooldown_until"] == 255.0  # 135.0 + 120.0

    # Stale Worker 1 now tries to release SUCCESS
    await l1.release(outcome=LeaseReleaseOutcome.SUCCESS)

    st_after = await limiter.get_domain_state("target.com")
    # Domain failure count and cooldown MUST NOT be cleared by stale worker
    assert st_after["consecutive_failures"] == 1
    assert st_after["cooldown_until"] == st_before["cooldown_until"]


@pytest.mark.asyncio
async def test_429_long_retry_after_not_clipped(tmp_path):
    """
    A 429 Retry-After of 300s (5m) MUST NOT be clipped to max_retry_backoff_seconds (30s).
    """
    db_file = tmp_path / "long_429.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        max_retry_backoff_seconds=30.0,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    lease = await limiter.acquire("https://target.com")
    await lease.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=300.0, http_status=429)

    # At T=131.0 (31 seconds later, > 30s max backoff), cooldown MUST still be active
    clock.advance(31.0)
    acquired, wait_sugg = await limiter._try_acquire_transaction("target.com", 1, clock.now())
    assert acquired is None
    assert wait_sugg == 269.0  # Exactly 400.0 - 131.0


@pytest.mark.asyncio
async def test_cross_domain_redirect_enforces_target_concurrency(tmp_path):
    """
    Redirecting to a different domain must check and enforce the target domain's
    per_domain_concurrency limit.
    """
    db_file = tmp_path / "redirect_conc.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(
        offline_mode=False,
        global_concurrency=2,
        per_domain_concurrency=1,
    )
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    # Worker 1 holds domain-b
    l_b = await limiter.acquire("https://domain-b.com")
    # Worker 2 holds domain-a
    l_a = await limiter.acquire("https://domain-a.com")

    # Worker 2 redirects to domain-b: MUST be blocked because domain-b has concurrency=1
    with pytest.raises(ConcurrencyTimeoutError):
        await l_a.record_redirect("https://domain-b.com/target")

    await l_a.release()
    await l_b.release()


def test_sigkill_crash_recovery_os_process(tmp_path):
    """
    True OS child process killed with SIGKILL / taskkill must be promptly reclaimed
    by recover_stale_leases via PID liveness checking even before lease_ttl_seconds.
    """
    db_file = str(tmp_path / "sigkill.db")

    # Child worker function running in external process
    worker_code = f"""
import asyncio
from harvey.controlled_discovery.limiter import PersistentEgressLimiter, LimiterConfig
async def main():
    limiter = PersistentEgressLimiter(r'{db_file}', LimiterConfig(offline_mode=False, lease_ttl_seconds=300.0))
    await limiter.init_db()
    lease = await limiter.acquire('https://crash-target.com')
    print('ACQUIRED', flush=True)
    await asyncio.sleep(60.0)
asyncio.run(main())
"""
    import subprocess
    proc = subprocess.Popen(
        [sys.executable, "-c", worker_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline().strip()
    assert line == "ACQUIRED"
    dead_pid = proc.pid

    # Terminate process abruptly (SIGKILL equivalent on Windows)
    proc.kill()
    proc.wait()
    assert not is_pid_alive(dead_pid)

    # Now sweep in main process
    async def sweep():
        limiter = PersistentEgressLimiter(db_file, LimiterConfig(offline_mode=False))
        await limiter.init_db()
        reclaimed = await limiter.recover_stale_leases()
        assert reclaimed >= 1
        assert await limiter.get_active_leases_count("crash-target.com") == 0

    asyncio.run(sweep())


# ── 13. Clock Consistency & Cross-Reboot Rate Limiting Invariants (W1-05-B-R2) ──

@pytest.mark.asyncio
async def test_http_date_parsed_against_unix_epoch_wall_clock(tmp_path):
    """
    RFC HTTP-Date Retry-After MUST calculate remaining delay against wall-clock UTC,
    never directly subtracting monotonic timestamp (SystemClock.now()).
    """
    db_file = tmp_path / "http_date_clock.db"
    # Simulated monotonic clock at 500.0, wall clock at Unix Epoch 1700000000.0
    clock = FakeClock(start_time=500.0, wall_time=1700000000.0, auto_advance_on_sleep=True)
    config = LimiterConfig(offline_mode=False, min_domain_interval_seconds=0.0)
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    lease = await limiter.acquire("https://rfc-date.test")
    assert lease.acquired_at == 500.0

    # Server returns HTTP-Date 45s in future (UTC: 1700000045.0)
    import email.utils
    date_str = email.utils.formatdate(1700000045.0, usegmt=True)

    await lease.release(
        outcome=LeaseReleaseOutcome.RATE_LIMITED,
        retry_after_seconds=date_str,
        http_status=429,
    )

    state = await limiter.get_domain_state("rfc-date.test")
    # Cooldown duration must be exactly 45.0s, so monotonic cooldown_until is 545.0
    assert state["cooldown_until"] == 545.0
    assert state["consecutive_failures"] == 1

    # At T=500.0, acquire must timeout
    with pytest.raises(ConcurrencyTimeoutError):
        await limiter.acquire("https://rfc-date.test", timeout=0.1)

    # Advance clock 46s
    clock.advance(46.0)
    lease2 = await limiter.acquire("https://rfc-date.test", timeout=0.5)
    assert lease2.domain == "rfc-date.test"
    await lease2.release()


@pytest.mark.asyncio
async def test_cross_reboot_preserves_active_429_cooldown(tmp_path):
    """
    OS reboot (monotonic clock baseline change) MUST NOT prematurely clear
    a 429 cooldown that is still active in wall-clock UTC.
    """
    db_file = tmp_path / "reboot_cooldown.db"

    # Pre-reboot instance:
    # Monotonic clock: 90000.0, Wall clock: 1700000000.0, Boot ID: "boot-session-1"
    c1 = FakeClock(start_time=90000.0, wall_time=1700000000.0, boot_id="boot-session-1")
    l1 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False), clock=c1)
    await l1.init_db()

    lease = await l1.acquire("https://cooldown-target.com")
    # 429 with 120s cooldown
    await lease.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=120.0, http_status=429)

    # OS Reboots!
    # Machine was off for 30s.
    # Post-reboot instance:
    # Monotonic clock resets to 10.0! Wall clock is now 1700000030.0.
    # Active cooldown still has 90s remaining (120 - 30).
    c2 = FakeClock(start_time=10.0, wall_time=1700000030.0, boot_id="boot-session-2")
    l2 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False), clock=c2)

    # Check domain state after reboot
    state = await l2.get_domain_state("cooldown-target.com")
    # Monotonic cooldown_until must be aligned to current boot monotonic clock (10.0 + 90.0 = 100.0)
    assert state["cooldown_until"] == 100.0
    assert state["consecutive_failures"] == 1

    # Acquire must still be blocked by active cooldown!
    acquired, wait_sugg = await l2._try_acquire_transaction("cooldown-target.com", 1, c2.now())
    assert acquired is None
    assert 89.0 <= wait_sugg <= 91.0

    # Advance clock past cooldown: 91s
    c2.advance(91.0)
    lease2 = await l2.acquire("https://cooldown-target.com", timeout=1.0)
    assert lease2.domain == "cooldown-target.com"
    await lease2.release()


@pytest.mark.asyncio
async def test_cross_reboot_clears_expired_cooldown_without_deadlock(tmp_path):
    """
    If cooldown expired while machine was powered off, post-reboot acquire
    MUST NOT deadlock for hours due to old large monotonic timestamps.
    """
    db_file = tmp_path / "reboot_expired.db"

    # Pre-reboot: monotonic=500000.0 (high uptime), cooldown 60s
    c1 = FakeClock(start_time=500000.0, wall_time=1700000000.0, boot_id="boot-old")
    l1 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False), clock=c1)
    await l1.init_db()

    lease = await l1.acquire("https://expired-cooldown.com")
    await lease.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=60.0, http_status=429)

    # Machine was off for 1 hour (3600s). Cooldown completely expired!
    # Post-reboot monotonic clock is at 5.0.
    c2 = FakeClock(start_time=5.0, wall_time=1700003600.0, boot_id="boot-new")
    l2 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False), clock=c2)

    state = await l2.get_domain_state("expired-cooldown.com")
    assert state["cooldown_until"] == 0.0

    # Acquire immediately succeeds without multi-day wait!
    lease2 = await l2.acquire("https://expired-cooldown.com", timeout=0.5)
    assert lease2.domain == "expired-cooldown.com"
    await lease2.release()


@pytest.mark.asyncio
async def test_cross_reboot_cleans_up_stale_pre_reboot_leases(tmp_path):
    """
    Active leases held by workers before an OS reboot MUST be reclaimed immediately
    on post-reboot startup via boot_id mismatch, freeing concurrency slots.
    """
    db_file = tmp_path / "reboot_stale_leases.db"

    c1 = FakeClock(start_time=100.0, wall_time=1700000000.0, boot_id="boot-pre")
    l1 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False, global_concurrency=1), clock=c1)
    await l1.init_db()

    # Pre-reboot worker acquired lease with 30s TTL
    lease1 = await l1.acquire("https://reboot-slot.com")
    assert await l1.get_active_leases_count() == 1

    # Sudden reboot 5s later (TTL not yet naturally expired)
    c2 = FakeClock(start_time=5.0, wall_time=1700000005.0, boot_id="boot-post")
    l2 = PersistentEgressLimiter(str(db_file), LimiterConfig(offline_mode=False, global_concurrency=1), clock=c2)

    # Explicit recovery pass sweeps pre-reboot leases
    reclaimed = await l2.recover_stale_leases()
    assert reclaimed == 1
    assert await l2.get_active_leases_count() == 0

    # Post-reboot worker can now immediately acquire the global concurrency slot!
    lease2 = await l2.acquire("https://reboot-slot.com", timeout=0.5)
    assert lease2.domain == "reboot-slot.com"
    await lease2.release()


@pytest.mark.asyncio
async def test_lease_auto_renewal_failure_aborts_bound_request_task(tmp_path):
    """
    When background lease renewal fails (e.g. database error or reclaimed by another process),
    the bound controlled request task MUST be immediately aborted via cancellation.
    """
    db_file = tmp_path / "renew_abort.db"
    clock = FakeClock(start_time=100.0, auto_advance_on_sleep=True)
    config = LimiterConfig(offline_mode=False, lease_ttl_seconds=10.0)
    limiter = PersistentEgressLimiter(str(db_file), config, clock=clock)
    await limiter.init_db()

    lease = await limiter.acquire("https://abort-test.com")
    task_cancelled_properly = False

    async def controlled_request_worker():
        nonlocal task_cancelled_properly
        try:
            async with lease:
                # Long-running HTTP download
                await asyncio.sleep(100.0)
        except asyncio.CancelledError:
            task_cancelled_properly = True
            raise

    worker_task = asyncio.create_task(controlled_request_worker())
    await asyncio.sleep(0.01)

    # Force a renewal failure by dropping the lease from DB behind its back
    conn = await limiter._get_conn()
    await conn.execute("DELETE FROM egress_leases WHERE lease_id = ?", (lease.lease_id,))
    await conn.commit()
    await conn.close()

    # Explicitly attempt renewal or advance clock so auto-renew fires
    with pytest.raises(LeaseExpiredError):
        await lease.renew()

    # Worker task must be cancelled by the abort mechanism
    with pytest.raises(asyncio.CancelledError):
        await worker_task

    assert task_cancelled_properly is True
    assert lease._lost_ownership is True
