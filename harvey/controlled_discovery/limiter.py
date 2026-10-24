"""
harvey.controlled_discovery.limiter

Cross-process persistent egress limiter, concurrency coordinator,
and resource circuit breaker for Discovery, Profile, and Scout components.

Implements robust SQLite transactional leases and atomic token-bucket/interval tracking.
Purely local component; strictly offline by default; zero live outbound calls unlocked.
"""

from __future__ import annotations

import asyncio
import ctypes
import email.utils
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Callable,
    Dict,
    Optional,
    Protocol,
    Tuple,
    Union,
)
from urllib.parse import urlparse

import aiosqlite

logger = logging.getLogger("harvey.controlled_discovery.limiter")


def is_pid_alive(pid: int) -> bool:
    """
    Check if an OS process with the given PID is currently alive.
    Safe against zombie/stale PIDs on Windows and POSIX.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            import errno
            return e.errno == errno.EPERM


# ── Clock Protocol & Implementations ──────────────────────────────────────────

class Clock(Protocol):
    def now(self) -> float:
        """Return monotonic or wall-clock timestamp in seconds."""
        ...

    async def sleep(self, seconds: float) -> None:
        """Sleep for the given seconds."""
        ...


class SystemClock:
    """
    Monotonic system clock immune to NTP / system wall-clock backward and forward steps.
    Guarantees consistent rate intervals, lease deadlines, and monotonic cooldown calculation.
    """
    def now(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FakeClock:
    """
    Deterministic controllable clock for high-speed simulation testing.
    Can auto-advance simulated time when sleeping, preventing slow real-world pauses.
    Supports synchronous tick callbacks for auto-renew and TTL expiration simulations.
    """

    def __init__(self, start_time: float = 1000.0, auto_advance_on_sleep: bool = True):
        self._current_time = float(start_time)
        self.auto_advance_on_sleep = auto_advance_on_sleep
        self._tick_listeners: list[Callable[[float], None]] = []

    def now(self) -> float:
        return self._current_time

    def add_tick_listener(self, cb: Callable[[float], None]) -> None:
        if cb not in self._tick_listeners:
            self._tick_listeners.append(cb)

    def remove_tick_listener(self, cb: Callable[[float], None]) -> None:
        if cb in self._tick_listeners:
            self._tick_listeners.remove(cb)

    def advance(self, seconds: float) -> None:
        self._current_time += float(seconds)
        for cb in list(self._tick_listeners):
            try:
                cb(self._current_time)
            except Exception:
                pass

    async def sleep(self, seconds: float) -> None:
        if self.auto_advance_on_sleep and seconds > 0:
            self.advance(seconds)
        await asyncio.sleep(0)


# ── Outcome and Status Enums ──────────────────────────────────────────────────

class LeaseReleaseOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RATE_LIMITED = "rate_limited"  # e.g. 429 received


class LimiterAcquireStatus(str, Enum):
    GRANTED = "granted"
    REJECTED_OFFLINE = "rejected_offline"
    REJECTED_CIRCUIT_BROKEN = "rejected_circuit_broken"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# ── Exceptions ────────────────────────────────────────────────────────────────

class LimiterError(Exception):
    """Base exception for egress limiter errors."""
    pass


class LeaseExpiredError(LimiterError):
    """Raised when an active lease has expired, failed renewal, or lost ownership."""
    pass


class OfflineEgressBlockedError(LimiterError):
    """Raised when an acquisition is attempted while offline mode is active."""
    pass


class ConcurrencyTimeoutError(LimiterError):
    """Raised when lease acquisition times out waiting for capacity."""
    pass


class MaxRetriesExceededError(LimiterError):
    """Raised when request attempt exceeds configured maximum retries."""
    def __init__(self, attempt: int, max_retries: int):
        super().__init__(f"Attempt count {attempt} exceeds max retries {max_retries}")
        self.attempt = attempt
        self.max_retries = max_retries


class ResponseSizeLimitExceededError(LimiterError):
    """Raised when response body streaming exceeds the configured byte cap."""
    def __init__(self, bytes_read: int, max_bytes: int):
        super().__init__(f"Response size exceeded limit: {bytes_read} > {max_bytes} bytes")
        self.bytes_read = bytes_read
        self.max_bytes = max_bytes


class RedirectLimitExceededError(LimiterError):
    """Raised when redirect count exceeds configured maximum."""
    def __init__(self, redirects: int, max_redirects: int):
        super().__init__(f"Redirect limit exceeded: {redirects} > {max_redirects}")
        self.redirects = redirects
        self.max_redirects = max_redirects


# ── Configuration Contract ───────────────────────────────────────────────────

@dataclass(frozen=True)
class LimiterConfig:
    # Concurrency
    global_concurrency: int = 1
    per_domain_concurrency: int = 1

    # Rate pacing
    min_domain_interval_seconds: float = 2.0

    # Timeouts and limits
    request_timeout_seconds: float = 15.0
    max_redirects: int = 3
    max_response_bytes: int = 2 * 1024 * 1024  # 2 MiB

    # Retries and backoff
    max_retries: int = 3
    base_retry_backoff_seconds: float = 1.0
    max_retry_backoff_seconds: float = 30.0

    # Lease recovery
    lease_ttl_seconds: float = 30.0

    # Safety lock
    offline_mode: bool = True


# ── Response Meter Contract ───────────────────────────────────────────────────

class ResponseBodyMeter:
    """
    Reusable metering contract for response streaming chunks.
    Enforces max_response_bytes incrementally without buffering unbounded payloads.
    """

    def __init__(self, max_bytes: int):
        self.max_bytes = int(max_bytes)
        self.bytes_metered = 0

    def update(self, chunk_or_len: Union[bytes, bytearray, memoryview, int]) -> int:
        """
        Increment byte meter with a chunk or length.
        Raises ResponseSizeLimitExceededError immediately if limit is exceeded.
        """
        if isinstance(chunk_or_len, int):
            chunk_len = chunk_or_len
        else:
            chunk_len = len(chunk_or_len)

        if chunk_len < 0:
            raise ValueError("Chunk length cannot be negative")

        self.bytes_metered += chunk_len
        if self.bytes_metered > self.max_bytes:
            raise ResponseSizeLimitExceededError(self.bytes_metered, self.max_bytes)
        return self.bytes_metered

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.max_bytes - self.bytes_metered)

    @property
    def is_exceeded(self) -> bool:
        return self.bytes_metered > self.max_bytes

    def reset(self) -> None:
        self.bytes_metered = 0

    async def meter_stream(self, stream: AsyncIterable[bytes]) -> AsyncIterator[bytes]:
        """Wraps an asynchronous byte stream, metering chunks on the fly."""
        async for chunk in stream:
            self.update(chunk)
            yield chunk


# ── Utility Functions ─────────────────────────────────────────────────────────

def normalize_domain(url_or_domain: str) -> str:
    """Extract normalized lowercase host from URL or bare domain string."""
    s = (url_or_domain or "").strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = f"http://{s}"
    try:
        parsed = urlparse(s)
        host = parsed.hostname or parsed.netloc or ""
        return host.split(":")[0].strip().lower()
    except Exception:
        return url_or_domain.strip().lower()


def parse_retry_after(value: Union[str, int, float, None], now: Optional[float] = None) -> Optional[float]:
    """
    Parse HTTP Retry-After header value into seconds delay.
    Supports integer seconds ('120') or RFC-2822 / RFC-1123 HTTP dates.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return max(0.0, float(value))

    val_str = str(value).strip()
    if not val_str:
        return None

    # Try numeric seconds
    try:
        return max(0.0, float(val_str))
    except ValueError:
        pass

    # Try HTTP date format
    try:
        dt = email.utils.parsedate_to_datetime(val_str)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            target_ts = dt.timestamp()
            ref_now = now if now is not None else time.time()
            return max(0.0, target_ts - ref_now)
    except Exception:
        pass

    return None


# ── Request Lease ─────────────────────────────────────────────────────────────

@dataclass
class RequestLease:
    lease_id: str
    domain: str
    attempt: int
    redirects_used: int
    acquired_at: float
    limiter: "PersistentEgressLimiter" = field(repr=False)
    bytes_metered: int = 0
    expires_at: float = 0.0
    _released: bool = field(default=False, repr=False)
    _renewal_task: Optional[asyncio.Task] = field(default=None, repr=False)
    _renewal_active: bool = field(default=False, repr=False)
    _lost_ownership: bool = field(default=False, repr=False)
    _bound_task: Optional[asyncio.Task] = field(default=None, repr=False)
    _tick_listener: Optional[Callable[[float], None]] = field(default=None, repr=False)

    async def release(
        self,
        outcome: LeaseReleaseOutcome = LeaseReleaseOutcome.SUCCESS,
        retry_after_seconds: Optional[Union[float, int, str]] = None,
        http_status: Optional[int] = None,
        bytes_metered: Optional[int] = None,
    ) -> None:
        """
        Release the active lease and record domain rate limit / backoff / audit stats.
        Idempotent: safe to call multiple times without state corruption.
        Guarantees only the legitimate current owner can update domain status or release.
        """
        self.stop_auto_renewal()
        if self._released:
            return
        self._released = True

        if bytes_metered is not None:
            self.bytes_metered = bytes_metered

        parsed_retry_after = parse_retry_after(retry_after_seconds, now=self.limiter.clock.now())

        await self.limiter._release_lease(
            lease_id=self.lease_id,
            domain=self.domain,
            attempt=self.attempt,
            redirects_used=self.redirects_used,
            acquired_at=self.acquired_at,
            bytes_metered=self.bytes_metered,
            outcome=outcome,
            retry_after_seconds=parsed_retry_after,
            http_status=http_status,
        )

    async def record_redirect(self, target_url_or_domain: Optional[str] = None) -> int:
        """
        Record a redirect step against this lease and enforce the maximum redirects cap.
        If a new domain is targeted, validates domain transition within redirect bounds.
        """
        self.assert_valid()
        self.redirects_used += 1
        if self.redirects_used > self.limiter.config.max_redirects:
            raise RedirectLimitExceededError(self.redirects_used, self.limiter.config.max_redirects)

        if target_url_or_domain:
            target_dom = normalize_domain(target_url_or_domain)
            if target_dom and target_dom != self.domain:
                # Update lease domain tracking in database
                await self.limiter._transfer_lease_domain(self.lease_id, self.domain, target_dom)
                self.domain = target_dom

        return self.redirects_used

    async def renew(self, extra_ttl_seconds: Optional[float] = None) -> float:
        """Extend lease expiration time to protect long active streaming transfers."""
        if self._lost_ownership:
            raise LeaseExpiredError(f"Lease {self.lease_id} has already lost ownership")
        if self._released:
            raise LimiterError("Cannot renew an already released lease")
        ttl = extra_ttl_seconds if extra_ttl_seconds is not None else self.limiter.config.lease_ttl_seconds
        try:
            new_expires = await self.limiter._renew_lease(self.lease_id, ttl)
            self.expires_at = new_expires
            return new_expires
        except Exception as e:
            self._lost_ownership = True
            self._abort_bound_task(f"Lease renewal failed: {e}")
            raise LeaseExpiredError(f"Lease renewal failed: {e}") from e

    def assert_valid(self) -> None:
        """Fail-closed assertion: verify this lease has not expired or lost ownership."""
        if self._lost_ownership:
            raise LeaseExpiredError(f"Lease {self.lease_id} has lost ownership or failed renewal")
        if self._released:
            raise LimiterError(f"Lease {self.lease_id} has already been released")
        if self.expires_at > 0 and self.limiter.clock.now() >= self.expires_at:
            self._lost_ownership = True
            self._abort_bound_task(f"Lease {self.lease_id} exceeded TTL without renewal")
            raise LeaseExpiredError(f"Lease {self.lease_id} has expired (now >= expires_at)")

    def start_auto_renewal(self, bound_task: Optional[asyncio.Task] = None) -> None:
        """
        Start background auto-renewal loop to keep lease alive during long operations.
        If renewal fails or lease expires, immediately aborts the bound task.
        """
        if self._renewal_active or self._released:
            return
        self._renewal_active = True
        self._bound_task = bound_task
        clock = self.limiter.clock
        if hasattr(clock, "add_tick_listener"):
            # For FakeClock deterministic simulation: register tick listener
            def _on_tick(current_now: float) -> None:
                if self._renewal_active and not self._released and not self._lost_ownership:
                    if current_now >= self.expires_at - (self.limiter.config.lease_ttl_seconds * 0.5):
                        asyncio.create_task(self._safe_renew())

            self._tick_listener = _on_tick
            clock.add_tick_listener(_on_tick)
        else:
            interval = max(0.5, self.limiter.config.lease_ttl_seconds / 3.0)

            async def _renewal_loop():
                while self._renewal_active and not self._released and not self._lost_ownership:
                    try:
                        await self.limiter.clock.sleep(interval)
                    except asyncio.CancelledError:
                        break
                    except Exception:
                        pass

                    if not self._renewal_active or self._released:
                        break

                    try:
                        new_exp = await self.renew()
                        self.expires_at = new_exp
                    except Exception as exc:
                        logger.warning("Background renewal failed for lease %s: %s", self.lease_id, exc)
                        self._lost_ownership = True
                        self._abort_bound_task(f"Background renewal failed: {exc}")
                        break

            self._renewal_task = asyncio.create_task(_renewal_loop())

    async def _safe_renew(self) -> None:
        try:
            if self._renewal_active and not self._released and not self._lost_ownership:
                new_exp = await self.renew()
                self.expires_at = new_exp
        except Exception:
            pass

    def stop_auto_renewal(self) -> None:
        """Stop the background auto-renewal loop cleanly."""
        self._renewal_active = False
        if self._renewal_task and not self._renewal_task.done():
            self._renewal_task.cancel()
            self._renewal_task = None
        if self._tick_listener:
            clock = self.limiter.clock
            if hasattr(clock, "remove_tick_listener"):
                clock.remove_tick_listener(self._tick_listener)
            self._tick_listener = None

    def _abort_bound_task(self, reason: str) -> None:
        """Abort bound controlled request task when lease safety is compromised."""
        if self._bound_task and not self._bound_task.done():
            logger.error("Aborting controlled request task due to lost lease safety: %s", reason)
            self._bound_task.cancel()

    def new_meter(self) -> ResponseBodyMeter:
        """Instantiate a response body meter bound to the limiter's size cap."""
        meter = ResponseBodyMeter(self.limiter.config.max_response_bytes)
        return meter

    async def __aenter__(self) -> "RequestLease":
        current_task = asyncio.current_task()
        self.start_auto_renewal(bound_task=current_task)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop_auto_renewal()
        if not self._released:
            if exc_type is None:
                await self.release(LeaseReleaseOutcome.SUCCESS)
            elif issubclass(exc_type, asyncio.CancelledError):
                await self.release(LeaseReleaseOutcome.CANCELLED)
            elif issubclass(exc_type, (asyncio.TimeoutError, ConcurrencyTimeoutError)):
                await self.release(LeaseReleaseOutcome.TIMEOUT)
            elif issubclass(exc_type, LeaseExpiredError):
                await self.release(LeaseReleaseOutcome.FAILURE)
            else:
                await self.release(LeaseReleaseOutcome.FAILURE)


# ── SQLite Schema ─────────────────────────────────────────────────────────────

LIMITER_SCHEMA = """
CREATE TABLE IF NOT EXISTS egress_leases (
    lease_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    worker_pid INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    acquired_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_egress_leases_domain ON egress_leases(domain);
CREATE INDEX IF NOT EXISTS idx_egress_leases_expires ON egress_leases(expires_at);

CREATE TABLE IF NOT EXISTS egress_domain_state (
    domain TEXT PRIMARY KEY,
    last_request_at REAL NOT NULL DEFAULT 0.0,
    cooldown_until REAL NOT NULL DEFAULT 0.0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS egress_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lease_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    worker_pid INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    redirects INTEGER NOT NULL,
    bytes_metered INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,
    http_status INTEGER,
    duration_seconds REAL NOT NULL,
    recorded_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_egress_audit_domain ON egress_audit_log(domain);
CREATE INDEX IF NOT EXISTS idx_egress_audit_recorded ON egress_audit_log(recorded_at);
"""


# ── Persistent Egress Limiter ─────────────────────────────────────────────────

class PersistentEgressLimiter:
    """
    Cross-process, SQLite-backed egress limiter and circuit breaker.
    Provides ACID concurrency management, domain-level rate pacing,
    stale lease recovery, retry backoff, and 429 handling.
    """

    def __init__(
        self,
        db_path: str,
        config: Optional[LimiterConfig] = None,
        clock: Optional[Clock] = None,
    ):
        self.db_path = str(db_path)
        self.config = config or LimiterConfig()
        self.clock = clock or SystemClock()
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def init_db(self) -> None:
        """Initialize schema and ensure WAL mode."""
        async with self._init_lock:
            if self._initialized:
                return
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            async with aiosqlite.connect(self.db_path, timeout=30.0) as db:
                await db.execute("PRAGMA journal_mode=WAL;")
                await db.execute("PRAGMA synchronous=NORMAL;")
                await db.execute("PRAGMA busy_timeout=10000;")
                await db.executescript(LIMITER_SCHEMA)
                await db.commit()
            self._initialized = True

    async def _get_conn(self) -> aiosqlite.Connection:
        if not self._initialized:
            await self.init_db()
        conn = await aiosqlite.connect(self.db_path, timeout=30.0)
        await conn.execute("PRAGMA busy_timeout=10000;")
        return conn

    async def acquire(
        self,
        url_or_domain: str,
        attempt: int = 1,
        timeout: Optional[float] = None,
    ) -> RequestLease:
        """
        Acquire a request lease for the target URL or domain.

        Enforces:
        1. Offline mode fail-closed check.
        2. Max retry count limit.
        3. Domain pacing (min_domain_interval_seconds) & cooldown (429 / backoff).
        4. Global and per-domain active lease concurrency limits.
        5. Automatic expiration and recovery of crashed worker leases.
        """
        if self.config.offline_mode:
            raise OfflineEgressBlockedError(
                "Egress requests are blocked in offline mode. Live network acquisition forbidden."
            )

        if attempt > self.config.max_retries:
            raise MaxRetriesExceededError(attempt, self.config.max_retries)

        domain = normalize_domain(url_or_domain)
        if not domain:
            raise ValueError(f"Invalid target URL or domain: {url_or_domain}")

        max_wait = timeout if timeout is not None else self.config.request_timeout_seconds
        start_wait = self.clock.now()
        deadline = start_wait + max_wait

        poll_interval = 0.05

        while True:
            now = self.clock.now()

            # Clock jump backward defense: reset start_wait if clock moved backward
            if now < start_wait:
                start_wait = now
                deadline = start_wait + max_wait

            if now >= deadline:
                raise ConcurrencyTimeoutError(
                    f"Timed out after {max_wait:.2f}s acquiring egress lease for {domain}"
                )

            acquired, wait_suggestion = await self._try_acquire_transaction(domain, attempt, now)
            if acquired:
                return acquired

            # Calculate time to sleep
            now = self.clock.now()
            remaining = deadline - now
            if remaining <= 0:
                raise ConcurrencyTimeoutError(
                    f"Timed out after {max_wait:.2f}s acquiring egress lease for {domain}"
                )

            sleep_time = min(poll_interval, remaining)
            if wait_suggestion and wait_suggestion > 0:
                sleep_time = min(sleep_time, wait_suggestion)
                sleep_time = max(0.01, sleep_time)

            await self.clock.sleep(sleep_time)

    async def _try_acquire_transaction(
        self,
        domain: str,
        attempt: int,
        now: float,
    ) -> Tuple[Optional[RequestLease], Optional[float]]:
        """
        Atomic transaction to test conditions and claim lease.
        Returns (lease, wait_suggestion_seconds).
        """
        conn = await self._get_conn()
        try:
            # Use BEGIN IMMEDIATE to ensure exclusive write lock from start
            await conn.execute("BEGIN IMMEDIATE;")

            # Step 1: Clean up expired leases
            cursor = await conn.execute(
                "SELECT lease_id, worker_pid, expires_at FROM egress_leases WHERE expires_at < ?",
                (now,),
            )
            expired_rows = await cursor.fetchall()
            await cursor.close()

            if expired_rows:
                expired_ids = [r[0] for r in expired_rows]
                placeholders = ",".join("?" for _ in expired_ids)
                await conn.execute(
                    f"DELETE FROM egress_leases WHERE lease_id IN ({placeholders})",
                    expired_ids,
                )

            await conn.execute(
                "DELETE FROM egress_leases WHERE expires_at < ?",
                (now,),
            )

            # Step 2: Check domain pacing and cooldown
            cursor = await conn.execute(
                "SELECT last_request_at, cooldown_until FROM egress_domain_state WHERE domain = ?",
                (domain,),
            )
            row = await cursor.fetchone()
            await cursor.close()

            if row:
                last_request_at, cooldown_until = row

                # Clock skew defense
                if last_request_at > now:
                    last_request_at = now

                # Check active cooldown (e.g. 429 Retry-After or failure backoff)
                if now < cooldown_until:
                    await conn.commit()
                    return None, cooldown_until - now

                # Check min interval pacing
                elapsed = now - last_request_at
                if elapsed < self.config.min_domain_interval_seconds:
                    needed_wait = self.config.min_domain_interval_seconds - elapsed
                    await conn.commit()
                    return None, needed_wait

            # Step 3: Check global concurrency
            cursor = await conn.execute("SELECT COUNT(*) FROM egress_leases")
            global_active = (await cursor.fetchone())[0]
            await cursor.close()

            if global_active >= self.config.global_concurrency:
                await conn.commit()
                return None, None

            # Step 4: Check per-domain concurrency
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM egress_leases WHERE domain = ?",
                (domain,),
            )
            domain_active = (await cursor.fetchone())[0]
            await cursor.close()

            if domain_active >= self.config.per_domain_concurrency:
                await conn.commit()
                return None, None

            # Step 5: Capacity available! Create lease
            lease_id = str(uuid.uuid4())
            pid = os.getpid()
            expires_at = now + self.config.lease_ttl_seconds

            await conn.execute(
                """
                INSERT INTO egress_leases (lease_id, domain, worker_pid, attempt, acquired_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (lease_id, domain, pid, attempt, now, expires_at),
            )

            # Update last_request_at to current time immediately upon grant
            await conn.execute(
                """
                INSERT INTO egress_domain_state (domain, last_request_at, cooldown_until, consecutive_failures)
                VALUES (?, ?, 0.0, 0)
                ON CONFLICT(domain) DO UPDATE SET
                    last_request_at = excluded.last_request_at
                """,
                (domain, now),
            )

            await conn.commit()

            lease = RequestLease(
                lease_id=lease_id,
                domain=domain,
                attempt=attempt,
                redirects_used=0,
                acquired_at=now,
                limiter=self,
                expires_at=expires_at,
            )
            return lease, None

        except aiosqlite.OperationalError:
            # DB locked by another concurrent transaction, wait and retry
            try:
                await conn.rollback()
            except Exception:
                pass
            return None, 0.05
        except Exception:
            try:
                await conn.rollback()
            except Exception:
                pass
            raise
        finally:
            await conn.close()

    async def _release_lease(
        self,
        lease_id: str,
        domain: str,
        attempt: int,
        redirects_used: int,
        acquired_at: float,
        bytes_metered: int,
        outcome: LeaseReleaseOutcome,
        retry_after_seconds: Optional[float] = None,
        http_status: Optional[int] = None,
    ) -> None:
        """Atomic release of lease, domain state update, and audit log settlement."""
        now = self.clock.now()
        duration = max(0.0, now - acquired_at)
        conn = await self._get_conn()
        try:
            await conn.execute("BEGIN IMMEDIATE;")

            # Ownership verification: ensure this lease actually exists and belongs to us
            cursor = await conn.execute(
                "SELECT domain, expires_at FROM egress_leases WHERE lease_id = ?",
                (lease_id,),
            )
            lease_row = await cursor.fetchone()
            await cursor.close()

            is_valid_owner = lease_row is not None

            # 1. Delete lease
            await conn.execute(
                "DELETE FROM egress_leases WHERE lease_id = ?",
                (lease_id,),
            )

            # If this lease expired or was already reclaimed, do NOT overwrite domain state!
            if not is_valid_owner:
                await conn.commit()
                return

            # 2. Update domain state
            cursor = await conn.execute(
                "SELECT consecutive_failures FROM egress_domain_state WHERE domain = ?",
                (domain,),
            )
            row = await cursor.fetchone()
            await cursor.close()

            failures = row[0] if row else 0
            cooldown_until = 0.0

            if outcome == LeaseReleaseOutcome.SUCCESS:
                failures = 0
            elif outcome == LeaseReleaseOutcome.RATE_LIMITED or http_status == 429:
                failures += 1
                if retry_after_seconds is not None and retry_after_seconds > 0:
                    # Preserve full 429 Retry-After window (do not clip to max_retry_backoff_seconds)
                    cooldown_duration = retry_after_seconds
                else:
                    cooldown_duration = min(
                        self.config.base_retry_backoff_seconds * (2 ** failures),
                        self.config.max_retry_backoff_seconds,
                    )
                cooldown_until = now + cooldown_duration
            elif outcome in (LeaseReleaseOutcome.FAILURE, LeaseReleaseOutcome.TIMEOUT):
                failures += 1
                cooldown_duration = min(
                    self.config.base_retry_backoff_seconds * (2 ** (failures - 1)),
                    self.config.max_retry_backoff_seconds,
                )
                cooldown_until = now + cooldown_duration

            await conn.execute(
                """
                INSERT INTO egress_domain_state (domain, last_request_at, cooldown_until, consecutive_failures)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_request_at = excluded.last_request_at,
                    cooldown_until = MAX(egress_domain_state.cooldown_until, excluded.cooldown_until),
                    consecutive_failures = excluded.consecutive_failures
                """,
                (domain, now, cooldown_until, failures),
            )

            # 3. Insert audit log record for idempotent settlement tracking
            await conn.execute(
                """
                INSERT INTO egress_audit_log (
                    lease_id, domain, worker_pid, attempt, redirects,
                    bytes_metered, outcome, http_status, duration_seconds, recorded_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease_id, domain, os.getpid(), attempt, redirects_used,
                    bytes_metered, outcome.value, http_status, duration, now,
                ),
            )

            await conn.commit()
        except Exception:
            try:
                await conn.rollback()
            except Exception:
                pass
            raise
        finally:
            await conn.close()

    async def _renew_lease(self, lease_id: str, extra_ttl_seconds: float) -> float:
        """Renew an active lease by setting expires_at = now + extra_ttl_seconds."""
        now = self.clock.now()
        new_expires = now + extra_ttl_seconds
        conn = await self._get_conn()
        try:
            await conn.execute("BEGIN IMMEDIATE;")
            cursor = await conn.execute(
                "UPDATE egress_leases SET expires_at = ? WHERE lease_id = ? AND expires_at >= ?",
                (new_expires, lease_id, now),
            )
            updated = cursor.rowcount
            await cursor.close()
            await conn.commit()
            if updated == 0:
                raise LimiterError(f"Lease {lease_id} could not be renewed (expired or not found)")
            return new_expires
        finally:
            await conn.close()

    async def _transfer_lease_domain(self, lease_id: str, old_domain: str, new_domain: str) -> None:
        """Update lease domain in database when following a cross-domain redirect."""
        now = self.clock.now()
        conn = await self._get_conn()
        try:
            await conn.execute("BEGIN IMMEDIATE;")

            # Verify lease is still valid and unexpired
            cursor = await conn.execute(
                "SELECT domain, expires_at FROM egress_leases WHERE lease_id = ? AND expires_at >= ?",
                (lease_id, now),
            )
            lease_row = await cursor.fetchone()
            await cursor.close()
            if not lease_row:
                await conn.commit()
                raise LeaseExpiredError(f"Lease {lease_id} expired before redirect transfer")

            # Enforce per_domain_concurrency limit on new target domain
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM egress_leases WHERE domain = ? AND expires_at >= ?",
                (new_domain, now),
            )
            target_active = (await cursor.fetchone())[0]
            await cursor.close()
            if target_active >= self.config.per_domain_concurrency:
                await conn.commit()
                raise ConcurrencyTimeoutError(
                    f"Cannot redirect to {new_domain}: target domain concurrency limit ({self.config.per_domain_concurrency}) reached"
                )

            await conn.execute(
                "UPDATE egress_leases SET domain = ? WHERE lease_id = ?",
                (new_domain, lease_id),
            )
            await conn.commit()
        finally:
            await conn.close()

    async def get_active_leases_count(self, domain: Optional[str] = None) -> int:
        """Return count of unexpired active leases globally or for a specific domain."""
        now = self.clock.now()
        conn = await self._get_conn()
        try:
            if domain:
                norm_domain = normalize_domain(domain)
                cursor = await conn.execute(
                    "SELECT COUNT(*) FROM egress_leases WHERE domain = ? AND expires_at >= ?",
                    (norm_domain, now),
                )
            else:
                cursor = await conn.execute(
                    "SELECT COUNT(*) FROM egress_leases WHERE expires_at >= ?",
                    (now,),
                )
            count = (await cursor.fetchone())[0]
            await cursor.close()
            return count
        finally:
            await conn.close()

    async def get_domain_state(self, url_or_domain: str) -> Dict[str, Any]:
        """Get current rate limit status and failure count for a domain."""
        domain = normalize_domain(url_or_domain)
        conn = await self._get_conn()
        try:
            cursor = await conn.execute(
                "SELECT last_request_at, cooldown_until, consecutive_failures FROM egress_domain_state WHERE domain = ?",
                (domain,),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if not row:
                return {
                    "domain": domain,
                    "last_request_at": 0.0,
                    "cooldown_until": 0.0,
                    "consecutive_failures": 0,
                }
            return {
                "domain": domain,
                "last_request_at": row[0],
                "cooldown_until": row[1],
                "consecutive_failures": row[2],
            }
        finally:
            await conn.close()

    async def recover_stale_leases(self) -> int:
        """Explicit recovery pass: delete expired leases, freeing capacity for surviving workers."""
        now = self.clock.now()
        conn = await self._get_conn()
        try:
            await conn.execute("BEGIN IMMEDIATE;")

            # Sweep expired leases
            cursor = await conn.execute(
                "DELETE FROM egress_leases WHERE expires_at < ?",
                (now,),
            )
            deleted = cursor.rowcount
            await cursor.close()

            # Sweep dead worker PIDs (SIGKILL crash recovery)
            cursor = await conn.execute("SELECT lease_id, worker_pid FROM egress_leases")
            active_rows = await cursor.fetchall()
            await cursor.close()

            dead_ids = [lid for lid, pid in active_rows if not is_pid_alive(pid)]
            if dead_ids:
                placeholders = ",".join("?" for _ in dead_ids)
                cursor = await conn.execute(
                    f"DELETE FROM egress_leases WHERE lease_id IN ({placeholders})",
                    dead_ids,
                )
                deleted += cursor.rowcount
                await cursor.close()

            await conn.commit()
            return deleted
        finally:
            await conn.close()

    def calculate_backoff(self, attempt: int) -> float:
        """Calculate deterministic exponential backoff seconds for a retry attempt."""
        if attempt <= 1:
            return 0.0
        delay = self.config.base_retry_backoff_seconds * (2 ** (attempt - 2))
        return min(delay, self.config.max_retry_backoff_seconds)

    async def get_audit_summary(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Aggregate auditable metrics for requests settled through the limiter."""
        conn = await self._get_conn()
        try:
            if domain:
                norm_domain = normalize_domain(domain)
                cursor = await conn.execute(
                    """
                    SELECT COUNT(*), COALESCE(SUM(bytes_metered), 0),
                           SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'rate_limited' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'failure' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'timeout' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'cancelled' THEN 1 ELSE 0 END)
                    FROM egress_audit_log WHERE domain = ?
                    """,
                    (norm_domain,),
                )
            else:
                cursor = await conn.execute(
                    """
                    SELECT COUNT(*), COALESCE(SUM(bytes_metered), 0),
                           SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'rate_limited' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'failure' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'timeout' THEN 1 ELSE 0 END),
                           SUM(CASE WHEN outcome = 'cancelled' THEN 1 ELSE 0 END)
                    FROM egress_audit_log
                    """
                )
            row = await cursor.fetchone()
            await cursor.close()

            total, total_bytes, success, rate_limited, failure, timeout, cancelled = row
            return {
                "total_requests": total or 0,
                "total_bytes_metered": total_bytes or 0,
                "success": success or 0,
                "rate_limited": rate_limited or 0,
                "failure": failure or 0,
                "timeout": timeout or 0,
                "cancelled": cancelled or 0,
            }
        finally:
            await conn.close()
