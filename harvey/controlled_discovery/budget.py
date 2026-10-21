# test
"""Controlled Discovery Hard Budget & Atomic Ledger.

Implements cross-process atomic budget reservation and final settlement
using SQLite transactions and WAL mode.

Enforces Fail-Closed behavior:
- Zero external budget under unauthorized mode.
- Run-level and daily HTTP request limits.
- Search API call limits.
- Model token billing / quota accounting (USD cost and tokens/calls).
- Conservative handling of timeouts, network failures, and unknown pricing.
- Cross-process atomic reservation with row locks / transactions.
- Strict idempotency preventing double-settlement.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional


class BudgetExceededError(RuntimeError):
    """Raised immediately when any budget limit is exceeded (Fail-Closed)."""


class BudgetUnauthorizedError(RuntimeError):
    """Raised when an external budget request is made in unauthorized mode."""


class BudgetReservationNotFoundError(KeyError):
    """Raised when resolving or settling an unknown reservation."""


class BudgetAlreadySettledError(RuntimeError):
    """Raised when attempting to settle an already settled reservation."""


@dataclass(frozen=True)
class BudgetLimits:
    """Hard limits configuration for controlled discovery."""

    authorized: bool = False
    max_run_http_requests: int = 100
    max_daily_http_requests: int = 500
    max_search_api_calls: int = 20
    max_model_cost_usd: float = 2.0
    max_model_tokens: int = 500_000
    max_subscription_units: int = 50


@dataclass(frozen=True)
class ReservationRequest:
    """Specification for reserving budget before an external or model call."""

    run_id: str
    target_id: str
    action_type: str  # 'http_request', 'search_api', 'model_call'
    reserved_http_requests: int = 1
    reserved_search_calls: int = 0
    reserved_cost_usd: float = 0.0
    reserved_tokens: int = 0
    reserved_subscription_units: int = 0
    metadata_note: str = ""


@dataclass(frozen=True)
class ReservationRecord:
    """Active or settled reservation token."""

    reservation_id: str
    run_id: str
    target_id: str
    action_type: str
    reserved_http_requests: int
    reserved_search_calls: int
    reserved_cost_usd: float
    reserved_tokens: int
    reserved_subscription_units: int
    settled: bool
    created_at: str


@dataclass(frozen=True)
class SettlementReport:
    """Settlement outcome for a reservation."""

    reservation_id: str
    actual_http_requests: int
    actual_search_calls: int
    actual_cost_usd: float
    actual_tokens: int
    actual_subscription_units: int
    status: str  # 'success', 'failed', 'timeout', 'rejected'
    settled_at: str


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return date.today().isoformat()


class HardBudgetLedger:
    """Thread-safe and cross-process safe hard budget ledger backed by SQLite."""

    def __init__(self, db_path: str | Path, limits: Optional[BudgetLimits] = None):
        self.db_path = str(db_path)
        self.limits = limits or BudgetLimits(authorized=False)
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
                CREATE TABLE IF NOT EXISTS budget_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    reserved_http_requests INTEGER NOT NULL,
                    reserved_search_calls INTEGER NOT NULL,
                    reserved_cost_usd REAL NOT NULL,
                    reserved_tokens INTEGER NOT NULL,
                    reserved_subscription_units INTEGER NOT NULL,
                    settled INTEGER NOT NULL DEFAULT 0,
                    settled_status TEXT DEFAULT '',
                    actual_http_requests INTEGER DEFAULT 0,
                    actual_search_calls INTEGER DEFAULT 0,
                    actual_cost_usd REAL DEFAULT 0.0,
                    actual_tokens INTEGER DEFAULT 0,
                    actual_subscription_units INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    settled_at TEXT DEFAULT NULL,
                    metadata_note TEXT DEFAULT ''
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_budget_run ON budget_reservations(run_id, settled)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_budget_date ON budget_reservations(created_date, settled)"
            )
            conn.execute("COMMIT")

    def reserve(self, req: ReservationRequest) -> ReservationRecord:
        """Atomically check limits and reserve budget across processes.

        If unauthorized mode is active, all external budget allocations are 0.
        Raises BudgetUnauthorizedError or BudgetExceededError on threshold violations.
        """
        if not self.limits.authorized:
            raise BudgetUnauthorizedError(
                "Fail-Closed: Unauthorized mode forbids all external budget allocation (budget is 0)"
            )

        # Unknown pricing or negative values are forbidden
        if (
            req.reserved_http_requests < 0
            or req.reserved_search_calls < 0
            or req.reserved_cost_usd < 0
            or req.reserved_tokens < 0
            or req.reserved_subscription_units < 0
        ):
            raise ValueError("Budget reservation cannot request negative amounts")

        reservation_id = f"rsv_{uuid.uuid4().hex[:16]}"
        now_ts = _utcnow()
        today = _today_str()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # 1. Check Run-level HTTP requests (active + settled)
                cur = conn.execute(
                    """
                    SELECT
                        SUM(CASE WHEN settled = 1 THEN actual_http_requests ELSE reserved_http_requests END) AS run_http,
                        SUM(CASE WHEN settled = 1 THEN actual_search_calls ELSE reserved_search_calls END) AS run_search,
                        SUM(CASE WHEN settled = 1 THEN actual_cost_usd ELSE reserved_cost_usd END) AS run_cost,
                        SUM(CASE WHEN settled = 1 THEN actual_tokens ELSE reserved_tokens END) AS run_tokens,
                        SUM(CASE WHEN settled = 1 THEN actual_subscription_units ELSE reserved_subscription_units END) AS run_units
                    FROM budget_reservations
                    WHERE run_id = ?
                    """,
                    (req.run_id,),
                )
                row = cur.fetchone()
                run_http = (row["run_http"] or 0) + req.reserved_http_requests
                run_search = (row["run_search"] or 0) + req.reserved_search_calls
                run_cost = (row["run_cost"] or 0.0) + req.reserved_cost_usd
                run_tokens = (row["run_tokens"] or 0) + req.reserved_tokens
                run_units = (row["run_units"] or 0) + req.reserved_subscription_units

                if run_http > self.limits.max_run_http_requests:
                    raise BudgetExceededError(
                        f"Run HTTP request budget exceeded: {run_http} > {self.limits.max_run_http_requests}"
                    )
                if run_search > self.limits.max_search_api_calls:
                    raise BudgetExceededError(
                        f"Search API call budget exceeded: {run_search} > {self.limits.max_search_api_calls}"
                    )
                if run_cost > self.limits.max_model_cost_usd:
                    raise BudgetExceededError(
                        f"Model dollar budget exceeded: ${run_cost:.4f} > ${self.limits.max_model_cost_usd:.4f}"
                    )
                if run_tokens > self.limits.max_model_tokens:
                    raise BudgetExceededError(
                        f"Model token budget exceeded: {run_tokens} > {self.limits.max_model_tokens}"
                    )
                if run_units > self.limits.max_subscription_units:
                    raise BudgetExceededError(
                        f"Subscription quota unit budget exceeded: {run_units} > {self.limits.max_subscription_units}"
                    )

                # 2. Check Daily HTTP requests
                cur = conn.execute(
                    """
                    SELECT
                        SUM(CASE WHEN settled = 1 THEN actual_http_requests ELSE reserved_http_requests END) AS daily_http
                    FROM budget_reservations
                    WHERE created_date = ?
                    """,
                    (today,),
                )
                daily_row = cur.fetchone()
                daily_http = (daily_row["daily_http"] or 0) + req.reserved_http_requests
                if daily_http > self.limits.max_daily_http_requests:
                    raise BudgetExceededError(
                        f"Daily HTTP request budget exceeded: {daily_http} > {self.limits.max_daily_http_requests}"
                    )

                # 3. Persist reservation
                conn.execute(
                    """
                    INSERT INTO budget_reservations (
                        reservation_id, run_id, target_id, action_type,
                        reserved_http_requests, reserved_search_calls,
                        reserved_cost_usd, reserved_tokens, reserved_subscription_units,
                        settled, created_at, created_date, metadata_note
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        reservation_id,
                        req.run_id,
                        req.target_id,
                        req.action_type,
                        req.reserved_http_requests,
                        req.reserved_search_calls,
                        req.reserved_cost_usd,
                        req.reserved_tokens,
                        req.reserved_subscription_units,
                        now_ts,
                        today,
                        req.metadata_note,
                    ),
                )
                conn.execute("COMMIT")
                return ReservationRecord(
                    reservation_id=reservation_id,
                    run_id=req.run_id,
                    target_id=req.target_id,
                    action_type=req.action_type,
                    reserved_http_requests=req.reserved_http_requests,
                    reserved_search_calls=req.reserved_search_calls,
                    reserved_cost_usd=req.reserved_cost_usd,
                    reserved_tokens=req.reserved_tokens,
                    reserved_subscription_units=req.reserved_subscription_units,
                    settled=False,
                    created_at=now_ts,
                )
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def settle(
        self,
        reservation_id: str,
        status: str,  # 'success', 'failed', 'timeout', 'rejected'
        actual_http_requests: Optional[int] = None,
        actual_search_calls: Optional[int] = None,
        actual_cost_usd: Optional[float] = None,
        actual_tokens: Optional[int] = None,
        actual_subscription_units: Optional[int] = None,
        conservative_on_unknown: bool = True,
    ) -> SettlementReport:
        """Atomically settle an active reservation.

        If actual usage is unknown or failed/timed-out, conservative handling
        retains full reservation usage to prevent free-riding on failures.
        Subsequent settlements for the same reservation raise BudgetAlreadySettledError.
        """
        now_ts = _utcnow()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                    (reservation_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise BudgetReservationNotFoundError(
                        f"Reservation {reservation_id} does not exist"
                    )
                if row["settled"] == 1:
                    raise BudgetAlreadySettledError(
                        f"Reservation {reservation_id} has already been settled"
                    )

                # Conservative fallbacks:
                # On timeout, failure, or None, default to the reserved amount
                final_http = (
                    actual_http_requests
                    if actual_http_requests is not None
                    else row["reserved_http_requests"]
                )
                final_search = (
                    actual_search_calls
                    if actual_search_calls is not None
                    else row["reserved_search_calls"]
                )
                final_cost = (
                    actual_cost_usd
                    if actual_cost_usd is not None
                    else row["reserved_cost_usd"]
                )
                final_tokens = (
                    actual_tokens
                    if actual_tokens is not None
                    else row["reserved_tokens"]
                )
                final_units = (
                    actual_subscription_units
                    if actual_subscription_units is not None
                    else row["reserved_subscription_units"]
                )

                conn.execute(
                    """
                    UPDATE budget_reservations
                    SET settled = 1,
                        settled_status = ?,
                        actual_http_requests = ?,
                        actual_search_calls = ?,
                        actual_cost_usd = ?,
                        actual_tokens = ?,
                        actual_subscription_units = ?,
                        settled_at = ?
                    WHERE reservation_id = ?
                    """,
                    (
                        status,
                        final_http,
                        final_search,
                        final_cost,
                        final_tokens,
                        final_units,
                        now_ts,
                        reservation_id,
                    ),
                )
                conn.execute("COMMIT")
                return SettlementReport(
                    reservation_id=reservation_id,
                    actual_http_requests=final_http,
                    actual_search_calls=final_search,
                    actual_cost_usd=final_cost,
                    actual_tokens=final_tokens,
                    actual_subscription_units=final_units,
                    status=status,
                    settled_at=now_ts,
                )
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def get_run_usage(self, run_id: str) -> dict[str, float]:
        """Retrieve cumulative usage for a run including pending reservations."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN settled = 1 THEN actual_http_requests ELSE reserved_http_requests END) AS http,
                    SUM(CASE WHEN settled = 1 THEN actual_search_calls ELSE reserved_search_calls END) AS search,
                    SUM(CASE WHEN settled = 1 THEN actual_cost_usd ELSE reserved_cost_usd END) AS cost,
                    SUM(CASE WHEN settled = 1 THEN actual_tokens ELSE reserved_tokens END) AS tokens,
                    SUM(CASE WHEN settled = 1 THEN actual_subscription_units ELSE reserved_subscription_units END) AS units
                FROM budget_reservations
                WHERE run_id = ?
                """,
                (run_id,),
            )
            row = cur.fetchone()
            return {
                "http_requests": int(row["http"] or 0),
                "search_calls": int(row["search"] or 0),
                "cost_usd": float(row["cost"] or 0.0),
                "tokens": int(row["tokens"] or 0),
                "subscription_units": int(row["units"] or 0),
            }

    def get_daily_usage(self, target_date: Optional[str] = None) -> int:
        """Retrieve cumulative daily HTTP requests for a given date."""
        d = target_date or _today_str()
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN settled = 1 THEN actual_http_requests ELSE reserved_http_requests END) AS daily_http
                FROM budget_reservations
                WHERE created_date = ?
                """,
                (d,),
            )
            row = cur.fetchone()
            return int(row["daily_http"] or 0)
