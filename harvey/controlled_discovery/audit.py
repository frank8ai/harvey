"""Controlled Discovery Structured Outbound Audit Logger.

Records structured egress traffic audit entries into a dedicated local SQLite table.

Safety Invariants:
- NEVER logs Authorization headers, Cookie, API Key, proxy credentials, or secrets.
- Sanitizes query parameters and header dictionaries to avoid credential leakage.
- Explicitly notes that local SQLite storage is an append-only operational audit log,
  NOT a cryptographically tamper-proof immutable ledger.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


SENSITIVE_PARAM_PATTERN = re.compile(
    r"^(api_?key|token|auth|secret|password|passwd|access_token|refresh_token|credential|session)",
    re.IGNORECASE,
)

SENSITIVE_HEADER_PATTERN = re.compile(
    r"(authorization|cookie|set-cookie|api-key|x-api-key|secret|proxy-authorization|token)",
    re.IGNORECASE,
)


def sanitize_url(raw_url: str) -> str:
    """Sanitize URL by masking sensitive query params and userinfo credentials."""
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        # Strip userinfo (user:pass@host)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        # Sanitize query parameters
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_query = []
        for k, v in query_pairs:
            if SENSITIVE_PARAM_PATTERN.search(k):
                sanitized_query.append((k, "[REDACTED]"))
            else:
                sanitized_query.append((k, v))

        return urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                urlencode(sanitized_query),
                parsed.fragment,
            )
        )
    except Exception:
        return "[MALFORMED_URL_REDACTED]"


def sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Filter out any sensitive headers such as Authorization, Cookie, API keys."""
    if not headers:
        return {}
    cleaned: Dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k).strip()
        if SENSITIVE_HEADER_PATTERN.search(key_str):
            cleaned[key_str] = "[REDACTED]"
        else:
            cleaned[key_str] = str(v)
    return cleaned


@dataclass(frozen=True)
class OutboundAuditEvent:
    """Structured outbound network audit event."""

    run_id: str
    target_id: str
    original_url: str
    resolved_host: str
    resolved_ip: str
    resolved_port: int
    outbound_at: str
    policy_decision: str  # 'ALLOW', 'BLOCK', 'RATE_LIMIT', 'FORBIDDEN'
    permit_id: str
    budget_reservation_id: str
    status: str  # 'SUCCESS', 'FAILED', 'TIMEOUT', 'REJECTED', 'CANCELLED'
    actual_cost_usd: float = 0.0
    evidence_id: str = ""
    event_type: str = "REQUEST"  # 'REQUEST', 'RETRY', 'CANCEL', 'EXCEPTION'
    retry_count: int = 0
    error_message: str = ""
    details_json: str = "{}"
    event_id: str = ""


class OutboundAuditLogger:
    """Operational SQLite logger for controlled discovery outbound actions.

    Design Disclaimer: This logger provides structured, queryable local audit records.
    It does NOT provide cryptographic immutability or non-repudiation against an attacker
    with root/filesystem write access to the SQLite file.
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
                CREATE TABLE IF NOT EXISTS outbound_audit_log (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    original_url TEXT NOT NULL,
                    resolved_host TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    resolved_port INTEGER NOT NULL,
                    outbound_at TEXT NOT NULL,
                    policy_decision TEXT NOT NULL,
                    permit_id TEXT NOT NULL,
                    budget_reservation_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    actual_cost_usd REAL DEFAULT 0.0,
                    evidence_id TEXT DEFAULT '',
                    event_type TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    error_message TEXT DEFAULT '',
                    details_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_run ON outbound_audit_log(run_id, outbound_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_target ON outbound_audit_log(target_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_status ON outbound_audit_log(status)"
            )
            conn.execute("COMMIT")

    def log(self, event: OutboundAuditEvent) -> str:
        """Record an outbound event with automatic redaction of sensitive data."""
        event_id = event.event_id or f"aud_{uuid.uuid4().hex[:16]}"
        now_ts = datetime.now(timezone.utc).isoformat()
        outbound_at = event.outbound_at or now_ts

        # Sanitization passes
        safe_url = sanitize_url(event.original_url)
        safe_error = event.error_message
        # Scrub potential API key patterns or Authorization patterns in error messages
        safe_error = re.sub(
            r"(Bearer\s+)[A-Za-z0-9_\-\.]+", r"\1[REDACTED]", safe_error, flags=re.IGNORECASE
        )
        safe_error = re.sub(
            r"(key|token|secret)=([^&\s]+)", r"\1=[REDACTED]", safe_error, flags=re.IGNORECASE
        )

        # Verify details_json does not contain plaintext sensitive headers
        details = {}
        if event.details_json:
            try:
                parsed_details = json.loads(event.details_json)
                if isinstance(parsed_details, dict):
                    if "headers" in parsed_details and isinstance(
                        parsed_details["headers"], dict
                    ):
                        parsed_details["headers"] = sanitize_headers(
                            parsed_details["headers"]
                        )
                    details = parsed_details
            except Exception:
                details = {"raw_unparseable": True}

        safe_details_json = json.dumps(details)

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO outbound_audit_log (
                    event_id, run_id, target_id, original_url,
                    resolved_host, resolved_ip, resolved_port,
                    outbound_at, policy_decision, permit_id,
                    budget_reservation_id, status, actual_cost_usd,
                    evidence_id, event_type, retry_count,
                    error_message, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.run_id,
                    event.target_id,
                    safe_url,
                    event.resolved_host,
                    event.resolved_ip,
                    int(event.resolved_port or 0),
                    outbound_at,
                    event.policy_decision,
                    event.permit_id,
                    event.budget_reservation_id,
                    event.status,
                    float(event.actual_cost_usd or 0.0),
                    event.evidence_id,
                    event.event_type,
                    int(event.retry_count or 0),
                    safe_error,
                    safe_details_json,
                    now_ts,
                ),
            )
            conn.execute("COMMIT")
        return event_id

    def query_logs(
        self,
        run_id: Optional[str] = None,
        target_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries."""
        clauses = []
        params: List[Any] = []
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM outbound_audit_log {where_sql} ORDER BY outbound_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def count_events(self, run_id: Optional[str] = None) -> int:
        """Count total logged events."""
        sql = "SELECT COUNT(*) FROM outbound_audit_log"
        params: List[Any] = []
        if run_id:
            sql += " WHERE run_id = ?"
            params.append(run_id)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            return int(cur.fetchone()[0] or 0)
