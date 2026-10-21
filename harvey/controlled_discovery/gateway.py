"""Unified Controlled Egress Gateway for Harvey.

Implements the end-to-end outbound security contract:
  Authorize Target (Policy)
  -> Check robots / source policy
  -> Reserve Budget (HardBudgetLedger)
  -> Acquire Rate Permit (PersistentEgressLimiter)
  -> SSRF Transport Guard (SSRFSafeTransport)
  -> Perform Request
  -> Limit Bytes / Redirects / Retries
  -> Settle Budget
  -> Write Audit Record (OutboundAuditLogger)
  -> Issue Trusted Collection Receipt (Receipt Signer)

Redirects and retries re-execute authorization and resource metering checks.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import httpx

from harvey.controlled_discovery.audit import (
    OutboundAuditEvent,
    OutboundAuditLogger,
    sanitize_headers,
    sanitize_url,
)
from harvey.controlled_discovery.budget import (
    BudgetExceededError,
    BudgetUnauthorizedError,
    HardBudgetLedger,
    ReservationRequest,
)
from harvey.controlled_discovery.limiter import (
    LeaseReleaseOutcome,
    LimiterConfig,
    MaxRetriesExceededError,
    OfflineEgressBlockedError,
    PersistentEgressLimiter,
    RedirectLimitExceededError,
    RequestLease,
    ResponseBodyMeter,
    ResponseSizeLimitExceededError,
    normalize_domain,
)
from harvey.controlled_discovery.policy import (
    AccessPurpose,
    DecisionCode,
    PolicyDecision,
    RobotsFetchStatus,
    SourcePolicyEngine,
    TargetAllowlist,
)
from harvey.controlled_discovery.receipt import (
    CollectorReceipt,
    compute_content_sha256,
    sign_collector_receipt,
)
from harvey.security_ssrf import SSRFBlockedError, SSRFSafeTransport

logger = logging.getLogger("harvey.controlled_discovery.gateway")


class ControlledEgressBlockedError(Exception):
    """Raised when an outbound request is rejected by policy, budget, or rate-limiting."""
    def __init__(self, message: str, decision: Optional[PolicyDecision] = None):
        super().__init__(message)
        self.decision = decision


@dataclass
class ControlledEgressResponse:
    """Structured outcome of a successful controlled egress acquisition."""
    status_code: int
    headers: Dict[str, str]
    content: bytes
    url: str
    receipt: CollectorReceipt
    policy_decision: PolicyDecision
    run_id: str
    target_id: Optional[str]
    audit_event_id: str
    bytes_metered: int
    retries_used: int
    redirects_used: int


class ControlledEgressGateway:
    """
    Centralized egress gateway enforcing the strict 10-step outbound security contract.
    Guarantees zero unmonitored external socket or HTTP traffic.
    """

    def __init__(
        self,
        policy_engine: SourcePolicyEngine,
        budget_ledger: HardBudgetLedger,
        limiter: PersistentEgressLimiter,
        audit_logger: OutboundAuditLogger,
        signing_key: bytes,
        key_id: str = "w105-master-key",
        custom_transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 15.0,
    ):
        self.policy_engine = policy_engine
        self.budget_ledger = budget_ledger
        self.limiter = limiter
        self.audit_logger = audit_logger
        self.signing_key = signing_key
        self.key_id = key_id
        self.custom_transport = custom_transport
        self.timeout = timeout

    async def request(
        self,
        url: str,
        method: str = "GET",
        company_id: Optional[str] = None,
        purpose: AccessPurpose = AccessPurpose.CONTROLLED_EXPERIMENT,
        collector_id: str = "harvey.gateway",
        headers: Optional[Dict[str, str]] = None,
        run_id: Optional[str] = None,
        resolver: Optional[Callable] = None,
    ) -> ControlledEgressResponse:
        """
        Execute an HTTP request through the strict 10-stage egress pipeline.
        """
        current_run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
        req_headers = dict(headers or {})
        current_url = url
        redirect_count = 0
        attempt = 0

        max_retries = self.limiter.config.max_retries
        max_redirects = self.limiter.config.max_redirects

        while attempt <= max_retries:
            attempt += 1

            # Step 1 & 2: Authorize Target & Check Robots Policy
            policy_decision = self.policy_engine.evaluate_url(
                current_url,
                company_id=company_id,
                purpose=purpose,
            )
            if not policy_decision.allowed:
                # Audit denied attempt
                self._record_audit_event(
                    run_id=current_run_id,
                    target_id=company_id,
                    original_url=current_url,
                    status="DENIED_POLICY",
                    policy_decision=policy_decision.decision.value,
                    error_message=f"Policy rejection: {policy_decision.reason}",
                )
                raise ControlledEgressBlockedError(
                    f"Request to {current_url} denied by policy: {policy_decision.reason} ({policy_decision.decision.value})",
                    decision=policy_decision,
                )

            # Step 3: Reserve Budget
            try:
                reservation = self.budget_ledger.reserve(
                    ReservationRequest(
                        run_id=current_run_id,
                        target_id=company_id or "unknown",
                        action_type="http_request",
                        reserved_http_requests=1,
                        reserved_search_calls=0,
                        reserved_tokens=0,
                    )
                )
            except (BudgetExceededError, BudgetUnauthorizedError) as e:
                self._record_audit_event(
                    run_id=current_run_id,
                    target_id=company_id,
                    original_url=current_url,
                    status="DENIED_BUDGET",
                    policy_decision=policy_decision.decision.value,
                    error_message=str(e),
                )
                raise

            # Step 4: Acquire Rate Permit
            target_domain = normalize_domain(current_url)
            try:
                lease = await self.limiter.acquire(
                    url_or_domain=target_domain,
                    attempt=attempt,
                )
            except Exception as e:
                # Release budget conservatively if rate limit acquisition fails
                self.budget_ledger.settle(
                    reservation_id=reservation.reservation_id,
                    status="rejected",
                    actual_http_requests=1,
                    actual_search_calls=0,
                    actual_cost_usd=0.0,
                    actual_tokens=0,
                )
                self._record_audit_event(
                    run_id=current_run_id,
                    target_id=company_id,
                    original_url=current_url,
                    status="DENIED_RATE_LIMIT",
                    policy_decision=policy_decision.decision.value,
                    budget_reservation_id=reservation.reservation_id,
                    error_message=str(e),
                )
                raise

            # Step 5 & 6: SSRF Transport Guard & Perform Request with Stream Metering
            transport = self.custom_transport or SSRFSafeTransport(resolver=resolver)
            meter = ResponseBodyMeter(max_bytes=self.limiter.config.max_response_bytes)

            content_chunks: List[bytes] = []
            response_status = 0
            response_headers: Dict[str, str] = {}

            try:
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=self.timeout,
                    follow_redirects=False,
                ) as client:
                    httpx_req = client.build_request(method, current_url, headers=req_headers)
                    resp = await client.send(httpx_req, stream=True)
                    response_status = resp.status_code
                    response_headers = {k: v for k, v in resp.headers.items()}

                    # Meter streaming body
                    async for chunk in resp.aiter_bytes():
                        meter.update(chunk)
                        content_chunks.append(chunk)
                    await resp.aclose()

                body_bytes = b"".join(content_chunks)

                # Check for redirect (301, 302, 303, 307, 308)
                if response_status in (301, 302, 303, 307, 308) and "location" in response_headers:
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        await lease.release(outcome=LeaseReleaseOutcome.FAILURE, http_status=response_status)
                        self.budget_ledger.settle(reservation.reservation_id, status="failed", actual_http_requests=1)
                        raise RedirectLimitExceededError(redirect_count, max_redirects)

                    raw_location = response_headers["location"]
                    parsed_redirect = httpx.URL(current_url).join(raw_location)
                    new_url = str(parsed_redirect)

                    # Evaluate redirect policy
                    red_decision = self.policy_engine.evaluate_redirect(
                        initial_url=current_url,
                        redirect_url=new_url,
                        company_id=company_id,
                        purpose=purpose,
                    )
                    if not red_decision.allowed:
                        await lease.release(outcome=LeaseReleaseOutcome.FAILURE, http_status=response_status)
                        self.budget_ledger.settle(reservation.reservation_id, status="rejected", actual_http_requests=1)
                        dec_val = red_decision.target_decision.decision.value if hasattr(red_decision, "target_decision") else DecisionCode.DENIED_REDIRECT_TARGET.value
                        self._record_audit_event(
                            run_id=current_run_id,
                            target_id=company_id,
                            original_url=current_url,
                            status="DENIED_REDIRECT",
                            policy_decision=dec_val,
                            permit_id=lease.lease_id,
                            budget_reservation_id=reservation.reservation_id,
                            error_message=f"Redirect to {new_url} denied: {red_decision.reason}",
                        )
                        raise ControlledEgressBlockedError(
                            f"Redirect to {new_url} denied by policy: {red_decision.reason}",
                            decision=red_decision.target_decision if hasattr(red_decision, "target_decision") else None,
                        )

                    # Step 7: Settle budget and release lease for this step
                    await lease.release(outcome=LeaseReleaseOutcome.SUCCESS, http_status=response_status, bytes_metered=meter.bytes_metered)
                    self.budget_ledger.settle(reservation.reservation_id, status="success", actual_http_requests=1)

                    self._record_audit_event(
                        run_id=current_run_id,
                        target_id=company_id,
                        original_url=current_url,
                        status="REDIRECTED",
                        policy_decision=policy_decision.decision.value,
                        permit_id=lease.lease_id,
                        budget_reservation_id=reservation.reservation_id,
                        details_json={"redirect_to": new_url, "status_code": response_status},
                    )

                    # Loop with redirected URL
                    current_url = new_url
                    continue

                # Check for 429 Rate Limit
                if response_status == 429:
                    retry_after = response_headers.get("retry-after")
                    await lease.release(outcome=LeaseReleaseOutcome.RATE_LIMITED, retry_after_seconds=retry_after, http_status=response_status)
                    self.budget_ledger.settle(reservation.reservation_id, status="success", actual_http_requests=1)
                    if attempt <= max_retries:
                        await asyncio.sleep(self.limiter.config.base_retry_backoff_seconds * (2 ** (attempt - 1)))
                        continue
                    raise MaxRetriesExceededError(attempt, max_retries)

                # Step 7 & 8: Settle Budget & Release Lease
                await lease.release(outcome=LeaseReleaseOutcome.SUCCESS, http_status=response_status, bytes_metered=meter.bytes_metered)
                self.budget_ledger.settle(reservation.reservation_id, status="success", actual_http_requests=1)

                # Step 9: Write Audit Record
                audit_event = self._record_audit_event(
                    run_id=current_run_id,
                    target_id=company_id,
                    original_url=current_url,
                    status="SUCCESS" if response_status < 400 else f"HTTP_{response_status}",
                    policy_decision=policy_decision.decision.value,
                    permit_id=lease.lease_id,
                    budget_reservation_id=reservation.reservation_id,
                    actual_cost_usd=0.0,
                    retry_count=attempt - 1,
                    details_json={"status_code": response_status, "bytes_metered": meter.bytes_metered},
                )

                # Step 10: Issue Trusted Collection Receipt
                receipt = sign_collector_receipt(
                    run_id=current_run_id,
                    collector_id=collector_id,
                    collected_url=current_url,
                    raw_content_bytes=body_bytes,
                    permit_ref=lease.lease_id,
                    policy_decision_ref=policy_decision.decision.value,
                    secret_key=self.signing_key,
                    key_id=self.key_id,
                )

                return ControlledEgressResponse(
                    status_code=response_status,
                    headers=response_headers,
                    content=body_bytes,
                    url=current_url,
                    receipt=receipt,
                    policy_decision=policy_decision,
                    run_id=current_run_id,
                    target_id=company_id,
                    audit_event_id=audit_event.event_id,
                    bytes_metered=meter.bytes_metered,
                    retries_used=attempt - 1,
                    redirects_used=redirect_count,
                )

            except Exception as e:
                await lease.release(outcome=LeaseReleaseOutcome.FAILURE)
                try:
                    self.budget_ledger.settle(reservation.reservation_id, status="failed", actual_http_requests=1)
                except Exception:
                    pass
                self._record_audit_event(
                    run_id=current_run_id,
                    target_id=company_id,
                    original_url=current_url,
                    status="FAILURE",
                    policy_decision=policy_decision.decision.value,
                    permit_id=lease.lease_id,
                    budget_reservation_id=reservation.reservation_id,
                    error_message=str(e),
                )
                raise

        raise MaxRetriesExceededError(attempt, max_retries)

    def _record_audit_event(
        self,
        run_id: str,
        target_id: Optional[str],
        original_url: str,
        status: str,
        policy_decision: str,
        resolved_host: str = "",
        resolved_ip: str = "",
        resolved_port: int = 0,
        outbound_at: str = "",
        permit_id: str = "",
        budget_reservation_id: str = "",
        **kwargs,
    ) -> OutboundAuditEvent:
        parsed = urlparse(original_url)
        host = resolved_host or parsed.hostname or ""
        port = resolved_port or parsed.port or (443 if parsed.scheme == "https" else 80)
        event = OutboundAuditEvent(
            run_id=run_id,
            target_id=target_id or "",
            original_url=original_url,
            resolved_host=host,
            resolved_ip=resolved_ip,
            resolved_port=port,
            outbound_at=outbound_at,
            policy_decision=policy_decision,
            permit_id=permit_id,
            budget_reservation_id=budget_reservation_id,
            status=status,
            **kwargs,
        )
        self.audit_logger.log(event)
        return event
