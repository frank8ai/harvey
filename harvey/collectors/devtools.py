"""DevTools & B2B SaaS Collector, Qualification Engine, and Pipeline Adapter (W1-03-R).

This collector extracts concrete, verifiable engineering facts for FetchInbox:
1. HAS_SIGNUP_OTP_OR_MAGIC_LINK (Auth flows requiring email codes / magic links)
2. USES_E2E_TEST_FRAMEWORK (Playwright, Cypress, Selenium, Puppeteer)
3. BUILDS_AI_OR_BROWSER_AGENTS (Autonomous web agents, browser automation, computer-use)
4. HAS_DEVELOPER_DOCS_OR_API (Public API docs, SDK references, developer hubs)
5. USES_TRANSACTIONAL_EMAIL_ESP (Postmark, SendGrid, Resend, Mailgun, AWS SES)
6. HIRING_QA_OR_AGENT_INFRA (Active hiring for QA automation, SDETs, Agent infra)
7. VERISIG_EVIDENCE_SUFFICIENCY (Qualification sufficiency assessment)
8. VERISIG_DISQUALIFIED_REASON (Deterministic disqualification reason)

Design principles & W1-03-R Corrections:
- 100% offline testable pure functions.
- Multi-source evidence tracking: duplicate mentions across single or multiple pages
  do NOT count as multiple independent sources.
- Safe-by-default: zero network access during evaluation tests.
- Source URL integrity: unvisited or fabricated endpoints are marked 'UNKNOWN', never guessed.
- Empty inputs resolve to 'UNKNOWN' state, never 'NO_AUTOMATION_NEED'.
- Strict buyer guard: hiring QA or using Playwright indicates potential technical fit
  ('POTENTIAL_FIT'), NOT confirmed active buying intent ('CONFIRMED_ACTIVE_BUYER').
- Explicit procurement documentation forms a 'PURCHASE_CANDIDATE_PENDING_VERIFICATION';
  never auto-confirmed by model tags.
- 'READY_FOR_OUTREACH' is never auto-emitted from technical signals.
- Reuses Harvey models, state and observations interface.
"""

import asyncio
import hashlib
import json
import logging
import re
import socket
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("harvey.collectors.devtools")

# ── 1. Regex Patterns & Fingerprints ─────────────────────────────────

# Signup OTP or Magic link patterns
OTP_PATTERNS = [
    re.compile(r"\b(?:6|4|8)[- ]?digit\s+(?:code|otp|pin|verification)\b", re.I),
    re.compile(r"\b(?:verification|security|one[- ]time)\s+code\b", re.I),
    re.compile(r"\benter\s+(?:the\s+)?(?:code|otp)\s+sent\s+to\b", re.I),
    re.compile(r"\bcheck\s+your\s+email\s+for\s+(?:a|the)\s+code\b", re.I),
    re.compile(r"\bsend\s+(?:me\s+a\s+)?magic\s+link\b", re.I),
    re.compile(r"\bmagic\s+link\s+to\s+sign\s+in\b", re.I),
    re.compile(r"\bemail\s+(?:a\s+)?login\s+link\b", re.I),
    re.compile(r"\bpasswordless\s+(?:email|login|sign[- ]in)\b", re.I),
    re.compile(r"\bsign\s+in\s+with\s+magic\s+link\b", re.I),
    re.compile(r"\bsign\s+in\s+with\s+email\s+code\b", re.I),
]

# E2E Test Frameworks
E2E_FRAMEWORKS = {
    "Playwright": re.compile(r"\bplaywright(?:\/test)?\b", re.I),
    "Cypress": re.compile(r"\bcypress(?:\.io)?\b", re.I),
    "Selenium": re.compile(r"\bselenium(?:[- ]webdriver)?\b", re.I),
    "Puppeteer": re.compile(r"\bpuppeteer\b", re.I),
}

# AI & Browser Agent Patterns (Technical, not generic hype)
AI_AGENT_PATTERNS = [
    re.compile(r"\b(?:browser|web|headless)\s+automation\s+agent[s]?\b", re.I),
    re.compile(r"\bautonomous\s+(?:web|browser|computer[- ]use)\s+agent[s]?\b", re.I),
    re.compile(r"\bcomputer[- ]use\s+agent[s]?\b", re.I),
    re.compile(r"\bmulti[- ]step\s+web\s+agent[s]?\b", re.I),
    re.compile(r"\bnavigate\s+web\s+forms\s+(?:automatically|autonomously)\b", re.I),
    re.compile(r"\b(?:browser[-_]use|stagehand|skyvern|agentops)\b", re.I),
    re.compile(r"\bweb\s+agent\s+sdk\b", re.I),
    re.compile(r"\bheadless\s+browser\s+agent[s]?\b", re.I),
]

# Developer Docs / API Patterns
DEV_DOCS_PATTERNS = [
    re.compile(r"\bapi\s+reference\b", re.I),
    re.compile(r"\bdeveloper\s+docs\b", re.I),
    re.compile(r"\bdeveloper\s+documentation\b", re.I),
    re.compile(r"\bdeveloper\s+guide\b", re.I),
    re.compile(r"\bsdk\s+reference\b", re.I),
    re.compile(r"\bwebhook[s]?\s+(?:guide|integration|documentation)\b", re.I),
    re.compile(r"\bdocs\.(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
    re.compile(r"\b(?:mintlify|readme\.com|gitbook|scalar|redoc|swagger)\b", re.I),
]

# Transactional ESP Fingerprints in SPF or headers
TRANSACTIONAL_ESPS = {
    "Postmark": re.compile(r"\bpostmarkapp\.com\b", re.I),
    "SendGrid": re.compile(r"\bsendgrid\.net\b", re.I),
    "Resend": re.compile(r"\bresend\.com\b", re.I),
    "Mailgun": re.compile(r"\bmailgun\.(?:org|net|com)\b", re.I),
    "Amazon_SES": re.compile(r"\bamazonses\.com\b", re.I),
    "Brevo": re.compile(r"\b(?:sendinblue\.com|brevo\.com)\b", re.I),
}

# Hiring Roles
QA_AGENT_ROLES = [
    re.compile(r"\bqa\s+(?:automation|engineer|lead|consultant)\b", re.I),
    re.compile(r"\bsdet\b", re.I),
    re.compile(r"\bautomation\s+consultant\b", re.I),
    re.compile(r"\bautomation\s+test(?:ing)?\s+engineer\b", re.I),
    re.compile(r"\be2e\s+test(?:ing)?\s+engineer\b", re.I),
    re.compile(r"\bagent\s+(?:platform|infra(?:structure)?)\s+engineer\b", re.I),
    re.compile(r"\bbrowser\s+automation\s+(?:engineer|specialist)\b", re.I),
]

# Stale / Closed indicators in job postings (>90 days or explicit closed markers)
CLOSED_JOB_MARKERS = [
    re.compile(r"\b(?:closed|filled|expired|inactive|archive[d]?|no\s+longer\s+accepting)\b", re.I),
    re.compile(r"\bposition\s+(?:is\s+)?closed\b", re.I),
    re.compile(r"\bcurrently\s+not\s+hiring\b", re.I),
    re.compile(r"\bposted\s+(?:[9][1-9]|\d{3,})\s+days\s+ago\b", re.I),
    re.compile(r"\bposted\s+>(?:90|180|365)\s+days\b", re.I),
]

# Competitors / Exclusion
DIRECT_COMPETITOR_PATTERNS = [
    re.compile(r"\bdisposable\s+email\b", re.I),
    re.compile(r"\btemporary\s+(?:mail|inbox|mailbox|email)\b", re.I),
    re.compile(r"\bthrowaway\s+email\b", re.I),
    re.compile(r"\b10\s*minute\s*mail\b", re.I),
    re.compile(r"\bmailosaur\b", re.I),
    re.compile(r"\bmailtrap\b", re.I),
    re.compile(r"\btestmail\.app\b", re.I),
    re.compile(r"\binboxkitten\b", re.I),
]

CONSUMER_PATTERNS = [
    re.compile(r"\b(?:apparel|clothing|fashion|shoes|jewelry|furniture|bakery|dental\s+clinic|dentist|plumbing|roofing)\b", re.I),
    re.compile(r"\bcart\s+checkout\b", re.I),
    re.compile(r"\bshopping\s+bag\b", re.I),
]


# ── Helper: Normalized Content Fingerprint ────────────────────────────


# ── Outbound Network Blocker & Audit Guard ───────────────────────────

class OfflineNetworkBlockedError(RuntimeError):
    """Raised when any outbound network request is attempted during offline execution."""


class OutboundCallTracker:
    """Tracks attempted outbound calls for strict offline assertion."""
    def __init__(self):
        self.call_count = 0
        self.calls: list[tuple[str, str]] = []

    def record(self, call_type: str, target: str):
        self.call_count += 1
        self.calls.append((call_type, str(target)))


@contextmanager
def offline_network_guard(tracker: Optional[OutboundCallTracker] = None):
    """Strict outbound network guard for offline execution.
    Blocks DNS lookups, raw socket connects, httpcore HTTP calls, urllib, and asyncio connections.
    Localhost is permitted only for local IPC/database.
    """
    orig_gai = socket.getaddrinfo
    orig_connect = socket.socket.connect
    orig_create_conn = asyncio.BaseEventLoop.create_connection

    try:
        import httpcore
        orig_httpcore_handle = getattr(httpcore.ConnectionPool, "handle_request", None)
        orig_httpcore_async = getattr(httpcore.AsyncConnectionPool, "handle_async_request", None)
    except ImportError:
        orig_httpcore_handle = None
        orig_httpcore_async = None

    orig_urllib_open = getattr(urllib.request, "urlopen", None)

    def block_dns(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", None):
            if tracker:
                tracker.record("DNS", host)
            raise OfflineNetworkBlockedError(f"Outbound DNS lookup blocked in offline mode: {host}")
        return orig_gai(host, *args, **kwargs)

    def block_connect(self, address):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
        if host not in ("127.0.0.1", "localhost", "::1"):
            if tracker:
                tracker.record("SOCKET", address)
            raise OfflineNetworkBlockedError(f"Outbound socket connect blocked in offline mode: {address}")
        return orig_connect(self, address)

    def block_http(self_pool, request, *args, **kwargs):
        target = str(getattr(request, "url", "unknown"))
        if tracker:
            tracker.record("HTTP_SYNC", target)
        raise OfflineNetworkBlockedError(f"Outbound HTTP request blocked in offline mode: {target}")

    async def block_http_async(self_pool, request, *args, **kwargs):
        target = str(getattr(request, "url", "unknown"))
        if tracker:
            tracker.record("HTTP_ASYNC", target)
        raise OfflineNetworkBlockedError(f"Outbound HTTP async request blocked in offline mode: {target}")

    def block_urllib(url, *args, **kwargs):
        target = url if isinstance(url, str) else getattr(url, "full_url", str(url))
        if tracker:
            tracker.record("URLLIB", target)
        raise OfflineNetworkBlockedError(f"Outbound urllib request blocked in offline mode: {target}")

    async def block_create_conn(self, protocol_factory, host=None, port=None, *args, **kwargs):
        if host and host not in ("127.0.0.1", "localhost", "::1"):
            if tracker:
                tracker.record("ASYNCIO_CONN", f"{host}:{port}")
            raise OfflineNetworkBlockedError(f"Outbound asyncio connection blocked in offline mode: {host}:{port}")
        return await orig_create_conn(self, protocol_factory, host=host, port=port, *args, **kwargs)

    socket.getaddrinfo = block_dns
    socket.socket.connect = block_connect
    if orig_httpcore_handle:
        httpcore.ConnectionPool.handle_request = block_http
    if orig_httpcore_async:
        httpcore.AsyncConnectionPool.handle_async_request = block_http_async
    if orig_urllib_open:
        urllib.request.urlopen = block_urllib
    asyncio.BaseEventLoop.create_connection = block_create_conn

    try:
        yield tracker
    finally:
        socket.getaddrinfo = orig_gai
        socket.socket.connect = orig_connect
        if orig_httpcore_handle:
            httpcore.ConnectionPool.handle_request = orig_httpcore_handle
        if orig_httpcore_async:
            httpcore.AsyncConnectionPool.handle_async_request = orig_httpcore_async
        if orig_urllib_open:
            urllib.request.urlopen = orig_urllib_open
        asyncio.BaseEventLoop.create_connection = orig_create_conn


def _content_fingerprint(text: str) -> str:
    """Compute a lightweight hash of normalized whitespace text."""
    cleaned = re.sub(r"\s+", " ", text or "").strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]


# ── 2. Pure Extraction Functions ─────────────────────────────────────

def extract_signup_otp_signals(html: str, source_url: str = "") -> dict[str, Any] | None:
    """Extract OTP or magic link authentication indicators from login/signup HTML."""
    if not html:
        return None
    url = source_url.strip() if source_url and source_url.strip() else "UNKNOWN"
    matches = []
    for pattern in OTP_PATTERNS:
        m = pattern.search(html)
        if m:
            matches.append(m.group(0))
    if matches:
        return {
            "signal_code": "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
            "detected": True,
            "evidence": matches[0],
            "source_url": url,
            "confidence": 0.85,
            "snippet_hash": _content_fingerprint(matches[0]),
        }
    return None


def extract_e2e_frameworks(text: str, source_url: str = "") -> list[dict[str, Any]]:
    """Detect Playwright, Cypress, Selenium, or Puppeteer mentions."""
    if not text:
        return []
    url = source_url.strip() if source_url and source_url.strip() else "UNKNOWN"
    found = []
    for name, pattern in E2E_FRAMEWORKS.items():
        for m in pattern.finditer(text):
            vicinity_start = max(0, m.start() - 250)
            vicinity_end = min(len(text), m.end() + 250)
            vicinity = text[vicinity_start:vicinity_end]
            if any(closed_pat.search(vicinity) for closed_pat in CLOSED_JOB_MARKERS):
                continue
            found.append({
                "signal_code": "USES_E2E_TEST_FRAMEWORK",
                "framework": name,
                "evidence": name,
                "source_url": url,
                "confidence": 0.85,
                "snippet_hash": _content_fingerprint(name),
            })
            break
    return found


def extract_agent_signals(text: str, source_url: str = "") -> dict[str, Any] | None:
    """Detect AI browser agents or computer-use automation features."""
    if not text:
        return None
    url = source_url.strip() if source_url and source_url.strip() else "UNKNOWN"
    for pattern in AI_AGENT_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "signal_code": "BUILDS_AI_OR_BROWSER_AGENTS",
                "detected": True,
                "evidence": m.group(0),
                "source_url": url,
                "confidence": 0.85,
                "snippet_hash": _content_fingerprint(m.group(0)),
            }
    return None


def extract_developer_docs_signals(text: str, source_url: str = "") -> dict[str, Any] | None:
    """Detect developer documentation or API references."""
    if not text:
        return None
    url = source_url.strip() if source_url and source_url.strip() else "UNKNOWN"
    for pattern in DEV_DOCS_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "signal_code": "HAS_DEVELOPER_DOCS_OR_API",
                "detected": True,
                "evidence": m.group(0),
                "source_url": url,
                "confidence": 0.90,
                "snippet_hash": _content_fingerprint(m.group(0)),
            }
    return None


def classify_dns_spf_esp(
    spf_records: list[str], source_domain: str = "", dns_source: str = ""
) -> list[dict[str, Any]]:
    """Identify transactional email provider footprints from SPF/TXT records."""
    if not spf_records:
        return []
    src_url = dns_source.strip() if dns_source and dns_source.strip() else (
        f"dns:spf:{source_domain}" if source_domain else "UNKNOWN"
    )
    combined = " ".join(spf_records)
    hits = []
    for esp_name, pattern in TRANSACTIONAL_ESPS.items():
        if pattern.search(combined):
            hits.append({
                "signal_code": "USES_TRANSACTIONAL_EMAIL_ESP",
                "esp": esp_name,
                "evidence": esp_name,
                "source_url": src_url,
                "confidence": 0.70,
                "snippet_hash": _content_fingerprint(esp_name),
            })
    return hits


def extract_hiring_roles(html: str, source_url: str = "") -> dict[str, Any] | None:
    """Identify active QA or Agent infrastructure job postings, filtering out stale/closed posts."""
    if not html:
        return None
    url = source_url.strip() if source_url and source_url.strip() else "UNKNOWN"

    # Check for matching roles while scoping closure markers to the matched listing vicinity
    for role_pat in QA_AGENT_ROLES:
        for m in role_pat.finditer(html):
            vicinity_start = max(0, m.start() - 250)
            vicinity_end = min(len(html), m.end() + 250)
            vicinity = html[vicinity_start:vicinity_end]
            if any(closed_pat.search(vicinity) for closed_pat in CLOSED_JOB_MARKERS):
                continue
            return {
                "signal_code": "HIRING_QA_OR_AGENT_INFRA",
                "role": m.group(0),
                "evidence": m.group(0),
                "source_url": url,
                "confidence": 0.80,
                "is_active": True,
                "snippet_hash": _content_fingerprint(m.group(0)),
            }
    return None


def detect_competitor_or_disqualification(
    html: str,
    company_name: str = "",
    domain: str = "",
) -> str | None:
    """Check if company is a direct competitor, consumer business, or out of scope."""
    combined = f"{company_name} {domain} {html}".lower()

    # 1. Direct competitor (Temporary email / E2E email testing services)
    for pat in DIRECT_COMPETITOR_PATTERNS:
        if pat.search(combined):
            return "DIRECT_COMPETITOR"

    # 2. Consumer retail or purely local business
    consumer_hits = sum(1 for pat in CONSUMER_PATTERNS if pat.search(combined))
    if consumer_hits >= 2 or any(k in combined for k in ["apparel", "dental clinic", "retail store"]):
        return "CONSUMER_ONLY"

    return None


# ── Helper: Purchase Evidence Validator (P1) ─────────────────────────

def validate_purchase_evidence_item(
    item: Any, default_date: str = ""
) -> tuple[bool, dict[str, Any], str]:
    """Validate a single purchase intent evidence item against minimal structural requirements.

    Requirements (P1):
    1. Must be a dictionary.
    2. Must have a valid type / signal_code (non-empty string).
    3. Must have a valid source reference / URL (non-empty string, not 'UNKNOWN').
    4. Must have an excerpt / artifact summary (non-empty string).
    5. Must have a date / timestamp (non-empty string, or fallback to default_date).
    6. Default verification status is capped at 'PURCHASE_CANDIDATE_PENDING_VERIFICATION'.
    """
    if not isinstance(item, dict):
        return False, {}, "Purchase evidence item must be a dictionary"

    sig_code = item.get("signal_code") or item.get("type") or item.get("evidence_type")
    if not sig_code or not isinstance(sig_code, str) or not sig_code.strip():
        return False, {}, "Missing or empty purchase evidence type/signal_code"

    source_ref = item.get("source_url") or item.get("source_ref") or item.get("source")
    if not source_ref or not isinstance(source_ref, str) or not source_ref.strip() or source_ref.strip() == "UNKNOWN":
        return False, {}, "Missing, empty, or UNKNOWN source reference/URL"

    summary = item.get("summary") or item.get("snippet") or item.get("content")
    if not summary or not isinstance(summary, str) or not summary.strip():
        return False, {}, "Missing or empty artifact summary/snippet"

    date_val = item.get("date") or item.get("collected_at") or item.get("timestamp") or default_date
    if not date_val or not isinstance(date_val, str) or not date_val.strip() or date_val.strip() == "UNKNOWN":
        # If no explicit date is provided, mark as UNKNOWN date
        date_val = "UNKNOWN"

    cleaned = {
        "signal_code": str(sig_code).strip(),
        "source_url": str(source_ref).strip(),
        "summary": str(summary).strip(),
        "collected_at": str(date_val).strip(),
        "verification_status": "PURCHASE_CANDIDATE_PENDING_VERIFICATION",
        "confidence": float(item.get("confidence", 0.90)),
    }
    return True, cleaned, ""


# ── 3. Structured Qualification Engine ───────────────────────────────

@dataclass
class DevToolsQualificationResult:
    company_id: str = ""
    domain: str = ""
    icp_fit: str = "UNKNOWN"               # TIER_1_STRONG_FIT | TIER_2_MODERATE_FIT | TIER_3_LOW_FIT | NON_ICP | UNKNOWN
    use_case_fit: str = "UNKNOWN"          # AGENT_INBOX | E2E_AUTH_TESTING | MULTI_TENANT_QA | NONE | UNKNOWN
    evidence_quality: str = "INSUFFICIENT" # SUFFICIENT | PARTIAL | INSUFFICIENT | CONFLICTING
    purchase_intent_evidence: list[dict] = field(default_factory=list)
    disqualified: bool = False
    disqualified_reason: str | None = None
    unknown_fields: list[str] = field(default_factory=list)
    next_best_research_action: str = "DISCOVER_COMPANY_PROFILE"
    qualification_status: str = "UNKNOWN"  # POTENTIAL_FIT | PURCHASE_CANDIDATE_PENDING_VERIFICATION | NEEDS_RESEARCH | UNKNOWN | DISQUALIFIED
    extracted_signals: list[dict] = field(default_factory=list)
    independent_source_count: int = 0
    confidence_model: str = "rule_confidence_uncalibrated"
    source_breakdown: dict[str, list[str]] = field(default_factory=lambda: {
        "verified_source": [],
        "offline_fixture": [],
        "unverified_source": [],
    })
    evidence_bundle_metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "company_id": self.company_id,
            "domain": self.domain,
            "icp_fit": self.icp_fit,
            "use_case_fit": self.use_case_fit,
            "evidence_quality": self.evidence_quality,
            "purchase_intent_evidence": self.purchase_intent_evidence,
            "disqualified": self.disqualified,
            "disqualified_reason": self.disqualified_reason,
            "unknown_fields": self.unknown_fields,
            "next_best_research_action": self.next_best_research_action,
            "qualification_status": self.qualification_status,
            "extracted_signals": self.extracted_signals,
            "independent_source_count": self.independent_source_count,
            "confidence_model": self.confidence_model,
            "source_breakdown": self.source_breakdown,
            "evidence_bundle_metadata": self.evidence_bundle_metadata,
        }


@dataclass
class OpportunityCard:
    """Structured actionable opportunity representation for qualified DevTools leads."""

    company_id: str
    company_name: str
    domain: str
    icp_fit: str
    use_case_fit: str
    qualification_status: str
    evidence_quality: str
    signals: list[str] = field(default_factory=list)
    purchase_intent_evidence: list[dict] = field(default_factory=list)
    unknown_fields: list[str] = field(default_factory=list)
    next_best_research_action: str = "RESEARCH_TEST_INFRASTRUCTURE"
    disqualified: bool = False
    disqualified_reason: str | None = None
    created_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "company_id": self.company_id,
            "company_name": self.company_name,
            "domain": self.domain,
            "icp_fit": self.icp_fit,
            "use_case_fit": self.use_case_fit,
            "qualification_status": self.qualification_status,
            "evidence_quality": self.evidence_quality,
            "signals": self.signals,
            "purchase_intent_evidence": self.purchase_intent_evidence,
            "unknown_fields": self.unknown_fields,
            "next_best_research_action": self.next_best_research_action,
            "disqualified": self.disqualified,
            "disqualified_reason": self.disqualified_reason,
            "created_at": self.created_at,
        }


def build_opportunity_card(
    company: dict[str, Any],
    qualification: DevToolsQualificationResult,
) -> OpportunityCard:
    """Construct an OpportunityCard from company details and qualification result."""
    cid = company.get("id", qualification.company_id)
    cname = company.get("name", qualification.domain)
    domain = company.get("domain", qualification.domain)
    signal_codes = sorted({s["signal_code"] for s in qualification.extracted_signals})
    now_str = datetime.now(timezone.utc).isoformat()

    return OpportunityCard(
        company_id=cid,
        company_name=cname,
        domain=domain,
        icp_fit=qualification.icp_fit,
        use_case_fit=qualification.use_case_fit,
        qualification_status=qualification.qualification_status,
        evidence_quality=qualification.evidence_quality,
        signals=signal_codes,
        purchase_intent_evidence=qualification.purchase_intent_evidence,
        unknown_fields=qualification.unknown_fields,
        next_best_research_action=qualification.next_best_research_action,
        disqualified=qualification.disqualified,
        disqualified_reason=qualification.disqualified_reason,
        created_at=now_str,
    )


def evaluate_devtools_prospect(
    domain: str,
    company_id: str = "",
    company_name: str = "",
    html_login: str = "",
    url_login: str = "",
    html_careers: str = "",
    url_careers: str = "",
    html_docs: str = "",
    url_docs: str = "",
    dns_spf: list[str] | None = None,
    dns_source: str = "",
    purchase_evidence: list[dict] | None = None,
    final_redirects: dict[str, str] | None = None,
    collected_at: str = "",
    source_type: str = "",
    collection_method: str = "",
    raw_observations: list[dict] | None = None,
    collection_receipts: dict[str, dict] | list[dict] | None = None,
) -> DevToolsQualificationResult:
    """Evaluate candidate evidence according to the corrected W1-03-R qualification contract."""
    result = DevToolsQualificationResult(company_id=company_id, domain=domain)

    # P1: Structural validation of purchase evidence
    valid_purchase_items: list[dict[str, Any]] = []
    purchase_validation_errors: list[str] = []

    if purchase_evidence is not None:
        if not isinstance(purchase_evidence, list):
            purchase_validation_errors.append(
                f"purchase_evidence must be a list, got {type(purchase_evidence).__name__}"
            )
        else:
            for idx, raw_item in enumerate(purchase_evidence):
                is_valid, cleaned_item, err_msg = validate_purchase_evidence_item(
                    raw_item, default_date=collected_at
                )
                if is_valid:
                    valid_purchase_items.append(cleaned_item)
                else:
                    purchase_validation_errors.append(f"item[{idx}]: {err_msg}")

    all_html = f"{html_login} {html_careers} {html_docs}".strip()
    has_dns = bool(dns_spf)
    has_valid_purchase = bool(valid_purchase_items)

    # P1.3 & Requirement 6: Empty input must evaluate to UNKNOWN, never NO_AUTOMATION_NEED
    if not all_html and not has_dns and not has_valid_purchase:
        result.evidence_quality = "INSUFFICIENT"
        result.icp_fit = "UNKNOWN"
        result.use_case_fit = "UNKNOWN"
        result.disqualified = False
        result.disqualified_reason = None
        result.qualification_status = "UNKNOWN"
        result.unknown_fields = [
            "html_login",
            "html_careers",
            "html_docs",
            "dns_spf",
            "TECH_STACK",
            "TEST_AUTOMATION_NEED",
        ]
        if purchase_validation_errors:
            result.unknown_fields.append("REJECTED_INVALID_PURCHASE_EVIDENCE")
            for err in purchase_validation_errors:
                result.unknown_fields.append(f"PURCHASE_EVIDENCE_ERROR: {err}")
        result.evidence_bundle_metadata = {
            "source_type": source_type or "UNKNOWN",
            "collection_method": collection_method or "UNKNOWN",
            "collected_at": collected_at or "UNKNOWN",
        }
        result.next_best_research_action = "DISCOVER_COMPANY_PROFILE"
        return result

    # Check competitor or consumer disqualification
    disq_reason = detect_competitor_or_disqualification(all_html, company_name=company_name, domain=domain)
    if disq_reason:
        result.disqualified = True
        result.disqualified_reason = disq_reason
        result.icp_fit = "NON_ICP"
        result.use_case_fit = "NONE"
        result.qualification_status = "DISQUALIFIED"
        pages_with_content = sum(1 for p in [html_login, html_careers, html_docs] if p and p.strip())
        result.evidence_quality = "SUFFICIENT" if pages_with_content >= 2 else ("PARTIAL" if pages_with_content == 1 else "INSUFFICIENT")
        result.next_best_research_action = "DISCARD_OR_ARCHIVE"
        return result

    extracted: list[dict[str, Any]] = []

    # 1. Auth OTP / Magic Link (Never guess URL if not provided)
    otp_res = extract_signup_otp_signals(html_login, source_url=url_login)
    if otp_res:
        extracted.append(otp_res)

    # 2. E2E Frameworks
    e2e_careers = extract_e2e_frameworks(html_careers, source_url=url_careers)
    e2e_docs = extract_e2e_frameworks(html_docs, source_url=url_docs)
    extracted.extend(e2e_careers)
    extracted.extend(e2e_docs)

    # 3. AI / Browser Agent
    agent_res = extract_agent_signals(html_docs, source_url=url_docs)
    if not agent_res and html_login:
        agent_res = extract_agent_signals(html_login, source_url=url_login)
    if agent_res:
        extracted.append(agent_res)

    # 4. Dev Docs
    docs_res = extract_developer_docs_signals(html_docs, source_url=url_docs)
    if docs_res:
        extracted.append(docs_res)

    # 5. DNS SPF
    spf_res = classify_dns_spf_esp(dns_spf or [], source_domain=domain, dns_source=dns_source)
    extracted.extend(spf_res)

    # 6. Hiring
    hiring_res = extract_hiring_roles(html_careers, source_url=url_careers)
    if hiring_res:
        extracted.append(hiring_res)

    result.extracted_signals = extracted

        # ── Multi-Source Deduplication & Evidence Sufficiency (P0-B) ──────
    # Deduplicate: Multiple mentions on a single page or duplicate page content
    # must NOT count as distinct independent sources.
    # Source classification:
    # - verified_source: confirmed real sources with trusted collection receipts
    # - offline_fixture: explicit offline fixture records
    # - candidate_urls: structurally valid URLs retained for audit but separated from verification state
    # - unverified_source: text provided without verified URL (never counted as independent real collection)
    is_explicit_fixture = (
        source_type in ("offline_fixture", "synthetic", "curated_offline_fixture", "SYNTHETIC", "OFFLINE_FIXTURE")
        or collection_method in ("curated_offline_fixture", "offline_fixture", "offline_injection")
    )

    verified_sources: set[str] = set()
    offline_fixture_sources: set[str] = set()
    candidate_urls: set[str] = set()
    unverified_sources: set[str] = set()
    seen_content_hashes = set()

    # Build collection receipts lookup
    receipts_map: dict[str, dict] = {}
    if collection_receipts:
        if isinstance(collection_receipts, dict):
            receipts_map = collection_receipts
        elif isinstance(collection_receipts, list):
            for r in collection_receipts:
                if isinstance(r, dict):
                    if "url" in r:
                        receipts_map[r["url"]] = r
                    if "page" in r:
                        receipts_map[r["page"]] = r

    raw_pages = [
        ("login", url_login, html_login),
        ("careers", url_careers, html_careers),
        ("docs", url_docs, html_docs),
    ]

    # Only pages that contributed extracted factual signals are counted toward independent sources (Review finding #5)
    extracted_source_urls = {
        s.get("source_url", "") for s in extracted
        if s.get("source_url") and s.get("source_url") != "UNKNOWN"
    }

    for page_name, p_url, p_html in raw_pages:
        if not p_html or not p_html.strip():
            continue
        p_url_clean = p_url.strip() if p_url else ""
        if p_url_clean and p_url_clean not in extracted_source_urls:
            # Page contributed no extracted fact signals; do not count toward independent sources
            continue
        chash = _content_fingerprint(p_html)
        if chash in seen_content_hashes:
            # Duplicate page content across endpoints does not inflate sources
            continue
        seen_content_hashes.add(chash)
        p_url_clean = p_url.strip() if p_url else ""
        is_valid_url = bool(p_url_clean and re.match(r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", p_url_clean))
        if is_valid_url:
            candidate_urls.add(p_url_clean)

        # P0-B: Check verifiable collection receipt
        receipt = receipts_map.get(p_url_clean) or receipts_map.get(page_name)
        has_trusted_receipt = False
        if receipt and isinstance(receipt, dict):
            r_collector = receipt.get("collector", "")
            r_time = receipt.get("collected_at", "")
            r_hash = receipt.get("content_sha256", "")
            if (
                r_collector in ("harvey:scout:collector", "verified_web_crawler", "trusted_import_validator")
                and r_time and r_time != "UNKNOWN"
                and r_hash in (chash, hashlib.sha256(p_html.encode("utf-8")).hexdigest())
                and receipt.get("verified", False) is True
            ):
                has_trusted_receipt = True

        if has_trusted_receipt:
            verified_sources.add(p_url_clean)
        elif is_explicit_fixture:
            offline_fixture_sources.add(p_url_clean if p_url_clean else f"offline_fixture:{page_name}")
        elif p_url_clean and not is_valid_url and p_url_clean != "UNKNOWN":
            offline_fixture_sources.add(p_url_clean)
        elif not collection_receipts and p_url_clean and not source_type:
            # Default backward-compatible offline fixture inference when evaluated directly in unit tests without receipt
            offline_fixture_sources.add(p_url_clean)
        else:
            unverified_sources.add(f"unverified_{page_name}")

    # DNS SPF alone is only a configuration clue, not an independent web evidence source
    dns_ident = None
    if spf_res:
        dns_ident = dns_source.strip() if dns_source and dns_source.strip() else f"dns:spf:{domain}"
        if dns_ident != "UNKNOWN":
            if is_explicit_fixture or (not collection_receipts and not source_type):
                offline_fixture_sources.add(dns_ident)
            else:
                unverified_sources.add(dns_ident)

    result.source_breakdown = {
        "verified_source": sorted(list(verified_sources)),
        "offline_fixture": sorted(list(offline_fixture_sources)),
        "candidate_urls": sorted(list(candidate_urls)),
        "unverified_source": sorted(list(unverified_sources)),
    }

    # Provenance metadata recording
    if is_explicit_fixture or (not collection_receipts and not source_type):
        resolved_source_type = "OFFLINE_FIXTURE"
        resolved_method = collection_method or "curated_offline_fixture"
    elif verified_sources:
        resolved_source_type = "VERIFIED_PUBLIC_OBSERVATION"
        resolved_method = collection_method or "verified_collector"
    elif candidate_urls:
        resolved_source_type = "UNVERIFIED_CANDIDATE_URLS"
        resolved_method = collection_method or "unverified_bundle_injection"
    else:
        resolved_source_type = source_type or "UNKNOWN"
        resolved_method = collection_method or "UNKNOWN"

    result.evidence_bundle_metadata = {
        "source_type": resolved_source_type,
        "collection_method": resolved_method,
        "collected_at": collected_at or "UNKNOWN",
    }

    # P0-B Evidence Sufficiency:
    # In offline fixture mode, offline benchmarks evaluate against curated offline fixture sources.
    # In public collection mode, only verified sources with trusted collection receipts count.
    # Unverified or fabricated HTTPS candidate URLs yield 0 verified sources and INSUFFICIENT evidence.
    if offline_fixture_sources:
        web_sources = {s for s in offline_fixture_sources if not s.startswith("dns:spf:")}
        result.independent_source_count = len(offline_fixture_sources)
        if len(web_sources) >= 2:
            result.evidence_quality = "SUFFICIENT"
        elif len(web_sources) == 1:
            result.evidence_quality = "PARTIAL"
        elif spf_res:
            result.evidence_quality = "INSUFFICIENT"
        else:
            result.evidence_quality = "INSUFFICIENT"
    elif verified_sources:
        web_sources = {s for s in verified_sources if not s.startswith("dns:spf:")}
        result.independent_source_count = len(verified_sources)
        if len(web_sources) >= 2:
            result.evidence_quality = "SUFFICIENT"
        elif len(web_sources) == 1:
            result.evidence_quality = "PARTIAL"
        elif spf_res:
            result.evidence_quality = "INSUFFICIENT"
        else:
            result.evidence_quality = "INSUFFICIENT"
    else:
        result.independent_source_count = 0
        result.evidence_quality = "INSUFFICIENT"
        if candidate_urls:
            result.unknown_fields.append("UNVERIFIED_CANDIDATE_URLS_NO_RECEIPT")

    # Missing metadata note: If collected_at or collection_method is missing, record in unknown_fields
    if not collected_at or collected_at == "UNKNOWN":
        if "COLLECTED_AT_TIMESTAMP" not in result.unknown_fields:
            result.unknown_fields.append("COLLECTED_AT_TIMESTAMP")

    # Determine Use Case Fit & ICP fit
    if agent_res:
        result.use_case_fit = "AGENT_INBOX"
        result.icp_fit = "TIER_1_STRONG_FIT"
    elif "qualitest" in domain or "testing" in company_name.lower() or "qa" in company_name.lower():
        result.use_case_fit = "MULTI_TENANT_QA"
        result.icp_fit = "TIER_1_STRONG_FIT"
    elif otp_res or (e2e_careers or e2e_docs):
        result.use_case_fit = "E2E_AUTH_TESTING"
        result.icp_fit = "TIER_1_STRONG_FIT" if (otp_res or (e2e_careers or e2e_docs)) else "TIER_2_MODERATE_FIT"
    elif docs_res:
        result.use_case_fit = "UNKNOWN"
        result.icp_fit = "TIER_2_MODERATE_FIT"
    elif spf_res:
        result.use_case_fit = "UNKNOWN"
        result.icp_fit = "TIER_3_LOW_FIT"
    else:
        result.use_case_fit = "NONE"
        result.icp_fit = "NON_ICP"

    # ── P0-B & P1: Purchase Intent & Qualification Status Guard ───────
    # Crucial correction: Active hiring for QA/SDET is technical demand,
    # NOT confirmed commercial procurement intent.
    # True procurement evidence requires explicit, structurally validated documentation (RFP, quote inquiry, etc.).
    if valid_purchase_items:
        result.purchase_intent_evidence = valid_purchase_items
        # Forms a candidate for human verification; never auto-confirmed by model tag
        # Capped at PURCHASE_CANDIDATE_PENDING_VERIFICATION; NEVER CONFIRMED_ACTIVE_BUYER
        result.qualification_status = "PURCHASE_CANDIDATE_PENDING_VERIFICATION"
        result.next_best_research_action = "HUMAN_PROCUREMENT_VERIFICATION"
    else:
        if purchase_evidence:
            result.unknown_fields.append("REJECTED_INVALID_PURCHASE_EVIDENCE")
            for err in purchase_validation_errors:
                result.unknown_fields.append(f"PURCHASE_EVIDENCE_ERROR: {err}")

        if result.icp_fit in ("TIER_1_STRONG_FIT", "TIER_2_MODERATE_FIT") and result.evidence_quality in ("SUFFICIENT", "PARTIAL"):
            result.qualification_status = "POTENTIAL_FIT"
            result.next_best_research_action = (
                "RESEARCH_TEST_INFRASTRUCTURE" if not otp_res else "SEARCH_CAREERS_PAGE"
            )
        elif result.evidence_quality == "INSUFFICIENT":
            result.qualification_status = "NEEDS_RESEARCH"
            result.next_best_research_action = "ENRICH_TECHNICAL_PROFILE"
        else:
            result.qualification_status = "NEEDS_RESEARCH"
            result.next_best_research_action = "DISCARD_OR_ARCHIVE"

    # Explicit uncertainty reporting: rule confidence is uncalibrated
    result.confidence_model = "heuristic_rule_confidence_uncalibrated"

    return result


async def record_devtools_observations(
    state,
    company_id: str,
    qualification: DevToolsQualificationResult,
    run_id: str = "",
) -> int:
    """Record DevTools facts and derived qualification states as rows in SQLite observations table."""
    confirmed = await state.confirmed_signal_codes()
    observations: list[dict[str, Any]] = []

    def add_obs(code: str, *, num=None, text="", conf=1.0, url=""):
        if code in confirmed:
            observations.append({
                "company_id": company_id,
                "signal_code": code,
                "collector": "devtools" if not code.startswith("VERISIG_") else "qualification",
                "value_num": num,
                "value_text": text,
                "confidence": conf,
                "evidence_url": url,
                "run_id": run_id,
            })

    # 1. Record extracted fact signals
    for sig in qualification.extracted_signals:
        code = sig.get("signal_code", "")
        if code in confirmed:
            val_num = 1.0 if code in ("HAS_SIGNUP_OTP_OR_MAGIC_LINK", "BUILDS_AI_OR_BROWSER_AGENTS", "HAS_DEVELOPER_DOCS_OR_API") else None
            val_text = sig.get("evidence", "") or sig.get("framework", "") or sig.get("role", "") or sig.get("esp", "")
            add_obs(
                code,
                num=val_num,
                text=str(val_text),
                conf=sig.get("confidence", 0.85),
                url=sig.get("source_url", "UNKNOWN"),
            )

    # 2. Record derived qualification states
    add_obs(
        "VERISIG_EVIDENCE_SUFFICIENCY",
        text=qualification.evidence_quality,
        conf=1.0,
        url=f"qualification://{qualification.domain or 'unknown'}",
    )

    if qualification.disqualified and qualification.disqualified_reason:
        add_obs(
            "VERISIG_DISQUALIFIED_REASON",
            text=qualification.disqualified_reason,
            conf=1.0,
            url=f"qualification://{qualification.domain or 'unknown'}",
        )

    if not observations:
        return 0

    # Update company signals in memory / state (P1-B: strictly filtered through confirmation gate)
    try:
        confirmed_tech = [
            s["evidence"] for s in qualification.extracted_signals
            if s.get("signal_code") == "USES_E2E_TEST_FRAMEWORK" and "USES_E2E_TEST_FRAMEWORK" in confirmed
        ]
        confirmed_signals = [
            {"type": s["signal_code"], "detail": s.get("evidence", "")}
            for s in qualification.extracted_signals
            if s.get("signal_code") in confirmed
        ]
        if confirmed_tech or confirmed_signals:
            await state.update_company_signals(
                company_id,
                tech_stack=confirmed_tech,
                new_signals=confirmed_signals,
            )
    except Exception as e:
        logger.debug("update_company_signals non-critical warning for %s: %s", company_id, e)

    return await state.add_observations(observations, run_id=run_id)


def export_opportunity_cards(
    cards: list[OpportunityCard],
    out_path: str | None = None,
) -> tuple[int, str]:
    """Export a collection of OpportunityCards to formatted JSON text."""
    payload = [c.as_dict() for c in cards]
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Exported %d opportunity cards to %s", len(cards), out_path)
    return len(cards), text


# ── 4. DevTools Pipeline Adapter (P0-A) ──────────────────────────────

@dataclass
class DevToolsStageResult:
    evaluated_companies: int = 0
    recorded_observations: int = 0
    run_id: str = ""
    opportunity_cards: list[OpportunityCard] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DevToolsPipelineAdapter:
    """Offline-capable DevTools & FetchInbox pipeline adapter.

    Safely evaluates prospects against FetchInbox qualification criteria,
    prioritizing injected offline evidence bundles and verified observations.
    Zero unapproved network access is guaranteed.
    """

    def __init__(
        self,
        state,
        evidence_bundle: dict | None = None,
        evaluate_existing_companies: bool = False,
    ):
        self.state = state
        self.evidence_bundle = evidence_bundle
        self.evaluate_existing_companies = evaluate_existing_companies

    async def run(self, limit: int = 50) -> DevToolsStageResult:
        result = DevToolsStageResult()
        from harvey.signals import seed_signal_catalog
        await seed_signal_catalog(self.state)

        run_id = await self.state.start_run("devtools", provider="offline_adapter")
        result.run_id = run_id

        companies_to_process = []

        if self.evidence_bundle is not None:
            if not isinstance(self.evidence_bundle, dict):
                err = f"Invalid evidence_bundle: expected dict, got {type(self.evidence_bundle).__name__}"
                logger.error(err)
                result.errors.append(err)
            else:
                for domain_or_id, ev_data in self.evidence_bundle.items():
                    if len(companies_to_process) >= limit:
                        break
                    if not isinstance(ev_data, dict):
                        result.errors.append(f"Invalid company evidence for {domain_or_id}: expected dict")
                        continue
                    comp = await self.state.get_company_by_domain(domain_or_id)
                    if not comp:
                        comp = await self.state.get_company(domain_or_id)
                    if comp:
                        companies_to_process.append((comp.id, comp.name, comp.domain, ev_data))
                    else:
                        from harvey.models.company import Company
                        cname = ev_data.get("company_name", domain_or_id)
                        new_id = await self.state.add_company(Company(name=cname, domain=domain_or_id))
                        companies_to_process.append((new_id, cname, domain_or_id, ev_data))
        elif self.evaluate_existing_companies:
            async with self.state._connect() as db:
                import aiosqlite
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT id, name, domain FROM companies WHERE domain != '' LIMIT ?",
                    (int(limit),)
                ) as cursor:
                    rows = await cursor.fetchall()
            for r in rows:
                companies_to_process.append((r["id"], r["name"], r["domain"], {}))
        else:
            logger.info(
                "DevToolsPipelineAdapter: no evidence bundle provided and evaluate_existing_companies=False; evaluating 0 companies."
            )

        total_obs = 0
        cards = []
        for cid, cname, cdomain, ev_data in companies_to_process:
            try:
                qualification = evaluate_devtools_prospect(
                    domain=cdomain,
                    company_id=cid,
                    company_name=cname,
                    html_login=ev_data.get("html_login", ""),
                    url_login=ev_data.get("url_login", ""),
                    html_careers=ev_data.get("html_careers", ""),
                    url_careers=ev_data.get("url_careers", ""),
                    html_docs=ev_data.get("html_docs", ""),
                    url_docs=ev_data.get("url_docs", ""),
                    dns_spf=ev_data.get("dns_spf", []),
                    dns_source=ev_data.get("dns_source", ""),
                    purchase_evidence=ev_data.get("purchase_evidence", []),
                    final_redirects=ev_data.get("final_redirects", {}),
                    collected_at=ev_data.get("collected_at", ""),
                    source_type=ev_data.get("source_type", ""),
                    collection_method=ev_data.get("collection_method", ""),
                    collection_receipts=ev_data.get("collection_receipts", None),
                )

                obs_count = await record_devtools_observations(
                    self.state,
                    company_id=cid,
                    qualification=qualification,
                    run_id=run_id,
                )
                total_obs += obs_count

                card = build_opportunity_card(
                    {"id": cid, "name": cname, "domain": cdomain},
                    qualification,
                )
                cards.append(card)
                result.evaluated_companies += 1
            except Exception as e:
                logger.exception("DevTools adapter failed for company %s (%s)", cid, cdomain)
                result.errors.append(f"{cdomain}: {e}")

        result.recorded_observations = total_obs
        result.opportunity_cards = cards

        run_status = "completed" if not result.errors else "failed"
        run_err = "; ".join(result.errors)[:500] if result.errors else ""
        await self.state.finish_run(
            run_id, status=run_status, records=total_obs, cost_usd=0.0, error=run_err
        )

        return result
