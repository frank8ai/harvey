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

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

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
        if pattern.search(text):
            found.append({
                "signal_code": "USES_E2E_TEST_FRAMEWORK",
                "framework": name,
                "evidence": name,
                "source_url": url,
                "confidence": 0.85,
                "snippet_hash": _content_fingerprint(name),
            })
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

    # Check if the page is completely closed or archived
    for closed_pat in CLOSED_JOB_MARKERS:
        if closed_pat.search(html):
            return None

    # Check for matching roles
    for role_pat in QA_AGENT_ROLES:
        m = role_pat.search(html)
        if m:
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
    raw_observations: list[dict] | None = None,
) -> DevToolsQualificationResult:
    """Evaluate candidate evidence according to the corrected W1-03-R qualification contract."""
    result = DevToolsQualificationResult(company_id=company_id, domain=domain)

    all_html = f"{html_login} {html_careers} {html_docs}".strip()
    has_dns = bool(dns_spf)
    has_purchase = bool(purchase_evidence)

    # P1.3 & Requirement 6: Empty input must evaluate to UNKNOWN, never NO_AUTOMATION_NEED
    if not all_html and not has_dns and not has_purchase:
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
        result.evidence_quality = "SUFFICIENT" if all_html else "PARTIAL"
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

    # ── Multi-Source Deduplication & Evidence Sufficiency ──────────────
    # Deduplicate: Multiple mentions on a single page or duplicate page content
    # must NOT count as distinct independent sources.
    verified_sources = set()
    seen_content_hashes = set()

    raw_pages = [
        ("login", url_login, html_login),
        ("careers", url_careers, html_careers),
        ("docs", url_docs, html_docs),
    ]

    for page_name, p_url, p_html in raw_pages:
        if not p_html or not p_html.strip():
            continue
        chash = _content_fingerprint(p_html)
        if chash in seen_content_hashes:
            # Duplicate page content across endpoints does not inflate sources
            continue
        seen_content_hashes.add(chash)
        if p_url and p_url != "UNKNOWN":
            verified_sources.add(p_url)
        else:
            verified_sources.add(f"unverified_source_{page_name}")

    # DNS SPF alone is only a configuration clue, not an independent web evidence source
    if spf_res and len(verified_sources) > 0:
        verified_sources.add("dns_spf_config")

    source_count = len(verified_sources)
    result.independent_source_count = source_count

    if source_count >= 2:
        result.evidence_quality = "SUFFICIENT"
    elif source_count == 1:
        if spf_res and not all_html:
            result.evidence_quality = "INSUFFICIENT"
        else:
            result.evidence_quality = "PARTIAL"
    else:
        result.evidence_quality = "INSUFFICIENT"

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

    # ── P0-B: Purchase Intent & Qualification Status Guard ─────────────
    # Crucial correction: Active hiring for QA/SDET is technical demand,
    # NOT confirmed commercial procurement intent.
    # True procurement evidence requires explicit documentation (RFP, quote inquiry, etc.).
    if purchase_evidence:
        result.purchase_intent_evidence = purchase_evidence
        # Forms a candidate for human verification; never auto-confirmed by model tag
        result.qualification_status = "PURCHASE_CANDIDATE_PENDING_VERIFICATION"
        result.next_best_research_action = "HUMAN_PROCUREMENT_VERIFICATION"
    elif result.icp_fit in ("TIER_1_STRONG_FIT", "TIER_2_MODERATE_FIT") and result.evidence_quality in ("SUFFICIENT", "PARTIAL"):
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

    # Update company signals in memory / state
    try:
        await state.update_company_signals(
            company_id,
            tech_stack=[s["evidence"] for s in qualification.extracted_signals if s.get("signal_code") == "USES_E2E_TEST_FRAMEWORK"],
            new_signals=[
                {"type": s["signal_code"], "detail": s.get("evidence", "")}
                for s in qualification.extracted_signals
            ],
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

    def __init__(self, state, evidence_bundle: dict | None = None):
        self.state = state
        self.evidence_bundle = evidence_bundle or {}

    async def run(self, limit: int = 50) -> DevToolsStageResult:
        result = DevToolsStageResult()
        from harvey.signals import seed_signal_catalog
        await seed_signal_catalog(self.state)

        run_id = await self.state.start_run("devtools", provider="offline_adapter")
        result.run_id = run_id

        companies_to_process = []

        if self.evidence_bundle:
            for domain_or_id, ev_data in self.evidence_bundle.items():
                if len(companies_to_process) >= limit:
                    break
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
        else:
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
