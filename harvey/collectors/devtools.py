"""DevTools & B2B SaaS Collector and Offline Feature Extractors (W1-03).

This collector extracts concrete, verifiable engineering facts for FetchInbox:
1. HAS_SIGNUP_OTP_OR_MAGIC_LINK (Auth flows requiring email codes / magic links)
2. USES_E2E_TEST_FRAMEWORK (Playwright, Cypress, Selenium, Puppeteer)
3. BUILDS_AI_OR_BROWSER_AGENTS (Autonomous web agents, browser automation, computer-use)
4. HAS_DEVELOPER_DOCS_OR_API (Public API docs, SDK references, developer hubs)
5. USES_TRANSACTIONAL_EMAIL_ESP (Postmark, SendGrid, Resend, Mailgun, AWS SES)
6. HIRING_QA_OR_AGENT_INFRA (Active hiring for QA automation, SDETs, Agent infra)
7. VERISIG_EVIDENCE_SUFFICIENCY (Qualification sufficiency assessment)
8. VERISIG_DISQUALIFIED_REASON (Deterministic disqualification reason)

Design principles:
- 100% offline testable pure functions.
- Multi-source evidence tracking: multiple occurrences on the same page do NOT count as multiple independent sources.
- Safe-by-default: zero network access during evaluation tests.
- Reuses Harvey models, state and observations interface.
"""

import logging
import re
from dataclasses import dataclass, field
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

# Stale / Closed indicators in job postings
CLOSED_JOB_MARKERS = [
    re.compile(r"\b(?:closed|filled|expired|inactive|archive[d]?|no\s+longer\s+accepting)\b", re.I),
    re.compile(r"\bposition\s+(?:is\s+)?closed\b", re.I),
    re.compile(r"\bcurrently\s+not\s+hiring\b", re.I),
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
    re.compile(r"\b(?:apparel|clothing|fashion|shoes|jewelry|furniture|restaurant|bakery|dental|dentist|clinic|plumbing|roofing)\b", re.I),
    re.compile(r"\bcart\s+checkout\b", re.I),
    re.compile(r"\bshopping\s+bag\b", re.I),
]


# ── 2. Pure Extraction Functions ─────────────────────────────────────

def extract_signup_otp_signals(html: str, source_url: str = "") -> dict[str, Any] | None:
    """Extract OTP or magic link authentication indicators from login/signup HTML."""
    if not html:
        return None
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
            "source_url": source_url,
            "confidence": 0.85,
        }
    return None


def extract_e2e_frameworks(text: str, source_url: str = "") -> list[dict[str, Any]]:
    """Detect Playwright, Cypress, Selenium, or Puppeteer mentions."""
    if not text:
        return []
    found = []
    for name, pattern in E2E_FRAMEWORKS.items():
        if pattern.search(text):
            found.append({
                "signal_code": "USES_E2E_TEST_FRAMEWORK",
                "framework": name,
                "source_url": source_url,
                "confidence": 0.85,
            })
    return found


def extract_agent_signals(text: str, source_url: str = "") -> dict[str, Any] | None:
    """Detect AI browser agents or computer-use automation features."""
    if not text:
        return None
    for pattern in AI_AGENT_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "signal_code": "BUILDS_AI_OR_BROWSER_AGENTS",
                "detected": True,
                "evidence": m.group(0),
                "source_url": source_url,
                "confidence": 0.85,
            }
    return None


def extract_developer_docs_signals(text: str, source_url: str = "") -> dict[str, Any] | None:
    """Detect developer documentation or API references."""
    if not text:
        return None
    for pattern in DEV_DOCS_PATTERNS:
        m = pattern.search(text)
        if m:
            return {
                "signal_code": "HAS_DEVELOPER_DOCS_OR_API",
                "detected": True,
                "evidence": m.group(0),
                "source_url": source_url,
                "confidence": 0.90,
            }
    return None


def classify_dns_spf_esp(spf_records: list[str], source_domain: str = "") -> list[dict[str, Any]]:
    """Identify transactional email provider footprints from SPF/TXT records."""
    if not spf_records:
        return []
    combined = " ".join(spf_records)
    hits = []
    for esp_name, pattern in TRANSACTIONAL_ESPS.items():
        if pattern.search(combined):
            hits.append({
                "signal_code": "USES_TRANSACTIONAL_EMAIL_ESP",
                "esp": esp_name,
                "source_url": f"dns:spf:{source_domain}",
                "confidence": 0.70,
            })
    return hits


def extract_hiring_roles(html: str, source_url: str = "") -> dict[str, Any] | None:
    """Identify active QA or Agent infrastructure job postings, filtering out stale/closed posts."""
    if not html:
        return None

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
                "source_url": source_url,
                "confidence": 0.80,
                "is_active": True,
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
    icp_fit: str = "NON_ICP"               # TIER_1_STRONG_FIT | TIER_2_MODERATE_FIT | TIER_3_LOW_FIT | NON_ICP
    use_case_fit: str = "NONE"             # AGENT_INBOX | E2E_AUTH_TESTING | MULTI_TENANT_QA | NONE | UNKNOWN
    evidence_quality: str = "INSUFFICIENT" # SUFFICIENT | PARTIAL | INSUFFICIENT | CONFLICTING
    purchase_intent_evidence: list[dict] = field(default_factory=list)
    disqualified: bool = False
    disqualified_reason: str | None = None
    unknown_fields: list[str] = field(default_factory=list)
    next_best_research_action: str = "DISCARD_OR_ARCHIVE"
    qualification_status: str = "POTENTIAL_FIT" # CONFIRMED_ACTIVE_BUYER | POTENTIAL_FIT | NEEDS_REVIEW | DISQUALIFIED

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
        }


def evaluate_devtools_prospect(
    domain: str,
    company_id: str = "",
    company_name: str = "",
    html_login: str = "",
    html_careers: str = "",
    html_docs: str = "",
    dns_spf: list[str] | None = None,
    raw_observations: list[dict] | None = None,
) -> DevToolsQualificationResult:
    """Evaluate candidate evidence according to the W1-03 qualification contract."""
    result = DevToolsQualificationResult(company_id=company_id, domain=domain)

    # Check disqualification first
    all_html = f"{html_login} {html_careers} {html_docs}"
    disq_reason = detect_competitor_or_disqualification(all_html, company_name=company_name, domain=domain)
    if disq_reason:
        result.disqualified = True
        result.disqualified_reason = disq_reason
        result.icp_fit = "NON_ICP"
        result.use_case_fit = "NONE"
        result.qualification_status = "DISQUALIFIED"
        result.next_best_research_action = "DISCARD_OR_ARCHIVE"
        return result

    # Check for empty text / empty content
    if not all_html.strip() and not (dns_spf or []):
        result.evidence_quality = "INSUFFICIENT"
        result.icp_fit = "NON_ICP"
        result.use_case_fit = "NONE"
        result.disqualified = True
        result.disqualified_reason = "NO_AUTOMATION_NEED"
        result.qualification_status = "DISQUALIFIED"
        return result

    # Multi-source evidence tracking (group by distinct source URL / origin)
    evidence_sources: dict[str, list[str]] = {}

    def record_source(url_key: str, item_desc: str):
        if not url_key:
            url_key = "default_site"
        evidence_sources.setdefault(url_key, []).append(item_desc)

    # 1. Auth OTP / Magic Link
    otp_res = extract_signup_otp_signals(html_login, source_url=f"https://{domain}/login")
    if otp_res:
        record_source(f"https://{domain}/login", "HAS_SIGNUP_OTP_OR_MAGIC_LINK")

    # 2. E2E Frameworks
    e2e_res = (
        extract_e2e_frameworks(html_careers, source_url=f"https://{domain}/careers") +
        extract_e2e_frameworks(html_docs, source_url=f"https://{domain}/docs")
    )
    for item in e2e_res:
        record_source(item["source_url"], f"USES_E2E_TEST_FRAMEWORK:{item['framework']}")

    # 3. AI / Browser Agent
    agent_res = extract_agent_signals(html_docs, source_url=f"https://{domain}/docs")
    if agent_res:
        record_source(f"https://{domain}/docs", "BUILDS_AI_OR_BROWSER_AGENTS")
    else:
        # Check login or homepage
        agent_res_home = extract_agent_signals(html_login, source_url=f"https://{domain}/login")
        if agent_res_home:
            record_source(f"https://{domain}/login", "BUILDS_AI_OR_BROWSER_AGENTS")
            agent_res = agent_res_home

    # 4. Dev Docs
    docs_res = extract_developer_docs_signals(html_docs, source_url=f"https://{domain}/docs")
    if docs_res:
        record_source(f"https://{domain}/docs", "HAS_DEVELOPER_DOCS_OR_API")

    # 5. DNS SPF
    spf_res = classify_dns_spf_esp(dns_spf or [], source_domain=domain)
    for item in spf_res:
        record_source(f"dns:spf:{domain}", f"USES_TRANSACTIONAL_EMAIL_ESP:{item['esp']}")

    # 6. Hiring
    hiring_res = extract_hiring_roles(html_careers, source_url=f"https://{domain}/careers")
    if hiring_res:
        record_source(f"https://{domain}/careers", f"HIRING_QA_OR_AGENT_INFRA:{hiring_res['role']}")

    # Assess Evidence Sufficiency (Distinct Independent Sources)
    # Note: Only distinct non-empty sources count!
    independent_source_count = len(evidence_sources)

    if independent_source_count >= 2:
        result.evidence_quality = "SUFFICIENT"
    elif independent_source_count == 1:
        # If the only source is DNS SPF, it is merely a technical lead, never sufficient
        if list(evidence_sources.keys())[0].startswith("dns:spf"):
            result.evidence_quality = "INSUFFICIENT"
        else:
            result.evidence_quality = "PARTIAL"
    else:
        result.evidence_quality = "INSUFFICIENT"

    # Determine Use Case Fit and ICP fit
    if agent_res:
        result.use_case_fit = "AGENT_INBOX"
        result.icp_fit = "TIER_1_STRONG_FIT"
    elif "qualitest" in domain or "testing" in company_name.lower() or "qa" in company_name.lower():
        result.use_case_fit = "MULTI_TENANT_QA"
        result.icp_fit = "TIER_1_STRONG_FIT"
    elif otp_res or any("USES_E2E_TEST_FRAMEWORK" in str(v) for v in evidence_sources.values()):
        result.use_case_fit = "E2E_AUTH_TESTING"
        result.icp_fit = "TIER_1_STRONG_FIT" if (otp_res or any("USES_E2E_TEST_FRAMEWORK" in str(v) for v in evidence_sources.values())) else "TIER_2_MODERATE_FIT"
    elif docs_res:
        result.use_case_fit = "UNKNOWN"
        result.icp_fit = "TIER_2_MODERATE_FIT"
    else:
        result.use_case_fit = "NONE"
        result.icp_fit = "NON_ICP"

    # Determine Purchase Intent Evidence
    intent_items = []
    if hiring_res and hiring_res.get("is_active"):
        intent_items.append({
            "signal_code": "HIRING_QA_OR_AGENT_INFRA",
            "summary": f"Active hiring for {hiring_res['role']}",
            "source_url": hiring_res["source_url"],
            "confidence": hiring_res["confidence"],
        })
    result.purchase_intent_evidence = intent_items

    # Guard: Active buyer status requires SUFFICIENT evidence AND verified intent items
    if result.evidence_quality == "SUFFICIENT" and intent_items:
        result.qualification_status = "CONFIRMED_ACTIVE_BUYER"
        result.next_best_research_action = "READY_FOR_OUTREACH"
    elif result.icp_fit in ("TIER_1_STRONG_FIT", "TIER_2_MODERATE_FIT"):
        result.qualification_status = "POTENTIAL_FIT"
        result.next_best_research_action = "INSPECT_SIGNUP_FLOW" if not otp_res else "SEARCH_CAREERS_PAGE"
    else:
        result.qualification_status = "NEEDS_REVIEW"
        result.next_best_research_action = "DISCARD_OR_ARCHIVE"

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

    # Record derived qualification states
    add_obs(
        "VERISIG_EVIDENCE_SUFFICIENCY",
        text=qualification.evidence_quality,
        conf=1.0,
        url=f"qualification://{qualification.domain}",
    )

    if qualification.disqualified and qualification.disqualified_reason:
        add_obs(
            "VERISIG_DISQUALIFIED_REASON",
            text=qualification.disqualified_reason,
            conf=1.0,
            url=f"qualification://{qualification.domain}",
        )

    if not observations:
        return 0

    return await state.add_observations(observations, run_id=run_id)
