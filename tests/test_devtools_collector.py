import json
import os
import pytest
from pathlib import Path

from harvey.collectors.devtools import (
    extract_signup_otp_signals,
    extract_e2e_frameworks,
    extract_agent_signals,
    extract_developer_docs_signals,
    classify_dns_spf_esp,
    extract_hiring_roles,
    detect_competitor_or_disqualification,
    evaluate_devtools_prospect,
    record_devtools_observations,
    build_opportunity_card,
    export_opportunity_cards,
    DevToolsPipelineAdapter,
)
from harvey.signals import seed_signal_catalog
from harvey.state import StateManager
from harvey.models import Company


@pytest.fixture
def offline_fixtures():
    fixtures_path = Path(__file__).parent.parent / "fixtures" / "devtools" / "offline_samples.json"
    with open(fixtures_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Requirement 1 & P0-B: Strong technical match is POTENTIAL_FIT, NOT CONFIRMED_ACTIVE_BUYER ──
def test_strong_tech_match_evaluates_to_potential_fit(offline_fixtures):
    sample = offline_fixtures["saas_with_otp"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
        dns_source=sample["dns_source"],
    )
    assert res.icp_fit == "TIER_1_STRONG_FIT"
    assert res.use_case_fit == "E2E_AUTH_TESTING"
    assert res.evidence_quality == "SUFFICIENT"
    # Strict correction: Active hiring does NOT grant CONFIRMED_ACTIVE_BUYER
    assert res.qualification_status == "POTENTIAL_FIT"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res.next_best_research_action != "READY_FOR_OUTREACH"
    assert not res.disqualified


def test_positive_ai_browser_agent(offline_fixtures):
    sample = offline_fixtures["ai_browser_agent"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
        dns_source=sample["dns_source"],
    )
    assert res.icp_fit == "TIER_1_STRONG_FIT"
    assert res.use_case_fit == "AGENT_INBOX"
    assert res.evidence_quality == "SUFFICIENT"
    # Strict correction: Technical agent capabilities alone do not equal active buyer
    assert res.qualification_status == "POTENTIAL_FIT"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert not res.disqualified


# ── Requirement 2: Explicit procurement documentation forms human verification candidate ──
def test_explicit_procurement_documentation_requires_human_verification(offline_fixtures):
    sample = offline_fixtures["procurement_candidate"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
        dns_source=sample["dns_source"],
        purchase_evidence=sample["purchase_evidence"],
    )
    assert res.qualification_status == "PURCHASE_CANDIDATE_PENDING_VERIFICATION"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res.next_best_research_action == "HUMAN_PROCUREMENT_VERIFICATION"
    assert len(res.purchase_intent_evidence) == 1


# ── Requirement 3: Negative samples NOT misclassified as buyers ───────
def test_competitor_disqualified(offline_fixtures):
    sample = offline_fixtures["direct_competitor"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
    )
    assert res.disqualified is True
    assert res.disqualified_reason == "DIRECT_COMPETITOR"
    assert res.qualification_status == "DISQUALIFIED"
    assert res.icp_fit == "NON_ICP"


def test_consumer_retail_disqualified(offline_fixtures):
    sample = offline_fixtures["consumer_fashion"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
    )
    assert res.disqualified is True
    assert res.disqualified_reason == "CONSUMER_ONLY"
    assert res.qualification_status == "DISQUALIFIED"


# ── Requirement 4: Empty input must evaluate to UNKNOWN, never NO_AUTOMATION_NEED ──
def test_empty_input_evaluates_to_unknown_never_no_automation_need():
    res = evaluate_devtools_prospect(
        domain="blank-placeholder.org",
        company_name="Blank Co",
        html_login="",
        html_careers="",
        html_docs="",
        dns_spf=[],
    )
    assert res.icp_fit == "UNKNOWN"
    assert res.use_case_fit == "UNKNOWN"
    assert res.qualification_status == "UNKNOWN"
    assert res.evidence_quality == "INSUFFICIENT"
    assert res.disqualified is False
    assert res.disqualified_reason is None
    assert "html_login" in res.unknown_fields


# ── Requirement 5: Source URL tracking (No fabricated URL) ─────────────
def test_source_url_integrity_marks_unknown_when_not_provided():
    res = evaluate_devtools_prospect(
        domain="unvisited.dev",
        company_name="Unvisited Co",
        html_login="<form><p>Enter your 6-digit verification code</p></form>",
        url_login="",  # Empty source URL
        html_careers="<p>Hiring Playwright SDET</p>",
        url_careers="",  # Empty source URL
    )
    for sig in res.extracted_signals:
        # Must NOT invent https://unvisited.dev/login when not verified
        assert sig["source_url"] == "UNKNOWN"

    # P1-A source integrity: unverified sources do NOT count as independent sources!
    assert res.independent_source_count == 0
    assert res.evidence_quality == "INSUFFICIENT"
    assert "unverified_login" in res.source_breakdown["unverified_source"]
    assert "unverified_careers" in res.source_breakdown["unverified_source"]
    assert len(res.source_breakdown["verified_source"]) == 0
    assert "COLLECTED_AT_TIMESTAMP" in res.unknown_fields


# ── Requirement 6: Single page or duplicated content does not inflate sources ──
def test_single_page_duplication_counts_as_one_source(offline_fixtures):
    sample = offline_fixtures["single_page_duplication"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
    )
    # Only 1 unique content source, so evidence quality is PARTIAL, never SUFFICIENT
    assert res.evidence_quality == "PARTIAL"
    assert res.qualification_status == "POTENTIAL_FIT"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"


# ── Requirement 7: DNS SPF alone is technical lead, not sufficient ───
def test_dns_spf_alone_is_technical_lead_only():
    res = evaluate_devtools_prospect(
        domain="silent-dns-only.com",
        company_name="Silent DNS",
        html_login="",
        html_careers="",
        html_docs="",
        dns_spf=["v=spf1 include:sendgrid.net include:postmarkapp.com ~all"],
        dns_source="dns:spf:silent-dns-only.com",
    )
    assert res.evidence_quality == "INSUFFICIENT"
    assert len(res.purchase_intent_evidence) == 0
    assert res.qualification_status == "NEEDS_RESEARCH"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"


# ── Requirement 8: OpportunityCard generation and JSON export ─────────
def test_opportunity_card_generation_and_export(offline_fixtures, tmp_path):
    sample = offline_fixtures["saas_with_otp"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        url_login=sample["url_login"],
        html_careers=sample["html_careers"],
        url_careers=sample["url_careers"],
        html_docs=sample["html_docs"],
        url_docs=sample["url_docs"],
        dns_spf=sample["dns_spf"],
        dns_source=sample["dns_source"],
    )
    card = build_opportunity_card(
        {"id": "c_authagent_1", "name": sample["company_name"], "domain": sample["domain"]},
        res,
    )
    assert card.company_id == "c_authagent_1"
    assert card.icp_fit == "TIER_1_STRONG_FIT"
    assert card.qualification_status == "POTENTIAL_FIT"
    assert "HAS_SIGNUP_OTP_OR_MAGIC_LINK" in card.signals

    out_file = str(tmp_path / "opportunity_cards.json")
    count, text = export_opportunity_cards([card], out_path=out_file)
    assert count == 1
    assert os.path.exists(out_file)
    loaded = json.loads(text)
    assert loaded[0]["domain"] == sample["domain"]
    assert loaded[0]["qualification_status"] == "POTENTIAL_FIT"


# ── Requirement 9: Cohort filtering on DevTools signals in SQLite ─────
@pytest.mark.asyncio
async def test_cohort_filtering_by_devtools_signals(tmp_path):
    db_file = tmp_path / "cohort_harvey.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    for code in [
        "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
        "USES_E2E_TEST_FRAMEWORK",
        "BUILDS_AI_OR_BROWSER_AGENTS",
        "VERISIG_EVIDENCE_SUFFICIENCY",
        "VERISIG_DISQUALIFIED_REASON",
    ]:
        await state.set_signal_status(code, "confirmed")

    # Insert Company A: Agent with OTP
    comp_a = await state.add_company(Company(name="AgentCo", domain="agentco.ai"))
    await state.add_observations([
        {"company_id": comp_a, "signal_code": "HAS_SIGNUP_OTP_OR_MAGIC_LINK", "collector": "devtools", "confidence": 0.9},
        {"company_id": comp_a, "signal_code": "BUILDS_AI_OR_BROWSER_AGENTS", "collector": "devtools", "confidence": 0.9},
        {"company_id": comp_a, "signal_code": "VERISIG_EVIDENCE_SUFFICIENCY", "collector": "qualification", "value_text": "SUFFICIENT"},
    ])

    # Insert Company B: Disqualified competitor
    comp_b = await state.add_company(Company(name="FakeMail", domain="fakemail.org"))
    await state.add_observations([
        {"company_id": comp_b, "signal_code": "VERISIG_DISQUALIFIED_REASON", "collector": "qualification", "value_text": "DIRECT_COMPETITOR"},
    ])

    # Query 1: Cohort must have BUILDS_AI_OR_BROWSER_AGENTS and NOT disqualified
    cohort_1 = await state.cohort(
        require=["BUILDS_AI_OR_BROWSER_AGENTS"],
        exclude=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert comp_a in cohort_1
    assert comp_b not in cohort_1

    # Query 2: Cohort must have VERISIG_DISQUALIFIED_REASON
    cohort_disq = await state.cohort(
        require=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert comp_b in cohort_disq
    assert comp_a not in cohort_disq


# ── Requirement 10: Full DevToolsPipelineAdapter offline execution ─────
@pytest.mark.asyncio
async def test_devtools_pipeline_adapter_offline_run(offline_fixtures, tmp_path):
    db_file = tmp_path / "adapter_test.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    for code in [
        "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
        "USES_E2E_TEST_FRAMEWORK",
        "BUILDS_AI_OR_BROWSER_AGENTS",
        "HAS_DEVELOPER_DOCS_OR_API",
        "USES_TRANSACTIONAL_EMAIL_ESP",
        "HIRING_QA_OR_AGENT_INFRA",
        "VERISIG_EVIDENCE_SUFFICIENCY",
        "VERISIG_DISQUALIFIED_REASON",
    ]:
        await state.set_signal_status(code, "confirmed")

    # Inject bundle with 2 samples
    bundle = {
        "authagent.io": offline_fixtures["saas_with_otp"],
        "direct_comp.io": offline_fixtures["direct_competitor"],
    }

    adapter = DevToolsPipelineAdapter(state, evidence_bundle=bundle)
    res = await adapter.run(limit=10)

    assert res.evaluated_companies == 2
    assert res.recorded_observations >= 4
    assert len(res.opportunity_cards) == 2
    assert len(res.errors) == 0

    # Verify observations written into SQLite
    all_obs = await state.get_observations()
    assert len(all_obs) >= 4
    signal_codes_recorded = {o["signal_code"] for o in all_obs}
    assert "VERISIG_EVIDENCE_SUFFICIENCY" in signal_codes_recorded


# ── Requirement 11: Zero network access guarantee ─────────────────────
def test_zero_network_access_guarantee(monkeypatch):
    def forbidden_network(*args, **kwargs):
        raise RuntimeError("Forbidden outbound network call during offline test!")

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "request", forbidden_network)
    monkeypatch.setattr(httpx.Client, "request", forbidden_network)

    res = evaluate_devtools_prospect(
        domain="offline-guarantee.dev",
        company_name="Offline Test Co",
        html_login="<form><p>Enter your 6-digit verification code</p></form>",
        url_login="https://offline-guarantee.dev/login",
        html_careers="<p>Hiring Senior QA Engineer (Playwright)</p>",
        url_careers="https://offline-guarantee.dev/careers",
        html_docs="<h1>Developer API Reference</h1>",
        url_docs="https://offline-guarantee.dev/docs",
        dns_spf=["v=spf1 include:postmarkapp.com ~all"],
        dns_source="dns:spf:offline-guarantee.dev",
    )
    assert res.evidence_quality == "SUFFICIENT"
    assert res.qualification_status == "POTENTIAL_FIT"


# ── Requirement P0-B & P1: Adversarial & Structural Verification Tests ──

def test_p0_b_malicious_https_url_without_receipt_cannot_become_verified():
    """Adversarial sample: Valid HTTPS URLs with strong buying signals but NO trusted receipt
    MUST NOT be elevated to verified_source and MUST NOT achieve SUFFICIENT evidence.
    """
    res = evaluate_devtools_prospect(
        domain="malicious-prospect.io",
        company_name="Malicious Prospect Co",
        html_login="<form><p>Enter your 6-digit verification code to login</p></form>",
        url_login="https://malicious-prospect.io/fake-login",
        html_careers="<p>Hiring 50 SDET Playwright Engineers immediately for enterprise procurement</p>",
        url_careers="https://malicious-prospect.io/fake-careers",
        html_docs="<h1>Developer API Reference and SDK docs</h1>",
        url_docs="https://malicious-prospect.io/fake-docs",
        source_type="unverified_bundle_injection",
        collection_method="untrusted_injection",
    )
    # The HTTPS URLs are syntactically valid candidate URLs, but NOT verified sources
    assert len(res.source_breakdown["candidate_urls"]) == 3
    assert len(res.source_breakdown["verified_source"]) == 0
    assert len(res.source_breakdown["offline_fixture"]) == 0
    assert res.independent_source_count == 0
    # Must be INSUFFICIENT evidence
    assert res.evidence_quality == "INSUFFICIENT"
    assert "UNVERIFIED_CANDIDATE_URLS_NO_RECEIPT" in res.unknown_fields
    # Even with strong technical signals, insufficient evidence drops qualification to NEEDS_RESEARCH
    assert res.qualification_status == "NEEDS_RESEARCH"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res.qualification_status != "POTENTIAL_FIT"


def test_p0_b_trusted_collection_receipt_elevates_to_verified_source():
    """When a verifiable collection receipt is provided by a trusted collector, it is verified."""
    html_log = "<form><p>Enter your 6-digit verification code</p></form>"
    html_car = "<p>Hiring Playwright SDET</p>"
    import hashlib
    hash_log = hashlib.sha256(html_log.encode("utf-8")).hexdigest()
    hash_car = hashlib.sha256(html_car.encode("utf-8")).hexdigest()

    receipts = [
        {
            "url": "https://trusted-agent.io/login",
            "collector": "harvey:scout:collector",
            "collected_at": "2026-10-20T08:00:00Z",
            "content_sha256": hash_log,
            "verified": True,
        },
        {
            "url": "https://trusted-agent.io/careers",
            "collector": "harvey:scout:collector",
            "collected_at": "2026-10-20T08:01:00Z",
            "content_sha256": hash_car,
            "verified": True,
        },
    ]

    res = evaluate_devtools_prospect(
        domain="trusted-agent.io",
        company_name="Trusted Agent",
        html_login=html_log,
        url_login="https://trusted-agent.io/login",
        html_careers=html_car,
        url_careers="https://trusted-agent.io/careers",
        collection_receipts=receipts,
    )
    assert len(res.source_breakdown["verified_source"]) == 2
    assert res.independent_source_count == 2
    assert res.evidence_quality == "SUFFICIENT"
    assert res.qualification_status == "POTENTIAL_FIT"


def test_p1_invalid_purchase_evidence_rejected_never_confirmed_buyer():
    """P1: Malformed, empty, or string purchase evidence items MUST be rejected and NEVER confirmed."""
    # 1. Non-dict items (strings, integers)
    res_str = evaluate_devtools_prospect(
        domain="invalid-rfp.com",
        purchase_evidence=["arbitrary string that claims to be RFP"],
    )
    assert len(res_str.purchase_intent_evidence) == 0
    assert res_str.qualification_status != "PURCHASE_CANDIDATE_PENDING_VERIFICATION"
    assert res_str.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res_str.qualification_status == "UNKNOWN"

    # 2. Empty dicts
    res_empty = evaluate_devtools_prospect(
        domain="empty-rfp.com",
        purchase_evidence=[{}],
    )
    assert len(res_empty.purchase_intent_evidence) == 0
    assert res_empty.qualification_status == "UNKNOWN"

    # 3. Missing source reference
    res_nosrc = evaluate_devtools_prospect(
        domain="nosrc-rfp.com",
        purchase_evidence=[{"signal_code": "RFP", "summary": "Looking for tools"}],
    )
    assert len(res_nosrc.purchase_intent_evidence) == 0
    assert res_nosrc.qualification_status == "UNKNOWN"

    # 4. Valid structural RFP enters PURCHASE_CANDIDATE_PENDING_VERIFICATION, never CONFIRMED_ACTIVE_BUYER
    res_valid = evaluate_devtools_prospect(
        domain="valid-rfp.com",
        purchase_evidence=[{
            "signal_code": "DIRECT_PROCUREMENT_REQUEST",
            "source_url": "https://valid-rfp.com/rfp-2026.pdf",
            "summary": "Formal request for proposal for 50 QA test inboxes",
            "collected_at": "2026-10-20T09:00:00Z",
        }],
    )
    assert len(res_valid.purchase_intent_evidence) == 1
    assert res_valid.qualification_status == "PURCHASE_CANDIDATE_PENDING_VERIFICATION"
    assert res_valid.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res_valid.next_best_research_action == "HUMAN_PROCUREMENT_VERIFICATION"
