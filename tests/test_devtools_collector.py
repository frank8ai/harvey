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

# ── Review Closure Tests (P1-A, P1-B, Thread #3, Thread #5) ──────────

@pytest.mark.asyncio
async def test_p1_a_writer_skips_disqualified_companies(tmp_path):
    """P1-A: Prospects belonging to DISQUALIFIED companies must be excluded from Writer."""
    from harvey.agents.writer import Writer
    from harvey.config import load_config
    from harvey.models import Company, Prospect

    from harvey.signals import seed_signal_catalog
    db_file = tmp_path / "writer_disq.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    cfg = load_config()

    # 1. Add a competitor company and a regular company
    comp_id = await state.add_company(Company(name="Competitor Inc", domain="competitor.com"))
    good_id = await state.add_company(Company(name="Good SaaS", domain="goodsaas.io"))

    # 2. Add deliverable prospects for both
    p_disq_id = await state.add_prospect(Prospect(
        first_name="Alice", last_name="Bad", email="alice@competitor.com",
        company="Competitor Inc", company_id=comp_id, email_status="verified", email_verified=True, status="new"
    ))
    p_good_id = await state.add_prospect(Prospect(
        first_name="Bob", last_name="Good", email="bob@goodsaas.io",
        company="Good SaaS", company_id=good_id, email_status="verified", email_verified=True, status="new"
    ))

    # 3. Add disqualification observation for competitor
    await state.add_observation(
        "VERISIG_DISQUALIFIED_REASON",
        company_id=comp_id,
        value_text="DIRECT_COMPETITOR",
        confidence=1.0,
        evidence_url="test://disq",
    )

    # Check state method
    disq_ids = await state.get_disqualified_company_ids()
    assert comp_id in disq_ids
    assert good_id not in disq_ids

    # 4. Mock brain provider for writer to prevent actual LLM call
    class DummyBrain:
        def load_skills_for_agent(self, agent_name):
            return []
        def load_prompt(self, prompt_name, **kwargs):
            return "Prompt template"
        async def think(self, prompt, **kwargs):
            return "Subject: Hello\n\nBody text."
        async def think_json(self, prompt, **kwargs):
            if kwargs.get("task") == "personal_email":
                return {"subject": "quick question", "body": "Hello Bob"}
            return [
                {"step": 1, "subject": "hi {{first_name}}", "body": "Hello {{company}}", "delay_days": 0},
                {"step": 2, "subject": "follow {{first_name}}", "body": "Checking {{company}}", "delay_days": 3},
                {"step": 3, "subject": "bye {{first_name}}", "body": "Farewell {{company}}", "delay_days": 4}
            ]
    writer = Writer(brain=DummyBrain(), state=state, config=cfg)
    await writer.run()

    # 5. Outbox check: Bob gets drafts, Alice does NOT get drafts
    outbox = await state.get_outbox()
    recipients = {item["to_email"] for item in outbox}
    assert "bob@goodsaas.io" in recipients
    assert "alice@competitor.com" not in recipients

    # 6. Revocation check: add revocation observation (value_num=0)
    await state.add_observation(
        "VERISIG_DISQUALIFIED_REASON",
        company_id=comp_id,
        value_text="DIRECT_COMPETITOR",
        value_num=0.0,
        confidence=1.0,
        evidence_url="test://revoke",
    )
    disq_ids_revoked = await state.get_disqualified_company_ids()
    assert comp_id not in disq_ids_revoked


@pytest.mark.asyncio
async def test_p1_b_unconfirmed_signals_do_not_enter_company_profile(tmp_path):
    """P1-B: PROPOSED / REJECTED signals must NOT be written to company.signals_json or tech_stack_json."""
    from harvey.models import Company
    from harvey.signals import seed_signal_catalog
    from harvey.collectors.devtools import record_devtools_observations, DevToolsQualificationResult

    db_file = tmp_path / "confirm_gate.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    # Signal catalog seeds all signals as 'proposed' by default
    comp_id = await state.add_company(Company(name="SaaS Gate", domain="saasgate.io"))

    qual = DevToolsQualificationResult(
        company_id=comp_id,
        domain="saasgate.io",
        evidence_quality="SUFFICIENT",
        extracted_signals=[
            {
                "signal_code": "USES_E2E_TEST_FRAMEWORK",
                "evidence": "Playwright",
                "confidence": 0.85,
                "source_url": "https://saasgate.io/careers",
            },
            {
                "signal_code": "BUILDS_AI_OR_BROWSER_AGENTS",
                "evidence": "computer-use agent",
                "confidence": 0.85,
                "source_url": "https://saasgate.io/docs",
            },
        ],
    )

    # 1. With proposed signals, record_devtools_observations should filter them out
    obs_count = await record_devtools_observations(state, comp_id, qual)
    # Observations table records them, but company.signals and tech_stack remain empty!
    comp = await state.get_company(comp_id)
    assert "Playwright" not in comp.tech_stack
    assert len(comp.signals) == 0

    # 2. Confirm USES_E2E_TEST_FRAMEWORK only
    await state.set_signal_status("USES_E2E_TEST_FRAMEWORK", "confirmed")
    await record_devtools_observations(state, comp_id, qual)
    comp_confirmed = await state.get_company(comp_id)
    assert "Playwright" in comp_confirmed.tech_stack
    # BUILDS_AI_OR_BROWSER_AGENTS is still proposed, so it must NOT be in comp_confirmed.signals
    sig_types = [s.get("type") for s in comp_confirmed.signals]
    assert "USES_E2E_TEST_FRAMEWORK" in sig_types
    assert "BUILDS_AI_OR_BROWSER_AGENTS" not in sig_types


def test_review_thread_5_source_without_extracted_facts_does_not_inflate_sufficiency():
    """Review Thread #5: An OTP match on login + a careers page with NO extracted facts
    must NOT inflate evidence quality to SUFFICIENT.
    """
    res = evaluate_devtools_prospect(
        domain="factless-careers.io",
        company_name="Factless Careers SaaS",
        html_login="<form><p>Enter your 6-digit verification code</p></form>",
        url_login="https://factless-careers.io/login",
        html_careers="<h2>Careers</h2><p>We are a great place to work with free snacks and coffee!</p>",
        url_careers="https://factless-careers.io/careers",
        source_type="offline_fixture",
    )
    # Login contributed HAS_SIGNUP_OTP_OR_MAGIC_LINK.
    # Careers contributed NO extracted technical facts.
    assert len(res.extracted_signals) == 1
    assert res.extracted_signals[0]["signal_code"] == "HAS_SIGNUP_OTP_OR_MAGIC_LINK"
    # Independent source count should be 1 (only login), not 2
    assert res.independent_source_count == 1
    # Evidence quality must be PARTIAL, NOT SUFFICIENT
    assert res.evidence_quality == "PARTIAL"


@pytest.mark.asyncio
async def test_review_thread_3_pipeline_report_preserves_opportunity_cards(tmp_path, offline_fixtures):
    """Review Thread #3: PipelineReport must preserve opportunity_cards."""
    from harvey.pipeline import run_offline_prospecting
    db_file = tmp_path / "cards_preserve.db"
    state = StateManager(str(db_file))
    await state.init_db()

    bundle = {
        "authagent.io": offline_fixtures["saas_with_otp"],
    }
    report = await run_offline_prospecting(state, evidence_bundle=bundle)
    assert len(report.opportunity_cards) == 1
    card = report.opportunity_cards[0]
    assert card.domain == "authagent.io"
    assert card.qualification_status == "POTENTIAL_FIT"
    report_dict = report.as_dict()
    assert "opportunity_cards" in report_dict
    assert len(report_dict["opportunity_cards"]) == 1
    assert report_dict["opportunity_cards"][0]["domain"] == "authagent.io"

# ── W1-03-F2-G Qualification-to-Writer Fail-Closed Tests ──────────────

@pytest.mark.asyncio
async def test_disqualified_company_fails_closed_without_confirmed_catalog(tmp_path, offline_fixtures):
    """Defect Reproduction / Green verification:
    When a competitor is evaluated via DevToolsPipelineAdapter under the default
    PROPOSED Signal Catalog (without manual signal confirmation), qualification
    determines DISQUALIFIED / DIRECT_COMPETITOR.
    Without manual state.add_observation, the competitor prospect MUST NOT
    enter Campaign, email draft, or Outbox when Writer.run() executes.
    """
    from harvey.agents.writer import Writer
    from harvey.collectors.devtools import DevToolsPipelineAdapter
    from harvey.config import load_config
    from harvey.models import Company, Prospect
    from harvey.signals import seed_signal_catalog

    db_file = tmp_path / "red_disq_gate.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    # 1. Create company and a new prospect with deliverable email
    comp_id = await state.add_company(Company(name="TestMailTemp", domain="testmailtemp.io"))
    await state.add_prospect(Prospect(
        first_name="Competitor",
        last_name="Contact",
        email="contact@testmailtemp.io",
        company="TestMailTemp",
        company_id=comp_id,
        email_status="verified",
        email_verified=True,
        status="new",
    ))

    # 2. Process direct competitor evidence via real DevToolsPipelineAdapter
    evidence = {
        "testmailtemp.io": offline_fixtures["direct_competitor"],
    }
    adapter = DevToolsPipelineAdapter(state, evidence_bundle=evidence)
    res = await adapter.run()

    # 3. Assert qualification returned DISQUALIFIED / DIRECT_COMPETITOR
    assert len(res.opportunity_cards) == 1
    card = res.opportunity_cards[0]
    assert card.qualification_status == "DISQUALIFIED"
    assert card.disqualified is True
    assert card.disqualified_reason == "DIRECT_COMPETITOR"

    # 4. DummyBrain to prevent real LLM calls
    class DummyBrain:
        def load_skills_for_agent(self, agent_name):
            return []
        def load_prompt(self, prompt_name, **kwargs):
            return "Prompt template"
        async def think(self, prompt, **kwargs):
            return "Subject: Hello\n\nBody text."
        async def think_json(self, prompt, **kwargs):
            if kwargs.get("task") == "personal_email":
                return {"subject": "quick question", "body": "Hello"}
            return [
                {"step": 1, "subject": "hi {{first_name}}", "body": "Hello {{company}}", "delay_days": 0},
                {"step": 2, "subject": "follow {{first_name}}", "body": "Checking {{company}}", "delay_days": 3},
                {"step": 3, "subject": "bye {{first_name}}", "body": "Farewell {{company}}", "delay_days": 4},
            ]

    cfg = load_config()
    writer = Writer(brain=DummyBrain(), state=state, config=cfg)
    await writer.run()

    # 5. Assert: Disqualified company cannot enter Campaign, drafts, or Outbox
    async with state._connect() as db:
        async with db.execute("SELECT COUNT(*) FROM campaigns") as cur:
            campaign_count = (await cur.fetchone())[0]
    outbox = await state.get_outbox()
    assert campaign_count == 0, f"Expected 0 campaigns, got {campaign_count}"
    assert len(outbox) == 0, f"Expected 0 outbox items, got {len(outbox)}"


@pytest.mark.asyncio
async def test_sender_blocks_and_cancels_outbox_for_disqualified_company(tmp_path):
    """Fail-closed gate on send boundary:
    If an outbox item exists for a prospect whose company is DISQUALIFIED,
    Sender._drain_due() MUST NOT send the email, must cancel the outbox item,
    and actual outbound calls must be zero.
    """
    from harvey.agents.sender import Sender
    from harvey.config import load_config, EnvConfig
    from harvey.models import Company, Prospect
    from harvey.signals import seed_signal_catalog

    db_file = tmp_path / "sender_disq.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    comp_id = await state.add_company(Company(name="Disq Corp", domain="disqcorp.com"))
    prospect_id = await state.add_prospect(Prospect(
        first_name="Dan",
        last_name="Disq",
        email="dan@disqcorp.com",
        company="Disq Corp",
        company_id=comp_id,
        email_status="verified",
        email_verified=True,
        status="queued",
    ))

    # Add historical staged outbox item (approved for send)
    item_id = await state.add_outbox_item(
        prospect_id=prospect_id,
        to_email="dan@disqcorp.com",
        subject="Disqualified outreach",
        body="This must never be sent.",
        send_at="2000-01-01T00:00:00",
        status="approved",
        campaign_id="camp_disq",
        step=1,
    )

    # Disqualify company
    await state.add_observation(
        "VERISIG_DISQUALIFIED_REASON",
        company_id=comp_id,
        value_text="DIRECT_COMPETITOR",
        confidence=1.0,
        evidence_url="qualification://disqcorp.com",
    )

    # Fake mail provider to verify zero outbound email calls
    class FakeProvider:
        name = "fake"
        def __init__(self):
            self.sent = []
        def is_configured(self):
            return True
        async def send_email(self, *args, **kwargs):
            self.sent.append(args)
            from harvey.integrations.mail_provider import SendResult
            return SendResult(ok=True, message_id="fake_msg")

    cfg = load_config()
    env = EnvConfig()
    provider = FakeProvider()
    sender = Sender(brain=None, state=state, config=cfg, env=env)
    sender.provider = provider

    await sender._drain_due()

    # Outbound call count must be 0
    assert len(provider.sent) == 0
    # Outbox item must be cancelled
    cancelled = await state.get_outbox(status="cancelled")
    assert len(cancelled) == 1
    assert cancelled[0]["id"] == item_id
    assert "disqualified" in cancelled[0]["error"]


@pytest.mark.asyncio
async def test_revocation_allows_prospect_and_legitimate_client_not_blocked(tmp_path, offline_fixtures):
    """Audit recovery & legitimate clients:
    1. Legitimate prospect (non-competitor, e.g. saas_with_otp) must NOT be blocked.
    2. Disqualified company when corrected/revoked (value_num=0.0) is allowed to enter outreach.
    """
    from harvey.agents.writer import Writer
    from harvey.collectors.devtools import DevToolsPipelineAdapter
    from harvey.config import load_config
    from harvey.models import Company, Prospect
    from harvey.signals import seed_signal_catalog

    db_file = tmp_path / "legit_and_revoke.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    # 1. Legitimate client
    legit_cid = await state.add_company(Company(name="Legit SaaS", domain="authagent.io"))
    await state.add_prospect(Prospect(
        first_name="Legit",
        last_name="User",
        email="user@authagent.io",
        company="Legit SaaS",
        company_id=legit_cid,
        email_status="verified",
        email_verified=True,
        status="new",
    ))

    # Evaluate legitimate client
    evidence = {
        "authagent.io": offline_fixtures["saas_with_otp"],
    }
    adapter = DevToolsPipelineAdapter(state, evidence_bundle=evidence)
    res = await adapter.run()
    assert res.opportunity_cards[0].qualification_status == "POTENTIAL_FIT"
    assert res.opportunity_cards[0].disqualified is False

    # 2. Erroneously disqualified client that gets revoked
    rev_cid = await state.add_company(Company(name="Revoked Co", domain="revoked.io"))
    await state.add_prospect(Prospect(
        first_name="Rev",
        last_name="User",
        email="user@revoked.io",
        company="Revoked Co",
        company_id=rev_cid,
        email_status="verified",
        email_verified=True,
        status="new",
    ))
    # Initial disqualification
    await state.add_observation(
        "VERISIG_DISQUALIFIED_REASON",
        company_id=rev_cid,
        value_text="DIRECT_COMPETITOR",
        confidence=1.0,
        evidence_url="qualification://revoked.io",
    )
    assert rev_cid in await state.get_disqualified_company_ids()

    # Revoke disqualification via auditable observation (value_num=0.0)
    await state.add_observation(
        "VERISIG_DISQUALIFIED_REASON",
        company_id=rev_cid,
        value_text="DIRECT_COMPETITOR",
        value_num=0.0,
        confidence=1.0,
        evidence_url="audit://human_correction",
    )
    assert rev_cid not in await state.get_disqualified_company_ids()

    class DummyBrain:
        def load_skills_for_agent(self, agent_name):
            return []
        def load_prompt(self, prompt_name, **kwargs):
            return "Prompt template"
        async def think(self, prompt, **kwargs):
            return "Subject: Hello\n\nBody text."
        async def think_json(self, prompt, **kwargs):
            if kwargs.get("task") == "personal_email":
                return {"subject": "quick question", "body": "Hello"}
            return [
                {"step": 1, "subject": "hi {{first_name}}", "body": "Hello {{company}}", "delay_days": 0},
                {"step": 2, "subject": "follow {{first_name}}", "body": "Checking {{company}}", "delay_days": 3},
                {"step": 3, "subject": "bye {{first_name}}", "body": "Farewell {{company}}", "delay_days": 4},
            ]

    cfg = load_config()
    writer = Writer(brain=DummyBrain(), state=state, config=cfg)
    await writer.run()

    outbox = await state.get_outbox()
    recipients = {item["to_email"] for item in outbox}
    # Both legitimate client and revoked client must have drafts staged
    assert "user@authagent.io" in recipients
    assert "user@revoked.io" in recipients
