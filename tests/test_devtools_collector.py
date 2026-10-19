import json
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
)
from harvey.signals import seed_signal_catalog
from harvey.state import StateManager
from harvey.models import Company


@pytest.fixture
def offline_fixtures():
    fixtures_path = Path(__file__).parent.parent / "fixtures" / "devtools" / "offline_samples.json"
    with open(fixtures_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Requirement 4: Positive samples extract concrete evidence ─────────
def test_positive_saas_otp_and_playwright(offline_fixtures):
    sample = offline_fixtures["saas_with_otp"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
        dns_spf=sample["dns_spf"],
    )
    assert res.icp_fit == "TIER_1_STRONG_FIT"
    assert res.use_case_fit == "E2E_AUTH_TESTING"
    assert res.evidence_quality == "SUFFICIENT"
    assert len(res.purchase_intent_evidence) > 0
    assert res.qualification_status == "CONFIRMED_ACTIVE_BUYER"
    assert not res.disqualified


def test_positive_ai_browser_agent(offline_fixtures):
    sample = offline_fixtures["ai_browser_agent"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
        dns_spf=sample["dns_spf"],
    )
    assert res.icp_fit == "TIER_1_STRONG_FIT"
    assert res.use_case_fit == "AGENT_INBOX"
    assert res.evidence_quality == "SUFFICIENT"
    assert res.qualification_status == "CONFIRMED_ACTIVE_BUYER"
    assert not res.disqualified


# ── Requirement 5: Negative samples NOT misclassified as buyers ───────
def test_competitor_disqualified(offline_fixtures):
    sample = offline_fixtures["direct_competitor"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
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
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
        dns_spf=sample["dns_spf"],
    )
    assert res.disqualified is True
    assert res.disqualified_reason == "CONSUMER_ONLY"
    assert res.qualification_status == "DISQUALIFIED"


# ── Requirement 6: Empty text cannot become high ICP ──────────────────
def test_empty_text_cannot_become_high_icp():
    res = evaluate_devtools_prospect(
        domain="blank-placeholder.org",
        company_name="Blank Co",
        html_login="",
        html_careers="",
        html_docs="",
        dns_spf=[],
    )
    assert res.icp_fit == "NON_ICP"
    assert res.evidence_quality == "INSUFFICIENT"
    assert res.qualification_status == "DISQUALIFIED"
    assert res.disqualified is True


# ── Requirement 7: Stale / archived job is not active buyer signal ────
def test_stale_job_not_treated_as_active_intent(offline_fixtures):
    sample = offline_fixtures["stale_hiring_saas"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
        dns_spf=sample["dns_spf"],
    )
    # Stale hiring means NO active purchase intent items
    assert len(res.purchase_intent_evidence) == 0
    # Must NOT be marked CONFIRMED_ACTIVE_BUYER
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"
    assert res.qualification_status == "POTENTIAL_FIT"


# ── Requirement 8: Single page repeated mentions is not 2 sources ─────
def test_single_page_duplication_counts_as_one_source(offline_fixtures):
    sample = offline_fixtures["single_page_duplication"]
    res = evaluate_devtools_prospect(
        domain=sample["domain"],
        company_name=sample["company_name"],
        html_login=sample["html_login"],
        html_careers=sample["html_careers"],
        html_docs=sample["html_docs"],
        dns_spf=sample["dns_spf"],
    )
    # Only 1 source URL (login), so evidence quality is PARTIAL, never SUFFICIENT
    assert res.evidence_quality == "PARTIAL"
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"


# ── Requirement 9: DNS SPF alone does not produce buying conclusion ──
def test_dns_spf_alone_is_technical_lead_only():
    res = evaluate_devtools_prospect(
        domain="silent-dns-only.com",
        company_name="Silent DNS",
        html_login="",
        html_careers="",
        html_docs="",
        dns_spf=["v=spf1 include:sendgrid.net include:postmarkapp.com ~all"],
    )
    assert res.evidence_quality == "INSUFFICIENT"
    assert len(res.purchase_intent_evidence) == 0
    assert res.qualification_status != "CONFIRMED_ACTIVE_BUYER"


# ── Requirement 10: Cohort query matching on technical signals ───────
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


# ── Requirement 11: Observation timestamps and conflict handling ──────
@pytest.mark.asyncio
async def test_observation_timestamp_and_deterministic_conflict(tmp_path):
    db_file = tmp_path / "conflict_harvey.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)
    await state.set_signal_status("VERISIG_EVIDENCE_SUFFICIENCY", "confirmed")

    comp_id = await state.add_company(Company(name="ConflictTest", domain="conflict.com"))

    # T1: Observed PARTIAL
    await state.add_observations([
        {
            "company_id": comp_id,
            "signal_code": "VERISIG_EVIDENCE_SUFFICIENCY",
            "collector": "qualification",
            "value_text": "PARTIAL",
            "confidence": 0.7,
        }
    ])

    # T2: Later Observed SUFFICIENT
    await state.add_observations([
        {
            "company_id": comp_id,
            "signal_code": "VERISIG_EVIDENCE_SUFFICIENCY",
            "collector": "qualification",
            "value_text": "SUFFICIENT",
            "confidence": 0.95,
        }
    ])

    # Fetch company observations
    obs = await state.get_observations(company_id=comp_id)
    sufficiency_obs = [o for o in obs if o["signal_code"] == "VERISIG_EVIDENCE_SUFFICIENCY"]
    assert len(sufficiency_obs) == 2

    # Deterministic rule: highest confidence / latest observation wins
    latest_winning = max(sufficiency_obs, key=lambda x: (x["confidence"], x["observed_at"]))
    assert latest_winning["value_text"] == "SUFFICIENT"


# ── Requirement 12: Zero network access verification ──────────────────
def test_zero_network_access_guarantee(monkeypatch):
    # If any HTTP client is invoked, fail immediately
    def forbidden_network(*args, **kwargs):
        raise RuntimeError("Network call attempted during offline test!")

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "request", forbidden_network)
    monkeypatch.setattr(httpx.Client, "request", forbidden_network)

    # Pure extraction must run completely offline without triggering forbidden_network
    res = evaluate_devtools_prospect(
        domain="offline-guarantee.dev",
        company_name="Offline Test Co",
        html_login="<form><p>Enter your 6-digit verification code</p></form>",
        html_careers="<p>Hiring Senior QA Engineer (Playwright)</p>",
        html_docs="<h1>Developer API Reference</h1>",
        dns_spf=["v=spf1 include:postmarkapp.com ~all"],
    )
    assert res.evidence_quality == "SUFFICIENT"
    assert res.qualification_status == "CONFIRMED_ACTIVE_BUYER"
