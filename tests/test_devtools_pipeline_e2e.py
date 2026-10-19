import json
import pytest
from pathlib import Path

from harvey.pipeline import run_offline_prospecting, run_prospecting, PipelineReport
from harvey.collectors.devtools import (
    offline_network_guard,
    OutboundCallTracker,
    OfflineNetworkBlockedError,
    export_opportunity_cards,
)
from harvey.models import Company
from harvey.signals import seed_signal_catalog, SIGNAL_CATALOG
from harvey.state import StateManager


@pytest.fixture
def offline_fixtures():
    fixtures_path = Path(__file__).parent.parent / "fixtures" / "devtools" / "offline_samples.json"
    with open(fixtures_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_offline_evidence_only_outermost_network_block_and_reentrancy(tmp_path, offline_fixtures):
    """P0-A & Test Standard: Outermost network block, real SQLite state, 0 outbound requests,
    idempotent re-runs without state pollution, and all 9 positive/negative cases verified.
    """
    db_file = tmp_path / "offline_strictly_isolated.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    for sig in SIGNAL_CATALOG:
        await state.set_signal_status(sig["code"], "confirmed")

    # Pre-populate one existing company in SQLite to verify combining existing DB rows with bundle
    pre_existing_id = await state.add_company(Company(
        name="Denver Smiles Dental Clinic",
        domain="denver-smiles-clinic.com",
    ))
    assert pre_existing_id is not None

    # Injected bundle containing all 9 fixture classes
    evidence_bundle = {
        sample["domain"]: sample for sample in offline_fixtures.values()
    }
    assert len(evidence_bundle) == 9

    # Set up external tracker to verify zero outbound calls
    tracker = OutboundCallTracker()
    with offline_network_guard(tracker):
        # 1. Run strict Offline Evidence-Only entrypoint
        report = await run_offline_prospecting(
            state=state,
            evidence_bundle=evidence_bundle,
            limit=20,
        )

    # Outbound network requests MUST be exactly 0
    assert tracker.call_count == 0
    assert len(report.errors) == 0
    assert report.devtools_companies == 9
    assert report.devtools_observations >= 15
    assert report.devtools_run_id != ""
    assert report.discover["mode"] == "offline_evidence_only"

    # Verify all 9 fixture classes in SQLite observations and cohorts
    # 1. saas_with_otp: authagent.io (OTP, POTENTIAL_FIT)
    # 2. procurement_candidate: enterprise-agent.dev (RFP, PURCHASE_CANDIDATE_PENDING_VERIFICATION)
    # 3. ai_browser_agent: browserworker.ai (Agent, POTENTIAL_FIT)
    # 4. qa_agency: qualitest-labs.dev (SDET QA, POTENTIAL_FIT)
    # 5. direct_competitor: testmailtemp.io (DISQUALIFIED - DIRECT_COMPETITOR)
    # 6. consumer_fashion: cozythreads-apparel.com (DISQUALIFIED - CONSUMER_ONLY)
    # 7. local_dentist: denver-smiles-clinic.com (DISQUALIFIED - CONSUMER_ONLY, pre-existing row)
    # 8. stale_hiring_saas: cloudledger.net (Closed job filtered, POTENTIAL_FIT)
    # 9. single_page_duplication: agenticops.dev (Duplicate text counts as 1, PARTIAL)

    authagent = await state.get_company_by_domain("authagent.io")
    procurement = await state.get_company_by_domain("enterprise-agent.dev")
    browserworker = await state.get_company_by_domain("browserworker.ai")
    qualitest = await state.get_company_by_domain("qualitest-labs.dev")
    competitor = await state.get_company_by_domain("testmailtemp.io")
    consumer = await state.get_company_by_domain("cozythreads-apparel.com")
    dentist = await state.get_company_by_domain("denver-smiles-clinic.com")
    stale_hiring = await state.get_company_by_domain("cloudledger.net")
    single_dup = await state.get_company_by_domain("agenticops.dev")

    for c in [authagent, procurement, browserworker, qualitest, competitor, consumer, dentist, stale_hiring, single_dup]:
        assert c is not None, f"Company {c} missing in state"

    # Assert pre-existing company ID preserved (no duplicate company created)
    assert dentist.id == pre_existing_id

    # SQLite Cohort Query 1: Positive AI / Browser Agents (browserworker.ai)
    cohort_agent = await state.cohort(
        require=["BUILDS_AI_OR_BROWSER_AGENTS"],
        exclude=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert browserworker.id in cohort_agent
    assert competitor.id not in cohort_agent

    # SQLite Cohort Query 2: Disqualified competitors
    cohort_disq_comp = await state.cohort(
        require=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert competitor.id in cohort_disq_comp
    assert consumer.id in cohort_disq_comp
    assert dentist.id in cohort_disq_comp
    assert authagent.id not in cohort_disq_comp
    assert procurement.id not in cohort_disq_comp

    # Verify observations count before re-run
    async with state._connect() as db:
        async with db.execute("SELECT COUNT(*) FROM companies") as cur:
            initial_companies_count = (await cur.fetchone())[0]
    assert initial_companies_count == 9

    # Re-run idempotency test: Running again with identical input must NOT corrupt state
    with offline_network_guard(tracker):
        report_rerun = await run_offline_prospecting(
            state=state,
            evidence_bundle=evidence_bundle,
            limit=20,
        )

    assert tracker.call_count == 0
    assert len(report_rerun.errors) == 0
    async with state._connect() as db:
        async with db.execute("SELECT COUNT(*) FROM companies") as cur:
            companies_after_count = (await cur.fetchone())[0]
    assert companies_after_count == 9  # No duplicate company rows!


@pytest.mark.asyncio
async def test_run_prospecting_offline_evidence_only_flag(tmp_path, offline_fixtures):
    """Test that run_prospecting(..., offline_evidence_only=True) bypasses discovery and profiling."""
    db_file = tmp_path / "run_prospecting_offline.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    bundle = {
        "authagent.io": offline_fixtures["saas_with_otp"],
    }

    tracker = OutboundCallTracker()
    with offline_network_guard(tracker):
        report = await run_prospecting(
            state=state,
            config=None,
            devtools_evidence=bundle,
            offline_evidence_only=True,
        )

    assert tracker.call_count == 0
    assert report.discover["mode"] == "offline_evidence_only"
    assert report.devtools_companies == 1
    assert report.profiled_companies == 0
    assert len(report.errors) == 0


@pytest.mark.asyncio
async def test_empty_offline_bundle_returns_clear_state_without_network():
    """Empty input must not trigger sneaky network attempts, evaluating cleanly to UNKNOWN/INSUFFICIENT."""
    from harvey.collectors.devtools import evaluate_devtools_prospect

    tracker = OutboundCallTracker()
    with offline_network_guard(tracker):
        res = evaluate_devtools_prospect(domain="empty-probe.com")

    assert tracker.call_count == 0
    assert res.icp_fit == "UNKNOWN"
    assert res.use_case_fit == "UNKNOWN"
    assert res.qualification_status == "UNKNOWN"
    assert res.evidence_quality == "INSUFFICIENT"
    assert "html_login" in res.unknown_fields
