import json
import pytest
from pathlib import Path

from harvey.pipeline import run_prospecting, PipelineReport
from harvey.collectors import discover as D
from harvey.models import Company
from harvey.signals import seed_signal_catalog, SIGNAL_CATALOG
from harvey.state import StateManager


class MockDiscovery(D.DiscoveryProvider):
    key = "mock_discovery"
    label = "Mock Discovery"

    def __init__(self, businesses):
        self.businesses = businesses

    def configured(self, env):
        return True

    def estimate(self, queries):
        return 0.0

    async def fetch(self, client, env, query):
        return self.businesses


@pytest.mark.asyncio
async def test_full_devtools_pipeline_offline_e2e(tmp_path, monkeypatch):
    db_file = tmp_path / "pipeline_devtools_e2e.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    for sig in SIGNAL_CATALOG:
        await state.set_signal_status(sig["code"], "confirmed")

    # Offline fixtures
    fixtures_path = Path(__file__).parent.parent / "fixtures" / "devtools" / "offline_samples.json"
    with open(fixtures_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    # 1. Discovery returns 2 candidates
    discovered_biz = [
        D.Business(name="AuthAgent Inc", domain="authagent.io", provider="mock_discovery"),
        D.Business(name="TestMailTemp", domain="testmailtemp.io", provider="mock_discovery"),
    ]
    monkeypatch.setitem(D.PROVIDERS, "mock_discovery", MockDiscovery(discovered_biz))

    async def fake_profile_companies(st, comps):
        return len(comps), "profile-run-mock"
    monkeypatch.setattr("harvey.collectors.profile.profile_companies", fake_profile_companies)

    # Injected offline evidence bundle
    evidence_bundle = {
        "authagent.io": samples["saas_with_otp"],
        "testmailtemp.io": samples["direct_competitor"],
    }

    class DummyConfig:
        pass
    config = DummyConfig()

    report = await run_prospecting(
        state=state,
        config=config,
        provider="mock_discovery",
        queries=[D.DiscoveryQuery(term="devtools")],
        profile=True,
        devtools=True,
        devtools_limit=10,
        devtools_evidence=evidence_bundle,
    )

    # 1. Discover stage executed
    assert report.discover["new_companies"] == 2

    # 2. Profile stage executed
    assert report.profiled_companies == 2

    # 3. DevTools Pipeline Adapter executed
    assert report.devtools_companies == 2
    assert report.devtools_observations >= 4
    assert report.devtools_run_id != ""
    assert len(report.errors) == 0

    # 4. Cohort query verification on DevTools observations in SQLite
    authagent_id = await state.get_company_by_domain("authagent.io")
    testmail_id = await state.get_company_by_domain("testmailtemp.io")
    assert authagent_id is not None
    assert testmail_id is not None

    # Query 1: Cohort of OTP auth platforms without disqualification
    qualified_cohort = await state.cohort(
        require=["HAS_SIGNUP_OTP_OR_MAGIC_LINK"],
        exclude=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert authagent_id.id in qualified_cohort
    assert testmail_id.id not in qualified_cohort

    # Query 2: Cohort of disqualified competitors
    disqualified_cohort = await state.cohort(
        require=["VERISIG_DISQUALIFIED_REASON"],
    )
    assert testmail_id.id in disqualified_cohort
    assert authagent_id.id not in disqualified_cohort
