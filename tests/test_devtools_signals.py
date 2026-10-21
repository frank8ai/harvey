import pytest
import sqlite3
import aiosqlite
from pathlib import Path

from harvey.signals import SIGNAL_CATALOG, CORE_SIGNAL_CATALOG, DEVTOOLS_SIGNAL_CATALOG, seed_signal_catalog
from harvey.state import StateManager

# ── Requirement 1: Harvey 23 core signals intact ──────────────────────
def test_harvey_core_23_signals_fully_retained():
    assert len(CORE_SIGNAL_CATALOG) == 23
    assert len(DEVTOOLS_SIGNAL_CATALOG) == 8
    assert len(SIGNAL_CATALOG) == 31

    # Exact expected 23 core signal codes
    expected_core_codes = {
        "SERP_RANK", "FOUND_IN_SERP", "NO_WEBSITE", "UNCLAIMED_LISTING",
        "REVIEW_RATING", "REVIEW_COUNT", "INCUMBENT_AGENCY", "RUNNING_GOOGLE_ADS",
        "RUNNING_META_ADS", "TECH_STACK", "NO_SCHEMA_MARKUP", "NO_ONLINE_BOOKING",
        "SITE_PAGE_COUNT", "BLOG_STALE", "BLOCKS_AI_CRAWLERS", "HIRING_ROLE",
        "CONTACT_FOUND", "DECISION_MAKER_TITLE", "REGISTRY_VERIFIED", "LIKELY_OWNER",
        "EMAIL_PATTERN", "EMAIL_STATUS", "CONTACT_FORM_URL"
    }
    actual_core_codes = {s["code"] for s in CORE_SIGNAL_CATALOG}
    assert actual_core_codes == expected_core_codes


# ── Requirement 2: 8 New codes registered cleanly ────────────────────
def test_devtools_and_qualification_signals_registered():
    expected_new_codes = {
        "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
        "USES_E2E_TEST_FRAMEWORK",
        "BUILDS_AI_OR_BROWSER_AGENTS",
        "HAS_DEVELOPER_DOCS_OR_API",
        "USES_TRANSACTIONAL_EMAIL_ESP",
        "HIRING_QA_OR_AGENT_INFRA",
        "VERISIG_EVIDENCE_SUFFICIENCY",
        "VERISIG_DISQUALIFIED_REASON",
    }
    actual_new_codes = {s["code"] for s in DEVTOOLS_SIGNAL_CATALOG}
    assert actual_new_codes == expected_new_codes

    for sig in DEVTOOLS_SIGNAL_CATALOG:
        assert sig["category"] in ("profile", "verification", "discovery", "people")
        assert sig["value_type"] in ("bool", "text", "num")
        assert sig["cost_note"].lower().startswith("free")


# ── Requirement 3: Unregistered signal rejected by DB trigger ────────
@pytest.mark.asyncio
async def test_unregistered_signal_rejected_by_trigger(tmp_path):
    db_file = tmp_path / "test_harvey.db"
    state = StateManager(str(db_file))
    await state.init_db()
    await seed_signal_catalog(state)

    # Valid signal insert succeeds
    await state.set_signal_status("HAS_SIGNUP_OTP_OR_MAGIC_LINK", "confirmed")
    obs_id = await state.add_observations([
        {
            "company_id": "comp_1",
            "signal_code": "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
            "collector": "devtools",
            "value_num": 1.0,
            "confidence": 0.9,
        }
    ])
    assert obs_id == 1

    # Fake unregistered signal MUST be aborted by trg_observations_signal_known
    with pytest.raises(Exception) as excinfo:
        await state.add_observations([
            {
                "company_id": "comp_1",
                "signal_code": "FAKE_UNREGISTERED_SIGNAL",
                "collector": "devtools",
                "value_text": "bad",
            }
        ])
    assert "unknown signal_code" in str(excinfo.value).lower()
