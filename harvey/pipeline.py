"""The prospecting pipeline: DISCOVER → PROFILE → (people, verification).

Each stage is independently runnable and independently re-runnable. That is
the point of the design, not an accident of it: profiling can re-run without
re-buying discovery, and discovery can widen without re-profiling everyone.

What chains them is a *query*, not a hand-off. PROFILE asks the database
"which companies have I not looked at, or not looked at lately?" rather than
being handed a list by DISCOVER. So a profile run started for any reason
picks up whatever discovery left behind, a crashed run resumes by itself, and
re-observing on a schedule turns the same signal into a time series.

Segment before you enrich: enrichment cost scales with list size and
conversion does not, so profile the businesses you would actually contact,
not every row you hold.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("harvey.pipeline")

# How long a profile observation stays fresh. Re-reading a site every quarter
# is what makes "they dropped their agency" a visible event.
PROFILE_STALE_DAYS = 90


@dataclass
class PipelineReport:
    """What a full pass did, stage by stage."""

    discover: dict | None = None
    profiled_companies: int = 0
    profile_observations: int = 0
    profile_run_id: str = ""
    devtools_companies: int = 0
    devtools_observations: int = 0
    devtools_run_id: str = ""
    skipped: str = ""
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "discover": self.discover,
            "profiled_companies": self.profiled_companies,
            "profile_observations": self.profile_observations,
            "profile_run_id": self.profile_run_id,
            "devtools_companies": self.devtools_companies,
            "devtools_observations": self.devtools_observations,
            "devtools_run_id": self.devtools_run_id,
            "skipped": self.skipped,
            "errors": self.errors,
        }

    def summary_line(self) -> str:
        parts = []
        if self.discover:
            parts.append(f"{self.discover.get('new_companies', 0)} new companies")
        if self.profiled_companies:
            parts.append(f"{self.profiled_companies} profiled "
                         f"({self.profile_observations} observations)")
        return ", ".join(parts) or "nothing to do"


async def run_profile_stage(
    state,
    limit: int = 100,
    stale_days: int = PROFILE_STALE_DAYS,
) -> tuple[int, int, str]:
    """Profile whatever currently needs it.

    Returns (companies, observations, run_id). Free — three HTTP requests per
    business, no browser, no model call — so it is safe to run on every
    heartbeat without touching the Claude budget.
    """
    from harvey.collectors.profile import profile_companies

    pending = await state.companies_needing_profile(limit=limit,
                                                    stale_days=stale_days)
    if not pending:
        return 0, 0, ""

    logger.info("profile: %d companies need a look", len(pending))
    observations, run_id = await profile_companies(state, pending)
    return len(pending), observations, run_id


async def run_prospecting(
    state,
    config,
    provider: str | None = None,
    queries=None,
    max_spend: float = 1.0,
    profile: bool = True,
    profile_limit: int = 200,
    devtools: bool = False,
    devtools_limit: int = 50,
    devtools_evidence: dict | None = None,
    offline_evidence_only: bool = False,
    dry_run: bool = False,
) -> PipelineReport:
    """Discover businesses, then read what their websites say about them.

    The two stages are deliberately not coupled through a list: profiling
    queries the database for what needs attention, so it also sweeps up
    anything an earlier run left unfinished.
    """
    if offline_evidence_only:
        return await run_offline_prospecting(
            state=state,
            evidence_bundle=devtools_evidence,
            limit=devtools_limit,
        )

    from harvey.collectors.discover import DEFAULT_PROVIDER, run_discovery

    report = PipelineReport()

    discovery = await run_discovery(
        state, config, provider or DEFAULT_PROVIDER, queries,
        max_spend=max_spend, dry_run=dry_run,
    )
    report.discover = discovery.as_dict()
    report.errors.extend(discovery.errors)

    if dry_run:
        report.skipped = "dry run"
        return report

    if not profile and not devtools:
        report.skipped = "profiling skipped"
        return report

    # Profiling stage: run only if profile=True
    if profile:
        try:
            companies, observations, run_id = await run_profile_stage(
                state, limit=profile_limit)
            report.profiled_companies = companies
            report.profile_observations = observations
            report.profile_run_id = run_id
        except Exception as e:
            logger.exception("profile stage failed")
            report.errors.append(f"profile: {e}")
    else:
        report.skipped = "profiling skipped"
        logger.info("profiling skipped by profile=False")

    # Optional DevTools enrichment stage (default: False, offline pipeline adapter)
    if devtools:
        try:
            from harvey.collectors.devtools import DevToolsPipelineAdapter
            adapter = DevToolsPipelineAdapter(state, evidence_bundle=devtools_evidence)
            devtools_res = await adapter.run(limit=devtools_limit)
            report.devtools_companies = devtools_res.evaluated_companies
            report.devtools_observations = devtools_res.recorded_observations
            report.devtools_run_id = devtools_res.run_id
            if devtools_res.errors:
                report.errors.extend(devtools_res.errors)
            logger.info(
                "devtools: evaluated %d companies, recorded %d observations (run_id=%s)",
                devtools_res.evaluated_companies,
                devtools_res.recorded_observations,
                devtools_res.run_id,
            )
        except Exception as e:
            logger.exception("devtools stage failed")
            report.errors.append(f"devtools: {e}")

    return report


async def run_offline_prospecting(
    state,
    evidence_bundle: dict | None = None,
    limit: int = 50,
) -> PipelineReport:
    """Offline Evidence-Only execution entrypoint for DevTools and FetchInbox signals.

    Strictly guarantees zero unapproved outbound network access:
    - Discovery, profiling, DNS queries, and external scraping are completely bypassed.
    - An outermost network guard blocks any outbound socket, DNS, or HTTP calls.
    - Injected evidence bundles or pre-existing SQLite company records are fed
      directly into DevToolsPipelineAdapter.
    - Yields standard PipelineReport with observations recorded in SQLite.
    """
    from harvey.collectors.devtools import (
        DevToolsPipelineAdapter,
        offline_network_guard,
        OutboundCallTracker,
    )

    report = PipelineReport()
    report.discover = {"found": 0, "queries": 0, "new_companies": 0, "actual_cost": 0.0, "mode": "offline_evidence_only"}
    report.skipped = "discovery and profiling bypassed in offline evidence-only mode"

    tracker = OutboundCallTracker()
    with offline_network_guard(tracker):
        try:
            # P0-A: None => evaluate_existing_companies=True (explicit evaluation of SQLite companies)
            # {} => evaluate_existing_companies=False (evaluates 0 companies, no DB fallback)
            # dict with data => evaluates injected companies
            eval_existing = (evidence_bundle is None)
            adapter = DevToolsPipelineAdapter(
                state,
                evidence_bundle=evidence_bundle,
                evaluate_existing_companies=eval_existing,
            )
            res = await adapter.run(limit=limit)
            report.devtools_companies = res.evaluated_companies
            report.devtools_observations = res.recorded_observations
            report.devtools_run_id = res.run_id
            if res.errors:
                report.errors.extend(res.errors)
        except Exception as e:
            logger.exception("offline prospecting run failed: %s", e)
            report.errors.append(f"offline_prospecting: {e}")

    if tracker.call_count > 0:
        err = f"CRITICAL SECURITY VIOLATION: {tracker.call_count} outbound calls intercepted during offline run!"
        report.errors.append(err)
        logger.critical(err)

    return report
