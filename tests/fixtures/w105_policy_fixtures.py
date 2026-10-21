"""Synthetic fixtures for W1-05-A Source Policy Engine tests.
All data is strictly mock / synthetic. No real enterprise domains or production targets.
"""

from datetime import datetime, timedelta, timezone
from harvey.controlled_discovery.policy import (
    AccessPurpose,
    AuthorizationStatus,
    CompanyTargetScope,
    SourceStatus,
    TargetAllowlist,
)

MOCK_ROBOTS_TXT_ACME = """User-agent: *
Disallow: /private/
Disallow: /admin/
Disallow: /internal/
Allow: /public/
Allow: /research/
"""

MOCK_ROBOTS_TXT_DISALLOW_ALL = """User-agent: *
Disallow: /
"""

MOCK_ROBOTS_TXT_ALLOW_ALL = """User-agent: *
Allow: /
"""


def make_valid_acme_scope() -> CompanyTargetScope:
    """Create a verified mock company target scope for testing."""
    return CompanyTargetScope(
        company_id="comp_acme_test_001",
        primary_domain="acme-corp.test",
        allowed_domains={"alt.acme-corp.test"},
        allowed_path_prefixes=["/public/", "/research/"],
        disallowed_path_prefixes=["/public/classified/"],
        allowed_schemes={"https", "http"},
        allowed_ports={80, 443, 8443},
        allowed_purposes={
            AccessPurpose.RESEARCH_STUDY,
            AccessPurpose.CONTROLLED_EXPERIMENT,
        },
        required_statuses={
            AuthorizationStatus.TERMS_REVIEWED,
            AuthorizationStatus.DATA_USE_AUTHORIZED,
            AuthorizationStatus.APPROVED_FOR_EXPERIMENT,
        },
        source_status=SourceStatus.VERIFIED,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        allow_subdomains=False,
    )


def make_fixture_allowlist() -> TargetAllowlist:
    """Create a populated test allowlist with controlled synthetic companies."""
    allowlist = TargetAllowlist()
    allowlist.register_target(make_valid_acme_scope())
    return allowlist
