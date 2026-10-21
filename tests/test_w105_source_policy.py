"""Unit and integration tests for Harvey Controlled Discovery Source Policy Engine (W1-05-A).

Strictly covers:
1. Unregistered domain / allowlist denial (Fail-Closed).
2. Company ID mismatch denial.
3. Subdomain isolation (no auto-inheritance from parent domain).
4. Path out of scope & prefix restrictions.
5. Disallowed content types.
6. robots.txt disallowed path denial.
7. robots.txt fetch failure & unknown policy fail-closed denial.
8. Redirect targets re-authorization validation (cross-domain & cross-company).
9. URL normalization, URL-encoding, IDN/punycode, trailing dots, ports, case insensitivity.
10. Credentials present in URL & non-HTTP(S) scheme denial.
11. Expired authorization denial.
12. Non-verified source status fail-closed denial.
13. Discrete authorization dimensions separation.
14. IP literal crawling prohibition.
"""

from datetime import datetime, timedelta, timezone
import pytest

from harvey.controlled_discovery.policy import (
    AccessPurpose,
    AuthorizationStatus,
    CompanyTargetScope,
    DecisionCode,
    NormalizedUrl,
    PolicyDecision,
    RedirectDecision,
    RobotsFetchStatus,
    SourcePolicyEngine,
    SourceStatus,
    TargetAllowlist,
)
from tests.fixtures.w105_policy_fixtures import (
    MOCK_ROBOTS_TXT_ACME,
    MOCK_ROBOTS_TXT_ALLOW_ALL,
    MOCK_ROBOTS_TXT_DISALLOW_ALL,
    make_fixture_allowlist,
    make_valid_acme_scope,
)


@pytest.fixture
def engine_with_acme() -> SourcePolicyEngine:
    allowlist = make_fixture_allowlist()
    engine = SourcePolicyEngine(allowlist=allowlist)
    engine.inject_robots_txt("acme-corp.test", MOCK_ROBOTS_TXT_ACME)
    engine.inject_robots_txt("alt.acme-corp.test", MOCK_ROBOTS_TXT_ACME)
    return engine


class TestUrlNormalization:
    """Verify strict URL structural parsing, normalization and defense."""

    def test_valid_http_and_https_normalization(self):
        norm1 = SourcePolicyEngine.normalize_url("https://example.com/path?b=2&a=1")
        assert norm1.scheme == "https"
        assert norm1.host == "example.com"
        assert norm1.port == 443
        assert norm1.path == "/path"
        assert norm1.query == "a=1&b=2"
        assert norm1.clean_url == "https://example.com/path?a=1&b=2"

        norm2 = SourcePolicyEngine.normalize_url("http://example.com:8080/deep/resource")
        assert norm2.scheme == "http"
        assert norm2.host == "example.com"
        assert norm2.port == 8080
        assert norm2.clean_url == "http://example.com:8080/deep/resource"

    def test_trailing_dot_and_case_normalization(self):
        norm = SourcePolicyEngine.normalize_url("HTTPS://Acme-Corp.TEST./Public/About")
        assert norm.host == "acme-corp.test"
        assert norm.scheme == "https"
        assert norm.clean_url == "https://acme-corp.test/Public/About"

    def test_idn_punycode_conversion(self):
        # IDN domain test (e.g. münchen.test)
        norm = SourcePolicyEngine.normalize_url("https://xn--mnchen-3ya.test/public")
        assert norm.host == "xn--mnchen-3ya.test"
        assert norm.clean_url == "https://xn--mnchen-3ya.test/public"

    def test_reject_credentials_in_url(self):
        with pytest.raises(ValueError, match="embedded credentials"):
            SourcePolicyEngine.normalize_url("https://user:pass@example.com/secret")

        with pytest.raises(ValueError, match="embedded credentials"):
            SourcePolicyEngine.normalize_url("https://admin@example.com/api")

    def test_reject_unsupported_schemes(self):
        for bad_scheme in ["ftp://example.com/file", "file:///etc/passwd", "gopher://bad.com", "smtp://mail.com"]:
            with pytest.raises(ValueError, match="Prohibited or invalid scheme"):
                SourcePolicyEngine.normalize_url(bad_scheme)

    def test_reject_ip_literals(self):
        with pytest.raises(ValueError, match="Direct IP address crawling prohibited"):
            SourcePolicyEngine.normalize_url("https://127.0.0.1/public")

        with pytest.raises(ValueError, match="Direct IP address crawling prohibited"):
            SourcePolicyEngine.normalize_url("https://[::1]/public")

        with pytest.raises(ValueError, match="Direct IP address crawling prohibited"):
            SourcePolicyEngine.normalize_url("http://192.168.1.10/")


class TestAllowlistAndScopeGates:
    """Verify allowlist boundaries, company IDs, and path prefix enforcement."""

    def test_not_in_allowlist_denied(self, engine_with_acme):
        decision = engine_with_acme.evaluate_url("https://unauthorized-domain.com/public")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_NOT_IN_ALLOWLIST
        assert "not registered in target allowlist" in decision.reason

    def test_company_mismatch_denied(self, engine_with_acme):
        # Registered company is 'comp_acme_test_001', request asks for 'other_company'
        decision = engine_with_acme.evaluate_url(
            "https://acme-corp.test/public/index.html",
            company_id="other_company_999",
        )
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_COMPANY_MISMATCH
        assert "not requested company" in decision.reason

    def test_subdomain_does_not_auto_inherit(self, engine_with_acme):
        # acme-corp.test is in allowlist, but sub.acme-corp.test is NOT explicitly registered
        decision = engine_with_acme.evaluate_url("https://sub.acme-corp.test/public")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_SUBDOMAIN_NOT_PERMITTED
        assert "does not inherit authorization" in decision.reason

    def test_allowed_explicit_alternative_domain(self, engine_with_acme):
        # alt.acme-corp.test is explicitly registered in allowed_domains
        decision = engine_with_acme.evaluate_url("https://alt.acme-corp.test/public/index")
        assert decision.allowed
        assert decision.decision == DecisionCode.ALLOWED
        assert decision.company_id == "comp_acme_test_001"

    def test_path_prefix_out_of_scope_denied(self, engine_with_acme):
        # /other is not in ['/public/', '/research/']
        decision = engine_with_acme.evaluate_url("https://acme-corp.test/other/page")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_PATH_OUT_OF_SCOPE

    def test_path_explicitly_disallowed_prefix(self, engine_with_acme):
        # /public/classified/ is explicitly disallowed even under /public/
        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/classified/docs")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_PATH_OUT_OF_SCOPE
        assert "prohibited by prefix '/public/classified/'" in decision.reason

    def test_disallowed_content_type_denied(self, engine_with_acme):
        decision = engine_with_acme.evaluate_url(
            "https://acme-corp.test/public/file.pdf",
            content_type="application/pdf",
        )
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_DISALLOWED_CONTENT_TYPE


class TestRobotsTxtGates:
    """Verify fail-closed robots.txt gating."""

    def test_robots_allowed_path_passes(self, engine_with_acme):
        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/welcome")
        assert decision.allowed
        assert decision.decision == DecisionCode.ALLOWED
        assert AuthorizationStatus.ROBOTS_ALLOWED in decision.authorization_statuses
        assert decision.robots_status == RobotsFetchStatus.FETCHED_AND_PARSED

    def test_robots_disallowed_path_denied(self, engine_with_acme):
        # /admin/ is disallowed in MOCK_ROBOTS_TXT_ACME
        # First grant /admin/ in company scope to isolate the robots gate
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes.append("/admin/")

        decision = engine_with_acme.evaluate_url("https://acme-corp.test/admin/dashboard")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_ROBOTS_DISALLOWED
        assert "disallowed by robots.txt" in decision.reason

    def test_robots_unknown_fail_closed(self):
        # No robots injected and no fetcher configured
        allowlist = make_fixture_allowlist()
        engine = SourcePolicyEngine(allowlist=allowlist)

        decision = engine.evaluate_url("https://acme-corp.test/public/data")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_ROBOTS_POLICY_UNKNOWN
        assert decision.robots_status == RobotsFetchStatus.UNKNOWN
        assert "Robots.txt status unknown" in decision.reason

    def test_robots_fetch_failed_fail_closed(self, engine_with_acme):
        # Inject failure (None content)
        engine_with_acme.inject_robots_txt("acme-corp.test", None)
        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/data")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_ROBOTS_FETCH_FAILED
        assert decision.robots_status == RobotsFetchStatus.FETCH_FAILED

    def test_mock_fetcher_integration(self):
        def mock_fetcher(domain: str):
            if domain == "acme-corp.test":
                return MOCK_ROBOTS_TXT_ALLOW_ALL
            return None

        allowlist = make_fixture_allowlist()
        engine = SourcePolicyEngine(allowlist=allowlist, robots_fetcher=mock_fetcher)

        decision = engine.evaluate_url("https://acme-corp.test/public/ok")
        assert decision.allowed
        assert decision.robots_status == RobotsFetchStatus.FETCHED_AND_PARSED


class TestRedirectAndLifecycleGates:
    """Verify redirects, authorization expiration, and discrete status separation."""

    def test_redirect_to_same_scope_allowed(self, engine_with_acme):
        red_decision = engine_with_acme.evaluate_redirect(
            initial_url="https://acme-corp.test/public/initial",
            redirect_url="https://acme-corp.test/public/target",
        )
        assert red_decision.allowed
        assert red_decision.initial_decision.allowed
        assert red_decision.target_decision.allowed

    def test_redirect_to_unregistered_domain_blocked(self, engine_with_acme):
        red_decision = engine_with_acme.evaluate_redirect(
            initial_url="https://acme-corp.test/public/initial",
            redirect_url="https://evil-redirect.test/capture",
        )
        assert not red_decision.allowed
        assert "Redirect target was blocked" in red_decision.reason
        assert red_decision.target_decision.decision == DecisionCode.DENIED_NOT_IN_ALLOWLIST

    def test_redirect_to_different_company_blocked(self, engine_with_acme):
        # Register another company
        scope2 = CompanyTargetScope(
            company_id="comp_beta_test_002",
            primary_domain="beta-corp.test",
            allowed_path_prefixes=["/public/"],
            source_status=SourceStatus.VERIFIED,
        )
        engine_with_acme.allowlist.register_target(scope2)
        engine_with_acme.inject_robots_txt("beta-corp.test", MOCK_ROBOTS_TXT_ALLOW_ALL)

        # Evaluate redirect for company comp_acme_test_001
        red_decision = engine_with_acme.evaluate_redirect(
            initial_url="https://acme-corp.test/public/initial",
            redirect_url="https://beta-corp.test/public/home",
            company_id="comp_acme_test_001",
        )
        assert not red_decision.allowed
        assert red_decision.target_decision.decision == DecisionCode.DENIED_COMPANY_MISMATCH

    def test_expired_authorization_denied(self, engine_with_acme):
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.expires_at = datetime.now(timezone.utc) - timedelta(days=1)

        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/valid")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_AUTHORIZATION_EXPIRED
        assert "Authorization expired" in decision.reason

    def test_source_status_not_verified_denied(self, engine_with_acme):
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.source_status = SourceStatus.UNKNOWN

        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/valid")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_SOURCE_STATUS_FAIL_CLOSED
        assert "Source status is 'SourceStatus.UNKNOWN'" in decision.reason

    def test_unauthorized_purpose_denied(self, engine_with_acme):
        # Commercial crawl is not in allowed_purposes
        decision = engine_with_acme.evaluate_url(
            "https://acme-corp.test/public/valid",
            purpose=AccessPurpose.COMMERCIAL_CRAWL,
        )
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_PURPOSE_NOT_AUTHORIZED

    def test_discrete_status_dimensions_not_conflated(self, engine_with_acme):
        # Missing mandatory terms or experiment approval
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.required_statuses = {AuthorizationStatus.TERMS_REVIEWED}  # Missing DATA_USE_AUTHORIZED & APPROVED_FOR_EXPERIMENT

        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/valid")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_INSUFFICIENT_PERMISSIONS
        assert "Missing mandatory authorization dimensions" in decision.reason
