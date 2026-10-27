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


class TestSecurityDefectsRedReproductions:
    """Explicit Red-before-Green reproductions for SEC-01 through SEC-04."""

    def test_sec_01_reject_ambiguous_and_traversal_encodings(self, engine_with_acme):
        # %2e%2e, %2f, %5c, %25 multi-layer, raw backslash, null bytes
        malicious_urls = [
            "https://acme-corp.test/public/%2e%2e/admin",
            "https://acme-corp.test/public/%2E%2E/admin",
            "https://acme-corp.test/public/%2e%2e%2fadmin",
            "https://acme-corp.test/public/%252e%252e/admin",
            "https://acme-corp.test/public/%25252e/admin",
            "https://acme-corp.test/public/%2fadmin",
            "https://acme-corp.test/public/%2Fadmin",
            "https://acme-corp.test/public/%5cadmin",
            "https://acme-corp.test/public/%5Cadmin",
            "https://acme-corp.test/public/..\\admin",
            "https://acme-corp.test/public/%00admin",
        ]
        for u in malicious_urls:
            decision = engine_with_acme.evaluate_url(u)
            assert not decision.allowed, f"Expected {u} to be blocked"
            assert decision.decision in (
                DecisionCode.DENIED_MALFORMED_URL,
                DecisionCode.DENIED_PATH_OUT_OF_SCOPE,
            ), f"Unexpected decision code for {u}: {decision.decision}"

    def test_sec_02_empty_allowed_path_prefixes_must_fail_closed(self, engine_with_acme):
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = []  # Empty allowed prefixes! Must reject everything

        decision = engine_with_acme.evaluate_url("https://acme-corp.test/public/index.html")
        assert not decision.allowed
        assert decision.decision == DecisionCode.DENIED_PATH_OUT_OF_SCOPE
        assert "No allowed path prefixes configured" in decision.reason or "outside allowed" in decision.reason

        # Explicit root "/" should be required to allow the whole site
        scope.allowed_path_prefixes = ["/"]
        decision_root = engine_with_acme.evaluate_url("https://acme-corp.test/public/index.html")
        assert decision_root.allowed
        assert decision_root.decision == DecisionCode.ALLOWED

    def test_sec_04_prefix_boundary_confusion_blocked(self, engine_with_acme):
        scope = engine_with_acme.allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = ["/public"]

        # /publicity and /public_notes must be blocked despite starting with string "/public"
        boundary_evasions = [
            "https://acme-corp.test/publicity",
            "https://acme-corp.test/publicity/index.html",
            "https://acme-corp.test/public_notes",
        ]
        for u in boundary_evasions:
            decision = engine_with_acme.evaluate_url(u)
            assert not decision.allowed, f"Expected boundary evasion {u} to be blocked"
            assert decision.decision == DecisionCode.DENIED_PATH_OUT_OF_SCOPE

        # Legitimate sub-paths under /public must be allowed
        legit_urls = [
            "https://acme-corp.test/public",
            "https://acme-corp.test/public/",
            "https://acme-corp.test/public/about",
        ]
        for u in legit_urls:
            decision = engine_with_acme.evaluate_url(u)
            assert decision.allowed, f"Expected legitimate path {u} to be allowed"

    def test_sec_03_rfc9309_longest_match_and_order_independence(self):
        allowlist = make_fixture_allowlist()
        scope = allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = ["/"]
        engine = SourcePolicyEngine(allowlist=allowlist)

        # Test Case 1: Disallow /p vs Allow /page -> /page must be ALLOWED because /page is longer
        # Even if Disallow comes first
        robots_order1 = "User-agent: *\nDisallow: /p\nAllow: /page\n"
        engine.inject_robots_txt("acme-corp.test", robots_order1)
        decision = engine.evaluate_url("https://acme-corp.test/page")
        assert decision.allowed, "Longest rule (/page) must win over shorter rule (/p)"

        # Test Case 2: Order reversed
        robots_order2 = "User-agent: *\nAllow: /page\nDisallow: /p\n"
        engine.inject_robots_txt("acme-corp.test", robots_order2)
        decision = engine.evaluate_url("https://acme-corp.test/page")
        assert decision.allowed, "Rule order must not change longest-match outcome"

    def test_sec_03_rfc9309_equal_length_allow_wins_over_disallow(self):
        allowlist = make_fixture_allowlist()
        scope = allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = ["/"]
        engine = SourcePolicyEngine(allowlist=allowlist)

        # When Allow and Disallow have the exact same length, RFC 9309 states Allow wins
        robots_disallow_first = "User-agent: *\nDisallow: /page\nAllow: /page\n"
        engine.inject_robots_txt("acme-corp.test", robots_disallow_first)
        decision = engine.evaluate_url("https://acme-corp.test/page")
        assert decision.allowed, "Equal length tie: Allow must win over Disallow"

    def test_sec_03_rfc9309_wildcards_and_end_anchors(self):
        allowlist = make_fixture_allowlist()
        scope = allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = ["/"]
        engine = SourcePolicyEngine(allowlist=allowlist)

        robots_rules = "User-agent: *\nDisallow: /*.php$\nDisallow: /private*secret$\nAllow: /\n"
        engine.inject_robots_txt("acme-corp.test", robots_rules)

        # /*.php$ matches /index.php but NOT /index.php?query=1 or /index.phpx
        d1 = engine.evaluate_url("https://acme-corp.test/index.php")
        assert not d1.allowed
        assert d1.decision == DecisionCode.DENIED_ROBOTS_DISALLOWED

        d2 = engine.evaluate_url("https://acme-corp.test/index.php?query=1")
        assert d2.allowed

        d3 = engine.evaluate_url("https://acme-corp.test/private123secret")
        assert not d3.allowed
        assert d3.decision == DecisionCode.DENIED_ROBOTS_DISALLOWED

        d4 = engine.evaluate_url("https://acme-corp.test/private123secret/more")
        assert d4.allowed

    def test_sec_03_rfc9309_multiple_user_agents_and_case_sensitivity(self):
        allowlist = make_fixture_allowlist()
        scope = allowlist.get_scope_for_company("comp_acme_test_001")
        scope.allowed_path_prefixes = ["/"]
        # Set user agent to HarveyControlledBot/1.0
        engine = SourcePolicyEngine(allowlist=allowlist, user_agent="HarveyControlledBot/1.0")

        robots_txt = "User-agent: Googlebot\nDisallow: /\n\nUser-agent: HarveyControlledBot\nDisallow: /private/\nAllow: /public/\nAllow: /CaseSensitive/\n\nUser-agent: *\nDisallow: /public/\n"
        engine.inject_robots_txt("acme-corp.test", robots_txt)

        # Specific UA group should match HarveyControlledBot instead of Googlebot or *
        d1 = engine.evaluate_url("https://acme-corp.test/public/data")
        assert d1.allowed

        # Case sensitivity: /CaseSensitive/ allowed, /casesensitive/ disallowed or falls through
        d2 = engine.evaluate_url("https://acme-corp.test/CaseSensitive/doc")
        assert d2.allowed
    def test_revoked_and_suspended_authorization_denied(self, engine_with_acme):
        scope = engine_with_acme.allowlist.get_scope_for_company('comp_acme_test_001')

        # Suspended
        scope.source_status = SourceStatus.SUSPENDED
        d_susp = engine_with_acme.evaluate_url('https://acme-corp.test/public/valid')
        assert not d_susp.allowed
        assert d_susp.decision == DecisionCode.DENIED_SOURCE_STATUS_FAIL_CLOSED

        # Revoked
        scope.source_status = SourceStatus.REVOKED
        d_rev = engine_with_acme.evaluate_url('https://acme-corp.test/public/valid')
        assert not d_rev.allowed
        assert d_rev.decision == DecisionCode.DENIED_SOURCE_STATUS_FAIL_CLOSED

    def test_redirect_to_out_of_scope_or_traversal_path_blocked(self, engine_with_acme):
        # Redirect target in scope path
        r1 = engine_with_acme.evaluate_redirect(
            'https://acme-corp.test/public/start',
            'https://acme-corp.test/public/ok'
        )
        assert r1.allowed

        # Redirect target out-of-scope path (/other)
        r2 = engine_with_acme.evaluate_redirect(
            'https://acme-corp.test/public/start',
            'https://acme-corp.test/unauthorized/leak'
        )
        assert not r2.allowed
        assert r2.target_decision.decision == DecisionCode.DENIED_PATH_OUT_OF_SCOPE

        # Redirect target with traversal encoding
        r3 = engine_with_acme.evaluate_redirect(
            'https://acme-corp.test/public/start',
            'https://acme-corp.test/public/%2e%2e/admin'
        )
        assert not r3.allowed
        assert r3.target_decision.decision == DecisionCode.DENIED_MALFORMED_URL

    def test_zero_real_network_calls_invariant(self, monkeypatch, engine_with_acme):
        # Ensure that evaluate_url and evaluate_redirect NEVER perform socket/network calls
        import socket
        def blow_up(*args, **kwargs):
            raise AssertionError('Real network socket call attempted!')
        monkeypatch.setattr(socket, 'socket', blow_up)

        # Evaluate a URL and redirect
        d = engine_with_acme.evaluate_url('https://acme-corp.test/public/index.html')
        assert d.allowed
        r = engine_with_acme.evaluate_redirect(
            'https://acme-corp.test/public/index.html',
            'https://acme-corp.test/public/next'
        )
        assert r.allowed

