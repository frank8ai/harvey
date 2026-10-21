"""Harvey Controlled Discovery Source Policy and Robots Gate Engine.

Strictly separates authorization status dimensions:
- SOURCE_DISCOVERED
- PUBLICLY_ACCESSIBLE
- ROBOTS_ALLOWED
- TERMS_REVIEWED
- DATA_USE_AUTHORIZED
- APPROVED_FOR_EXPERIMENT

Enforces:
- Fail-closed default deny for all companies, domains, and paths.
- No wildcard/subdomain auto-inheritance.
- Strict URL structural validation (HTTP/HTTPS only, no userinfo credentials, normalized port, IDN/punycode, trailing dot stripping).
- Offline robots.txt parsing with injected text or offline mock fetcher.
- Fail-closed handling for robots errors, missing policies, and unknown source status.
- Redirect target re-authorization validation.
- Expiration of authorization records.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import logging
import re
from typing import Callable, Dict, List, Optional, Set
import urllib.parse
import urllib.robotparser

logger = logging.getLogger("harvey.controlled_discovery.policy")


class AuthorizationStatus(str, Enum):
    """Discrete dimensions of legal and operational authorization.
    These must NOT be conflated: a site being publicly accessible does not mean
    its data use is authorized or approved for experiment.
    """
    SOURCE_DISCOVERED = "SOURCE_DISCOVERED"
    PUBLICLY_ACCESSIBLE = "PUBLICLY_ACCESSIBLE"
    ROBOTS_ALLOWED = "ROBOTS_ALLOWED"
    TERMS_REVIEWED = "TERMS_REVIEWED"
    DATA_USE_AUTHORIZED = "DATA_USE_AUTHORIZED"
    APPROVED_FOR_EXPERIMENT = "APPROVED_FOR_EXPERIMENT"


class AccessPurpose(str, Enum):
    """Declared access purposes for controlled research and discovery."""
    RESEARCH_STUDY = "RESEARCH_STUDY"
    CONTROLLED_EXPERIMENT = "CONTROLLED_EXPERIMENT"
    BENCHMARK_AUDIT = "BENCHMARK_AUDIT"
    COMMERCIAL_CRAWL = "COMMERCIAL_CRAWL"
    UNSPECIFIED = "UNSPECIFIED"


class SourceStatus(str, Enum):
    """Evaluation lifecycle status of a data source."""
    VERIFIED = "VERIFIED"
    REVIEW_PENDING = "REVIEW_PENDING"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class DecisionCode(str, Enum):
    """Deterministic decision codes returned by policy engine."""
    ALLOWED = "ALLOWED"
    DENIED_NOT_IN_ALLOWLIST = "DENIED_NOT_IN_ALLOWLIST"
    DENIED_COMPANY_MISMATCH = "DENIED_COMPANY_MISMATCH"
    DENIED_SUBDOMAIN_NOT_PERMITTED = "DENIED_SUBDOMAIN_NOT_PERMITTED"
    DENIED_SCHEME_UNSUPPORTED = "DENIED_SCHEME_UNSUPPORTED"
    DENIED_CREDENTIALS_PRESENT = "DENIED_CREDENTIALS_PRESENT"
    DENIED_PORT_PROHIBITED = "DENIED_PORT_PROHIBITED"
    DENIED_IP_LITERAL = "DENIED_IP_LITERAL"
    DENIED_MALFORMED_URL = "DENIED_MALFORMED_URL"
    DENIED_PATH_OUT_OF_SCOPE = "DENIED_PATH_OUT_OF_SCOPE"
    DENIED_DISALLOWED_CONTENT_TYPE = "DENIED_DISALLOWED_CONTENT_TYPE"
    DENIED_SOURCE_STATUS_FAIL_CLOSED = "DENIED_SOURCE_STATUS_FAIL_CLOSED"
    DENIED_PURPOSE_NOT_AUTHORIZED = "DENIED_PURPOSE_NOT_AUTHORIZED"
    DENIED_AUTHORIZATION_EXPIRED = "DENIED_AUTHORIZATION_EXPIRED"
    DENIED_INSUFFICIENT_PERMISSIONS = "DENIED_INSUFFICIENT_PERMISSIONS"
    DENIED_ROBOTS_DISALLOWED = "DENIED_ROBOTS_DISALLOWED"
    DENIED_ROBOTS_FETCH_FAILED = "DENIED_ROBOTS_FETCH_FAILED"
    DENIED_ROBOTS_POLICY_UNKNOWN = "DENIED_ROBOTS_POLICY_UNKNOWN"
    DENIED_REDIRECT_TARGET = "DENIED_REDIRECT_TARGET"


class RobotsFetchStatus(str, Enum):
    """Robots retrieval / parse status."""
    FETCHED_AND_PARSED = "FETCHED_AND_PARSED"
    FETCH_FAILED = "FETCH_FAILED"
    EMPTY_ALLOW_ALL = "EMPTY_ALLOW_ALL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NormalizedUrl:
    """Structured, normalized URL representation."""
    raw_url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    clean_url: str


@dataclass
class CompanyTargetScope:
    """Explicit target scope for an enterprise.
    Defaults to DENY: nothing is allowed unless explicitly added.
    """
    company_id: str
    primary_domain: str
    allowed_domains: Set[str] = field(default_factory=set)
    allowed_path_prefixes: List[str] = field(default_factory=list)
    disallowed_path_prefixes: List[str] = field(default_factory=list)
    allowed_schemes: Set[str] = field(default_factory=lambda: {"https", "http"})
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443})
    disallowed_content_types: Set[str] = field(default_factory=lambda: {
        "application/pdf",
        "application/zip",
        "application/octet-stream",
        "video/",
        "audio/",
        "image/",
    })
    allowed_purposes: Set[AccessPurpose] = field(default_factory=lambda: {
        AccessPurpose.RESEARCH_STUDY,
        AccessPurpose.CONTROLLED_EXPERIMENT,
    })
    required_statuses: Set[AuthorizationStatus] = field(default_factory=lambda: {
        AuthorizationStatus.TERMS_REVIEWED,
        AuthorizationStatus.DATA_USE_AUTHORIZED,
        AuthorizationStatus.APPROVED_FOR_EXPERIMENT,
    })
    source_status: SourceStatus = SourceStatus.UNKNOWN
    expires_at: Optional[datetime] = None
    allow_subdomains: bool = False


@dataclass
class TargetAllowlist:
    """Container for registered enterprise target policies.
    Contains ZERO pre-baked target companies by default.
    """
    _scopes_by_company: Dict[str, CompanyTargetScope] = field(default_factory=dict)
    _company_by_domain: Dict[str, str] = field(default_factory=dict)

    def register_target(self, target: CompanyTargetScope) -> None:
        """Register or update a company target scope."""
        domain = target.primary_domain.strip(".").lower()
        self._scopes_by_company[target.company_id] = target
        self._company_by_domain[domain] = target.company_id
        for alt in target.allowed_domains:
            self._company_by_domain[alt.strip(".").lower()] = target.company_id

    def get_scope_for_company(self, company_id: str) -> Optional[CompanyTargetScope]:
        return self._scopes_by_company.get(company_id)

    def get_company_for_domain(self, domain: str) -> Optional[str]:
        domain_clean = domain.strip(".").lower()
        return self._company_by_domain.get(domain_clean)

    def is_domain_registered(self, domain: str) -> bool:
        domain_clean = domain.strip(".").lower()
        return domain_clean in self._company_by_domain


@dataclass(frozen=True)
class PolicyDecision:
    """Deterministic decision result returned by the policy engine."""
    decision: DecisionCode
    allowed: bool
    company_id: Optional[str]
    url: str
    normalized_url: Optional[NormalizedUrl]
    reason: str
    authorization_statuses: Set[AuthorizationStatus] = field(default_factory=set)
    robots_status: RobotsFetchStatus = RobotsFetchStatus.UNKNOWN
    audit_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass(frozen=True)
class RedirectDecision:
    """Evaluation result for an HTTP redirect transition."""
    allowed: bool
    initial_url: str
    target_url: str
    initial_decision: PolicyDecision
    target_decision: PolicyDecision
    reason: str


class SourcePolicyEngine:
    """Pure deterministic engine governing controlled access, allowlist matching,
    discrete authorization status checking, and robots.txt gating.

    Never performs live external network requests.
    """

    def __init__(
        self,
        allowlist: Optional[TargetAllowlist] = None,
        user_agent: str = "HarveyControlledBot/1.0",
        robots_fetcher: Optional[Callable[[str], Optional[str]]] = None,
    ):
        self.allowlist = allowlist or TargetAllowlist()
        self.user_agent = user_agent
        # robots_fetcher must be an injected mock/offline fetcher
        self._robots_fetcher = robots_fetcher
        self._robots_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}
        self._robots_status_cache: Dict[str, RobotsFetchStatus] = {}

    @staticmethod
    def normalize_url(raw_url: str) -> NormalizedUrl:
        """Parse and normalize a raw URL strictly.
        Raises ValueError for malformed URLs, presence of userinfo, non-HTTP schemes,
        or invalid domains.
        """
        if not raw_url or not isinstance(raw_url, str):
            raise ValueError("URL cannot be empty or non-string")

        url_str = raw_url.strip()
        parsed = urllib.parse.urlsplit(url_str)

        # 1. Scheme check
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Prohibited or invalid scheme: {parsed.scheme}")

        # 2. Reject credentials (userinfo)
        if parsed.username or parsed.password or "@" in (parsed.netloc.split(":")[0]):
            raise ValueError("URLs containing embedded credentials/userinfo are strictly prohibited")

        # 3. Host normalization & IDN handling
        raw_host = parsed.hostname
        if not raw_host:
            raise ValueError("URL has missing or empty hostname")

        # Strip trailing dots from FQDN
        host_str = raw_host.rstrip(".").lower()

        # Check if host is an IP literal (we forbid direct IP crawling in controlled study)
        try:
            ipaddress.ip_address(host_str)
            raise ValueError(f"Direct IP address crawling prohibited: {host_str}")
        except ValueError as e:
            if "Direct IP address crawling prohibited" in str(e):
                raise
            pass

        # IDN / punycode encoding
        try:
            ascii_host = host_str.encode("idna").decode("ascii")
        except Exception as e:
            raise ValueError(f"IDN / punycode conversion failed for hostname {raw_host}: {e}") from e

        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", ascii_host):
            raise ValueError(f"Hostname contains invalid characters or pattern: {ascii_host}")

        # 4. Port normalization
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80

        # 5. Path normalization
        path = parsed.path
        if not path:
            path = "/"
        else:
            # Normalize double slashes and dot segments
            path = urllib.parse.urljoin("/", path)

        # 6. Query normalization (sort keys for canonicalization)
        query_str = ""
        if parsed.query:
            query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            query_params.sort(key=lambda x: x[0])
            query_str = urllib.parse.urlencode(query_params)

        # Clean canonical URL
        port_part = f":{port}" if (scheme == "https" and port != 443) or (scheme == "http" and port != 80) else ""
        clean_url = f"{scheme}://{ascii_host}{port_part}{path}"
        if query_str:
            clean_url = f"{clean_url}?{query_str}"

        return NormalizedUrl(
            raw_url=raw_url,
            scheme=scheme,
            host=ascii_host,
            port=port,
            path=path,
            query=query_str,
            clean_url=clean_url,
        )

    def inject_robots_txt(self, domain: str, robots_content: Optional[str]) -> None:
        """Inject offline robots.txt content directly into the policy engine cache."""
        domain_clean = domain.strip(".").lower()
        if robots_content is None:
            self._robots_status_cache[domain_clean] = RobotsFetchStatus.FETCH_FAILED
            if domain_clean in self._robots_cache:
                del self._robots_cache[domain_clean]
            return

        parser = urllib.robotparser.RobotFileParser()
        parser.parse(robots_content.splitlines())
        self._robots_cache[domain_clean] = parser
        self._robots_status_cache[domain_clean] = RobotsFetchStatus.FETCHED_AND_PARSED

    def _get_robots_parser(self, domain: str) -> tuple[Optional[urllib.robotparser.RobotFileParser], RobotsFetchStatus]:
        """Retrieve or fetch (via mock) robots.txt parser. Returns (parser, status)."""
        domain_clean = domain.strip(".").lower()
        if domain_clean in self._robots_status_cache:
            return self._robots_cache.get(domain_clean), self._robots_status_cache[domain_clean]

        if self._robots_fetcher is not None:
            try:
                content = self._robots_fetcher(domain_clean)
                if content is not None:
                    parser = urllib.robotparser.RobotFileParser()
                    parser.parse(content.splitlines())
                    self._robots_cache[domain_clean] = parser
                    self._robots_status_cache[domain_clean] = RobotsFetchStatus.FETCHED_AND_PARSED
                    return parser, RobotsFetchStatus.FETCHED_AND_PARSED
                else:
                    self._robots_status_cache[domain_clean] = RobotsFetchStatus.FETCH_FAILED
                    return None, RobotsFetchStatus.FETCH_FAILED
            except Exception as e:
                logger.warning("Robots fetcher failed for domain %s: %s", domain_clean, e)
                self._robots_status_cache[domain_clean] = RobotsFetchStatus.FETCH_FAILED
                return None, RobotsFetchStatus.FETCH_FAILED

        # No fetcher and not injected -> Fail-Closed UNKNOWN
        return None, RobotsFetchStatus.UNKNOWN

    def evaluate_url(
        self,
        url: str,
        company_id: Optional[str] = None,
        purpose: AccessPurpose = AccessPurpose.RESEARCH_STUDY,
        content_type: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> PolicyDecision:
        """Evaluate whether an outbound target URL is authorized under controlled discovery policy.

        Fail-Closed Principles:
        1. Malformed URLs or credentials -> DENIED
        2. Not in target allowlist -> DENIED
        3. Company ID mismatch -> DENIED
        4. Subdomain not explicitly approved -> DENIED
        5. Scheme or port not allowed -> DENIED
        6. Scope path mismatch -> DENIED
        7. Content type prohibited -> DENIED
        8. Source status UNKNOWN/REVOKED/SUSPENDED -> DENIED
        9. Authorization expired -> DENIED
        10. Insufficient required discrete authorizations -> DENIED
        11. Robots status unknown or failed -> DENIED (Fail-Closed)
        12. Robots disallowed -> DENIED
        """
        now = current_time or datetime.now(timezone.utc)

        # 1. Structural URL Parsing
        try:
            norm = self.normalize_url(url)
        except ValueError as e:
            err_msg = str(e)
            code = DecisionCode.DENIED_MALFORMED_URL
            if "credentials" in err_msg:
                code = DecisionCode.DENIED_CREDENTIALS_PRESENT
            elif "scheme" in err_msg:
                code = DecisionCode.DENIED_SCHEME_UNSUPPORTED
            elif "IP address crawling prohibited" in err_msg:
                code = DecisionCode.DENIED_IP_LITERAL
            return PolicyDecision(
                decision=code,
                allowed=False,
                company_id=company_id,
                url=url,
                normalized_url=None,
                reason=err_msg,
            )

        host = norm.host

        # 2. Allowlist domain check
        registered_company_id = self.allowlist.get_company_for_domain(host)
        target_scope: Optional[CompanyTargetScope] = None

        if registered_company_id:
            target_scope = self.allowlist.get_scope_for_company(registered_company_id)
        else:
            # Check parent domains for non-inherited subdomains
            parts = host.split(".")
            parent_found = False
            for i in range(1, len(parts) - 1):
                parent_candidate = ".".join(parts[i:])
                if self.allowlist.is_domain_registered(parent_candidate):
                    parent_found = True
                    parent_scope = self.allowlist.get_scope_for_company(
                        self.allowlist.get_company_for_domain(parent_candidate) or ""
                    )
                    if parent_scope and not parent_scope.allow_subdomains:
                        return PolicyDecision(
                            decision=DecisionCode.DENIED_SUBDOMAIN_NOT_PERMITTED,
                            allowed=False,
                            company_id=parent_scope.company_id,
                            url=url,
                            normalized_url=norm,
                            reason=(
                                f"Subdomain {host} does not inherit authorization from "
                                f"parent domain {parent_candidate}"
                            ),
                        )
                    elif parent_scope and parent_scope.allow_subdomains:
                        target_scope = parent_scope
                        break

            if not target_scope:
                return PolicyDecision(
                    decision=DecisionCode.DENIED_NOT_IN_ALLOWLIST,
                    allowed=False,
                    company_id=company_id,
                    url=url,
                    normalized_url=norm,
                    reason=f"Domain {host} is not registered in target allowlist",
                )

        # 3. Company ID match check
        if company_id is not None and target_scope.company_id != company_id:
            return PolicyDecision(
                decision=DecisionCode.DENIED_COMPANY_MISMATCH,
                allowed=False,
                company_id=company_id,
                url=url,
                normalized_url=norm,
                reason=(
                    f"Domain {host} belongs to company '{target_scope.company_id}', "
                    f"not requested company '{company_id}'"
                ),
            )

        # 4. Scheme & Port checks
        if norm.scheme not in target_scope.allowed_schemes:
            return PolicyDecision(
                decision=DecisionCode.DENIED_SCHEME_UNSUPPORTED,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Scheme {norm.scheme} is not in allowed schemes {target_scope.allowed_schemes}",
            )

        if norm.port not in target_scope.allowed_ports:
            return PolicyDecision(
                decision=DecisionCode.DENIED_PORT_PROHIBITED,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Port {norm.port} is not in allowed ports {target_scope.allowed_ports}",
            )

        # 5. Path checks
        # First check disallowed paths
        for dis in target_scope.disallowed_path_prefixes:
            if norm.path.startswith(dis):
                return PolicyDecision(
                    decision=DecisionCode.DENIED_PATH_OUT_OF_SCOPE,
                    allowed=False,
                    company_id=target_scope.company_id,
                    url=url,
                    normalized_url=norm,
                    reason=f"Path {norm.path} is prohibited by prefix '{dis}'",
                )

        # If allowed paths are specified, must match at least one
        if target_scope.allowed_path_prefixes:
            matched_prefix = False
            for allowed_pref in target_scope.allowed_path_prefixes:
                if norm.path.startswith(allowed_pref):
                    matched_prefix = True
                    break
            if not matched_prefix:
                return PolicyDecision(
                    decision=DecisionCode.DENIED_PATH_OUT_OF_SCOPE,
                    allowed=False,
                    company_id=target_scope.company_id,
                    url=url,
                    normalized_url=norm,
                    reason=f"Path {norm.path} is outside allowed path prefixes",
                )

        # 6. Content-Type check (if provided in header inspection / pre-flight)
        if content_type:
            ct_lower = content_type.lower().strip()
            for dis_ct in target_scope.disallowed_content_types:
                if dis_ct in ct_lower:
                    return PolicyDecision(
                        decision=DecisionCode.DENIED_DISALLOWED_CONTENT_TYPE,
                        allowed=False,
                        company_id=target_scope.company_id,
                        url=url,
                        normalized_url=norm,
                        reason=f"Content-Type {content_type} matches disallowed pattern '{dis_ct}'",
                    )

        # 7. Purpose check
        if purpose not in target_scope.allowed_purposes:
            return PolicyDecision(
                decision=DecisionCode.DENIED_PURPOSE_NOT_AUTHORIZED,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Access purpose {purpose} is not authorized for target",
            )

        # 8. Source Status Fail-Closed
        if target_scope.source_status != SourceStatus.VERIFIED:
            return PolicyDecision(
                decision=DecisionCode.DENIED_SOURCE_STATUS_FAIL_CLOSED,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Source status is '{target_scope.source_status}', required '{SourceStatus.VERIFIED}'",
            )

        # 9. Expiration check
        if target_scope.expires_at is not None:
            exp = target_scope.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                return PolicyDecision(
                    decision=DecisionCode.DENIED_AUTHORIZATION_EXPIRED,
                    allowed=False,
                    company_id=target_scope.company_id,
                    url=url,
                    normalized_url=norm,
                    reason=f"Authorization expired at {exp.isoformat()}",
                )

        # 10. Discrete Authorization Dimensions Check
        # Ensure all required statuses exist
        mandatory_statuses = {
            AuthorizationStatus.TERMS_REVIEWED,
            AuthorizationStatus.DATA_USE_AUTHORIZED,
            AuthorizationStatus.APPROVED_FOR_EXPERIMENT,
        }
        missing_statuses = mandatory_statuses.difference(target_scope.required_statuses)
        if missing_statuses:
            return PolicyDecision(
                decision=DecisionCode.DENIED_INSUFFICIENT_PERMISSIONS,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Missing mandatory authorization dimensions: {missing_statuses}",
                authorization_statuses=set(target_scope.required_statuses),
            )

        # 11. Robots.txt evaluation (Fail-closed)
        parser, rob_status = self._get_robots_parser(host)
        if rob_status == RobotsFetchStatus.UNKNOWN:
            return PolicyDecision(
                decision=DecisionCode.DENIED_ROBOTS_POLICY_UNKNOWN,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Robots.txt status unknown for domain {host}; fail-closed deny",
                authorization_statuses=set(target_scope.required_statuses),
                robots_status=rob_status,
            )

        if rob_status == RobotsFetchStatus.FETCH_FAILED:
            return PolicyDecision(
                decision=DecisionCode.DENIED_ROBOTS_FETCH_FAILED,
                allowed=False,
                company_id=target_scope.company_id,
                url=url,
                normalized_url=norm,
                reason=f"Robots.txt fetch failed for domain {host}; fail-closed deny",
                authorization_statuses=set(target_scope.required_statuses),
                robots_status=rob_status,
            )

        if parser is not None:
            # Note: urllib.robotparser.can_fetch requires a full URL or url-encoded path
            if not parser.can_fetch(self.user_agent, norm.clean_url):
                return PolicyDecision(
                    decision=DecisionCode.DENIED_ROBOTS_DISALLOWED,
                    allowed=False,
                    company_id=target_scope.company_id,
                    url=url,
                    normalized_url=norm,
                    reason=f"Path {norm.path} is disallowed by robots.txt for user-agent {self.user_agent}",
                    authorization_statuses=set(target_scope.required_statuses),
                    robots_status=rob_status,
                )

        # All gates passed: record all verified statuses including ROBOTS_ALLOWED
        effective_statuses = set(target_scope.required_statuses)
        effective_statuses.add(AuthorizationStatus.SOURCE_DISCOVERED)
        effective_statuses.add(AuthorizationStatus.PUBLICLY_ACCESSIBLE)
        effective_statuses.add(AuthorizationStatus.ROBOTS_ALLOWED)

        return PolicyDecision(
            decision=DecisionCode.ALLOWED,
            allowed=True,
            company_id=target_scope.company_id,
            url=url,
            normalized_url=norm,
            reason="All source policy, allowlist, purpose, and robots gates passed",
            authorization_statuses=effective_statuses,
            robots_status=rob_status,
        )

    def evaluate_redirect(
        self,
        initial_url: str,
        redirect_url: str,
        company_id: Optional[str] = None,
        purpose: AccessPurpose = AccessPurpose.RESEARCH_STUDY,
    ) -> RedirectDecision:
        """Evaluate redirect transition.
        Re-evaluates the target URL against allowlist, target scope, and robots gates.
        Cross-domain or cross-company redirection to an unauthorized target is strictly denied.
        """
        initial_decision = self.evaluate_url(initial_url, company_id=company_id, purpose=purpose)
        target_decision = self.evaluate_url(redirect_url, company_id=company_id, purpose=purpose)

        if not initial_decision.allowed:
            return RedirectDecision(
                allowed=False,
                initial_url=initial_url,
                target_url=redirect_url,
                initial_decision=initial_decision,
                target_decision=target_decision,
                reason=f"Initial URL was not authorized: {initial_decision.reason}",
            )

        if not target_decision.allowed:
            return RedirectDecision(
                allowed=False,
                initial_url=initial_url,
                target_url=redirect_url,
                initial_decision=initial_decision,
                target_decision=target_decision,
                reason=f"Redirect target was blocked by policy: {target_decision.reason}",
            )

        return RedirectDecision(
            allowed=True,
            initial_url=initial_url,
            target_url=redirect_url,
            initial_decision=initial_decision,
            target_decision=target_decision,
            reason="Redirect target successfully authorized under controlled discovery policy",
        )
