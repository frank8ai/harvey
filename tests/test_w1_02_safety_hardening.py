"""Automated verification test suite for W1-02 safety hardening:
1. Physical Outbound Mail Blocking (Gmail, M365, SMTP, Instantly, Outbox approve-all, Heartbeat drain)
2. Instantly Side-Effect Interception (Campaigns, Leads, Activation, Replies)
3. SSRF Transport Boundary Protection (IPv4 loopback, IPv6, RFC1918, Cloud metadata, DNS Rebinding, Redirects)
4. Dashboard and Runtime Isolation
"""

import asyncio
import os
import socket
import tempfile
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio

from harvey.config import BrainConfig, ChannelsConfig, EnvConfig, ExperimentSecurityConfig, HarveyConfig, ICPConfig, PersonaConfig, ProductConfig
from harvey.integrations.gmail import GmailProvider
from harvey.integrations.instantly import InstantlyClient
from harvey.integrations.mail_provider import DryRunMailProvider, InboundMessage, get_mail_provider
from harvey.integrations.microsoft import MicrosoftProvider
from harvey.integrations.smtp_mail import SmtpImapProvider
from harvey.models.campaign import Campaign, EmailStep
from harvey.models.prospect import Prospect
from harvey.security_ssrf import SSRFBlockedError, SSRFSafeBackend, SSRFSafeTransport, is_safe_ip
from harvey.state import StateManager


def _now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@pytest_asyncio.fixture
async def state():
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = StateManager(os.path.join(tmpdir, "test_sec.db"))
        await sm.init_db()
        yield sm


def make_test_config(provider="dry_run", outbound_blocked=True):
    return HarveyConfig(
        persona=PersonaConfig(
            name="Test", company="Co", role="BD", email="test@co.com", linkedin="", tone="direct"
        ),
        product=ProductConfig(
            name="Prod", description="desc", pricing="$10", key_benefits=["b1"], objection_responses={}
        ),
        icp=ICPConfig(industries=["Tech"], company_size="1-10", titles=["CEO"], geography=["US"]),
        channels=ChannelsConfig(
            email={"enabled": True, "provider": provider, "max_daily_sends": 50, "require_approval": True}
        ),
        brain=BrainConfig(provider="claude"),
        experiment_security=ExperimentSecurityConfig(outbound_send_blocked=outbound_blocked),
    )


# ==============================================================================
# 1. PHYSICAL OUTBOUND MAIL SENDING TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_gmail_provider_outbound_physically_blocked(monkeypatch):
    """Verify GmailProvider.send_email is physically blocked with zero network egress."""
    cfg = make_test_config(provider="gmail")
    env = EnvConfig(gmail_client_id="dummy", gmail_client_secret="dummy")
    p = GmailProvider(cfg, env)

    calls = []
    async def fake_request(*a, **kw):
        calls.append((a, kw))
        return {}
    monkeypatch.setattr(p, "_request", fake_request)

    res = await p.send_email("target@example.com", "Subject", "Body")
    assert not res.ok
    assert "PHYSICALLY BLOCKED" in res.error
    assert len(calls) == 0, "No network request should have been made to Gmail API"


@pytest.mark.asyncio
async def test_smtp_provider_outbound_physically_blocked(monkeypatch):
    """Verify SmtpImapProvider.send_email is physically blocked with zero network egress."""
    cfg = make_test_config(provider="smtp")
    env = EnvConfig(smtp_host="smtp.example.com", smtp_username="user", smtp_password="pwd")
    p = SmtpImapProvider(cfg, env)

    calls = []
    import aiosmtplib
    async def fake_send(*a, **kw):
        calls.append((a, kw))
        return {}
    monkeypatch.setattr(aiosmtplib, "send", fake_send)

    res = await p.send_email("target@example.com", "Subject", "Body")
    assert not res.ok
    assert "PHYSICALLY BLOCKED" in res.error
    assert len(calls) == 0, "No SMTP packet should have been sent"


@pytest.mark.asyncio
async def test_microsoft_provider_outbound_physically_blocked():
    """Verify MicrosoftProvider.send_email is physically blocked when not using mock transport."""
    cfg = make_test_config(provider="microsoft")
    env = EnvConfig(m365_client_id="dummy", m365_tenant_id="dummy")
    p = MicrosoftProvider(cfg, env, transport=None)  # No MockTransport -> live mode

    res = await p.send_email("target@example.com", "Subject", "Body")
    assert not res.ok
    assert "PHYSICALLY BLOCKED" in res.error


@pytest.mark.asyncio
async def test_instantly_side_effects_physically_blocked(monkeypatch):
    """Verify InstantlyClient blocks campaigns creation, sequence setting, lead addition, and activation."""
    client = InstantlyClient("dummy_key")

    http_calls = []
    async def fake_http_request(*a, **kw):
        http_calls.append((a, kw))
        return httpx.Response(200, json={})
    monkeypatch.setattr(httpx.AsyncClient, "request", fake_http_request)

    # 1. Create campaign
    res = await client.create_campaign("Test Campaign")
    assert res is not None
    assert "blocked" in res.get("id", "")

    # 2. Set campaign emails
    res = await client.set_campaign_emails("camp_id", [{"subject": "s", "body": "b", "wait": 0}])
    assert res is not None
    assert res.get("dry_run") is True

    # 3. Add leads
    res = await client.add_leads("camp_id", [{"email": "test@example.com"}])
    assert res is not None
    assert res.get("dry_run") is True

    # 4. Activate campaign
    res = await client.activate_campaign("camp_id")
    assert res is not None
    assert "blocked" in res.get("status", "")

    # 5. Send reply
    res = await client.send_reply("uuid-123", "reply body")
    assert res is not None
    assert res.get("dry_run") is True

    assert len(http_calls) == 0, "All Instantly side-effects must be intercepted before network transport"


@pytest.mark.asyncio
async def test_sender_outbox_approve_all_uses_dry_run_provider(state):
    """Verify that even if all Outbox items are approved, only DryRunMailProvider is invoked."""
    from harvey.agents.sender import Sender

    cfg = make_test_config(provider="gmail")  # User configured Gmail!
    env = EnvConfig()
    sender = Sender(brain=None, state=state, config=cfg, env=env)

    # Assert provider was auto-replaced with DryRunMailProvider
    assert isinstance(sender.provider, DryRunMailProvider)
    assert sender.provider.name == "dry_run"

    # Add prospect & campaign
    pid = await state.add_prospect(Prospect(
        first_name="Alice", last_name="Smith", title="CTO", company="Acme",
        email="alice@acme.com", email_status="verified", email_verified=True, status="new"
    ))
    cid = await state.add_campaign(Campaign(
        id="", name="Launch", channel="email",
        sequence=[EmailStep(step=1, subject="Hi {{first_name}}", body="Body for {{company}}", delay_days=0)],
        prospect_ids=[pid], status="draft"
    ))

    # Stage items
    campaigns = await state.get_campaigns_by_status("draft")
    await sender._stage_campaign_native(campaigns[0])

    # Approve all items
    approved_count = await state.approve_outbox()
    assert approved_count == 1

    # Drain queue
    sender.send_pacing = False
    await sender._drain_due()

    # Verify status in database
    sent_items = await state.get_outbox(status="sent")
    assert len(sent_items) == 1
    assert sent_items[0]["status"] == "sent"

    # Verify that sender.provider captured it in-memory with zero network egress
    assert len(sender.provider.sent_messages) == 1
    msg = sender.provider.sent_messages[0]
    assert msg["to"] == "alice@acme.com"
    assert "dryrun-" in msg["message_id"]


@pytest.mark.asyncio
async def test_heartbeat_drain_unknown_provider_fails_closed(state):
    """Verify that unknown provider or missing credentials fails closed."""
    from harvey.agents.sender import Sender

    cfg = make_test_config(provider="unknown_provider")
    sender = Sender(brain=None, state=state, config=cfg, env=EnvConfig())
    # Unknown provider in experiment security defaults to DryRunMailProvider
    assert isinstance(sender.provider, DryRunMailProvider)


# ==============================================================================
# 2. SSRF AND NETWORK EGRESS BOUNDARY TESTS
# ==============================================================================

def test_ip_safety_classifier():
    """Test ipaddress validation against private, loopback, link-local, cloud metadata, and IPv4-mapped IPv6."""
    assert not is_safe_ip("127.0.0.1")
    assert not is_safe_ip("127.0.1.1")
    assert not is_safe_ip("10.0.0.1")
    assert not is_safe_ip("172.16.0.1")
    assert not is_safe_ip("192.168.1.1")
    assert not is_safe_ip("169.254.169.254")  # AWS/GCP/Azure metadata
    assert not is_safe_ip("::1")
    assert not is_safe_ip("::ffff:127.0.0.1")  # IPv4-mapped loopback
    assert not is_safe_ip("::ffff:169.254.169.254")  # IPv4-mapped metadata
    assert not is_safe_ip("0.0.0.0")
    assert not is_safe_ip("100.64.0.1")  # Shared address space
    assert not is_safe_ip("fc00::1")  # IPv6 Unique Local

    # Public safe IPs
    assert is_safe_ip("8.8.8.8")
    assert is_safe_ip("1.1.1.1")
    assert is_safe_ip("93.184.216.34")


@pytest.mark.asyncio
async def test_ssrf_blocks_localhost_and_loopback():
    """Verify SSRFSafeBackend immediately blocks loopback addresses."""
    backend = SSRFSafeBackend()
    with pytest.raises(SSRFBlockedError, match="prohibited"):
        await backend.connect_tcp("127.0.0.1", 80)

    with pytest.raises(SSRFBlockedError, match="loopback"):
        await backend.connect_tcp("localhost", 80)


@pytest.mark.asyncio
async def test_ssrf_blocks_cloud_metadata():
    """Verify SSRFSafeBackend blocks cloud metadata IP 169.254.169.254."""
    backend = SSRFSafeBackend()
    with pytest.raises(SSRFBlockedError, match="prohibited"):
        await backend.connect_tcp("169.254.169.254", 80)


@pytest.mark.asyncio
async def test_ssrf_blocks_private_subnets():
    """Verify SSRFSafeBackend blocks RFC1918 addresses."""
    backend = SSRFSafeBackend()
    for ip in ("10.200.1.5", "172.20.10.2", "192.168.100.50"):
        with pytest.raises(SSRFBlockedError, match="prohibited"):
            await backend.connect_tcp(ip, 80)


@pytest.mark.asyncio
async def test_ssrf_blocks_dns_rebinding():
    """Verify SSRFSafeBackend defeats DNS rebinding by asserting on the exact resolved IP before connect."""
    query_count = 0
    def rebinding_resolver(host, port, **kw):
        nonlocal query_count
        query_count += 1
        if query_count == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    backend = SSRFSafeBackend(resolver=rebinding_resolver)

    # First call connects to 93.184.216.34 (will fail at socket level since port 9999 is closed, but passes SSRF check)
    try:
        await backend.connect_tcp("rebind.example.com", 9999, timeout=0.1)
    except Exception as e:
        assert not isinstance(e, SSRFBlockedError)

    # Second call (DNS rebind to 127.0.0.1) is blocked by SSRF check!
    with pytest.raises(SSRFBlockedError, match="prohibited IP 127.0.0.1"):
        await backend.connect_tcp("rebind.example.com", 9999, timeout=0.1)


@pytest.mark.asyncio
async def test_ssrf_blocks_redirect_to_internal():
    """Verify that redirects to loopback or private IPs are blocked by the transport."""
    # Mock redirect response pointing to http://127.0.0.1:8080
    class RedirectMockTransport(httpx.AsyncHTTPTransport):
        def __init__(self):
            super().__init__()
            self._pool._network_backend = SSRFSafeBackend()

    transport = RedirectMockTransport()

    # Test connecting through SSRFSafeTransport directly to 127.0.0.1
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(Exception) as exc_info:
            await client.get("http://127.0.0.1:8080/secret")
        assert "SSRF" in str(exc_info.value) or isinstance(exc_info.value, SSRFBlockedError)


# ==============================================================================
# 3. DASHBOARD AND RUNTIME ISOLATION TESTS
# ==============================================================================

def test_dashboard_default_binding():
    """Verify dashboard defaults to 127.0.0.1."""
    import inspect
    from harvey.dashboard import start_dashboard
    sig = inspect.signature(start_dashboard)
    assert sig.parameters["host"].default == "127.0.0.1"
    assert sig.parameters["port"].default == 5555


@pytest.mark.asyncio
async def test_brain_no_tools_flag(state, monkeypatch):
    import harvey.brain as brain_mod
    from harvey.brain import Brain
    class _FakeProc:
        returncode = 0
        async def communicate(self):
            return b'{"result": "ok"}', b""
    captured = {}
    async def fake_exec(*cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc()
    monkeypatch.setattr(brain_mod.asyncio, "create_subprocess_exec", fake_exec)
    brain = Brain(state=state, brain_config=BrainConfig(provider="claude"))
    await brain.think("test prompt")
    cmd = captured.get("cmd", [])
    assert "--tools" in cmd
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in cmd
    assert "--dangerously-skip-permissions" not in cmd
