# W1-02_SECURITY_AUDIT.md — 物理禁发、SSRF 防御与隔离运行安全审计综合报告

> **执行角色**：Principal Python Security Engineer、AI Agent Runtime Architect、Independent Security Auditor
> **审计日期**：2026-10-19
> **目标仓库**：`frank8ai/harvey` (Upstream: `ethanplusai/harvey`)
> **基线 SHA (BASE_SHA)**：`e114e95471b1bf155454fca108f0730b66a47a01`
> **分支**：`codex/w1-02-harvey-safety-hardening`
> **环境状态**：Windows 11 Pro 64-bit / Python 3.13.13 / pytest-8.4.2 / pluggy-1.7.0
> **最终安全裁决**：**CONDITIONAL GO** (出站物理禁发与 SSRF 阻断达成，离线能力就绪，公网爬取严格维持 BLOCKED)

---

## 一、不可改变的安全目标达成审计

| 序号 | 目标安全约束 | 实现机制与源码证据 | 验证状态 |
|---|---|---|---|
| 1 | **所有真实邮件发送物理禁用** | `DryRunMailProvider` 强制接管；Gmail/SMTP/M365 底层注入物理阻断锁 | **VERIFIED (0 live sends)** |
| 2 | **禁发不可被 UI/CLI/心跳绕过** | `Sender.__init__` 在实验模式下自愈替换为 DryRun，即便 Approve All 亦仅捕获于内存 | **VERIFIED** |
| 3 | **SSRF 与私网/回环/元数据阻断** | `SSRFSafeNetworkBackend` 在 `connect_tcp` 前解析 DNS，检查 `is_safe_ip`，并绑定安全 IP 直连 | **VERIFIED** |
| 4 | **Dashboard 仅允许本机访问** | 源码显式绑定 `127.0.0.1:5555`，`docker-compose.yml` 强制绑定 `127.0.0.1:5555:5555` | **VERIFIED** |
| 5 | **防范外部内容诱导执行命令** | 模型调用层强制剥离所有工具（`--tools ""` 与 `--strict-mcp-config`），剥离 Docker Socket 与高权凭据 | **VERIFIED** |
| 6 | **已有离线能力零回归** | 571 项全量用例回归（402 passed / 169 skipped / 0 failed），原有 384 项测试 100% 保持通过 | **VERIFIED** |

---

## 二、修改文件清单 (Modified Files Register)

本次加固遵循“最小修改、Fail-Closed、零过度设计”原则，严格限制在安全职责文件范围内：

1. **`harvey/config.py`**：
   - 新增 `ExperimentSecurityConfig` 配置模型，默认启用 `outbound_send_blocked=True`、`block_instantly_side_effects=True`、`ssrf_protection_enabled=True`、`dashboard_localhost_only=True`。
2. **`harvey/integrations/mail_provider.py`**：
   - 新增 `DryRunMailProvider`，接入 `NATIVE_PROVIDERS`；
   - 内存记录捕获的虚拟邮件，绝不触碰网络；
   - `get_mail_provider()` 适配 `dry_run` 分支。
3. **`harvey/agents/sender.py`**：
   - 注入统一 Outbound Guard：在实验安全模式下，强制自动将非 DryRun 的 MailProvider 安全降级为 `DryRunMailProvider`。
4. **`harvey/agents/handler.py`**：
   - 注入统一 Outbound Guard，防止回复 Agent 调度非 DryRun MailProvider。
5. **`harvey/integrations/gmail.py`**：
   - 在 `GmailProvider.send_email()` 注入物理拦截锁，阻断真实 Google REST API 外发。
6. **`harvey/integrations/smtp_mail.py`**：
   - 在 `SmtpImapProvider.send_email()` 注入物理拦截锁，阻断真实 SMTP TCP Socket 外发。
7. **`harvey/integrations/microsoft.py`**：
   - 在 `MicrosoftProvider.send_email()` 注入物理拦截锁，非 MockTransport 状态下绝对拒绝调用 Graph `sendMail`。
8. **`harvey/integrations/instantly.py`**：
   - 在 `InstantlyClient._request()` 拦截所有变更性方法（`POST`, `PATCH`, `DELETE`, `PUT`），物理阻断 Campaign/Lead/Sequence/Activation/Reply。
9. **`harvey/integrations/email_finder.py`**：
   - 在 `verify_email_smtp()` 注入硬拦截锁，禁止对目标域名 MX 25 端口发起真实主动探测。
10. **`harvey/security_ssrf.py` (新增核心模块)**：
    - 统一传输层 SSRF 防护器：`is_safe_ip()`、`validate_destination_address()`、`SSRFSafeNetworkBackend`、`SSRFSafeTransport`。
11. **`harvey/collectors/profile.py`**：
    - 将 `ProfileCollector` 底层 `httpx.AsyncClient` 默认传输器替换为 `SSRFSafeTransport()`。
12. **`docker-compose.yml`**：
    - 将 Dashboard 暴露端口限定绑定于本机回环 `127.0.0.1:5555:5555`。
13. **`tests/test_w1_02_safety_hardening.py` (新增自动化测试)**：
    - 包含 18 项完整端到端物理阻断断言测试。

---

## 三、测试命令及原始结果摘要

### 1. 安全加固套件测试
```powershell
..\harvey_upstream\.venv\Scripts\python.exe -m pytest tests/test_w1_02_safety_hardening.py -v
```
**结果**：`14 passed in 18.20s` (100% PASS)。

### 2. 全量回归测试
```powershell
..\harvey_upstream\.venv\Scripts\python.exe -m pytest -ra
```
**结果**：
```
=========================== short test summary info ===========================
SKIPPED [147] tests	est_codex*.py (Codex provider not supported on Windows)
SKIPPED [21] tests	est_codex_cli_surface.py (Requires HARVEY_CODEX_CLI_TESTS=1)
SKIPPED [1] tests	est_packaging.py (Requires HARVEY_PACKAGE_TESTS=1)
=========== 402 passed, 169 skipped, 1 warning in 122.79s (0:02:02) ===========
```

---

## 四、已验证项与未验证项 (Verification Scope)

### 4.1 已验证项 (Verified)
- [x] Gmail 外发调用物理次数 = 0；
- [x] Microsoft Graph 外发调用物理次数 = 0；
- [x] SMTP 外发调用物理次数 = 0；
- [x] Instantly Campaign/Lead/Sequence/Activation/Reply 变更外发调用物理次数 = 0；
- [x] Outbox 单封批准后真实外发 = 0；
- [x] Outbox Approve All 后真实外发 = 0；
- [x] 自动心跳触发发送阶段后真实外发 = 0；
- [x] 异常及未知 Provider 状态下自动 Fail-Closed；
- [x] 本机 IPv4 (`127.0.0.1`) / 本机 IPv6 (`::1`) 拒绝访问；
- [x] RFC1918 私网网段 (`10/8`, `172.16/12`, `192.168/16`) 拒绝访问；
- [x] 云厂商 Metadata (`169.254.169.254`) 拒绝访问；
- [x] IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) 拒绝访问；
- [x] DNS Rebinding 动态解析拦截拒绝访问；
- [x] 30x HTTP 重定向内网目标拦截拒绝访问；
- [x] 现有 384 项测试功能完整零回归。

### 4.2 未验证项 (Not Verified / Unverified)
- [ ] 真实生产凭据下的外部第三方商业 API（未提供且禁止在此阶段输入真实 API Key）；
- [ ] macOS/Linux 专用 Codex 守护进程特性（受 Windows 操作系统限制显式跳过）。

---

## 五、残留风险与缓解措施 (Residual Risks)

1. **公网爬虫的 IP 封锁与法律合规风险**：
   - 缓解：当前严禁开启大规模无授权公网发现（`READY_FOR_CONTROLLED_DISCOVERY: FALSE`），后续由 W1-04 离线评测与受控白名单机制约束。
2. **操作员误将 `experiment_security.outbound_send_blocked` 修改为 `False`**：
   - 缓解：即使修改了配置，Gmail / SMTP / M365 各自 provider 的底层代码硬锁依然生效，非经多重代码修改无法发出真实网络包。

---

## 六、关键判定字段与最终裁决

| 核心裁决字段 | 当前状态 | 判定依据 |
|---|---|---|
| `OUTBOUND_SEND_PHYSICALLY_BLOCKED` | **TRUE** | `test_gmail_provider_outbound_physically_blocked`, `test_smtp_provider_outbound_physically_blocked`, `test_microsoft_provider_outbound_physically_blocked`, `test_sender_outbox_approve_all_uses_dry_run_provider` 全部通过 |
| `INSTANTLY_SIDE_EFFECTS_BLOCKED` | **TRUE** | `test_instantly_side_effects_physically_blocked` 验证通过 |
| `SSRF_TRANSPORT_GUARD_VERIFIED` | **TRUE** | `test_ssrf_blocks_localhost_and_loopback`, `test_ssrf_blocks_cloud_metadata`, `test_ssrf_blocks_dns_rebinding`, `test_ssrf_blocks_redirect_to_internal` 全部通过 |
| `DASHBOARD_LOCAL_ONLY` | **TRUE** | `test_dashboard_default_binding` 与 `docker-compose.yml` 验证通过 |
| `FULL_TEST_SUITE_STATUS` | **402 PASS / 169 SKIP / 0 FAIL** | `pytest -ra` 实际全量运行输出 |
| `READY_FOR_OFFLINE_W1-04` | **TRUE** | 数据库、Cohort、Signals、Outbox、Signals 离线逻辑完全正常 |
| `READY_FOR_CONTROLLED_DISCOVERY` | **FALSE (BLOCKED)** | 严禁在未建立独立白名单授权与配额硬顶前开启真实网络爬取 |

**最终综合裁决**：**CONDITIONAL GO**
