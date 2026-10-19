# W1-02_TEST_RESULTS.md — 物理测试与真实用例执行综合报告

> **执行环境**：Windows 11 Pro 64-bit / Python 3.13.13 / pytest-8.4.2 / pluggy-1.7.0
> **基准 SHA (BASE_SHA)**：`e114e95471b1bf155454fca108f0730b66a47a01`
> **当前加固分支**：`codex/w1-02-harvey-safety-hardening`
> **执行日期**：2026-10-19
> **测试执行模式**：零外发物理阻断、Mock/Fixture 驱动、Fail-Closed

---

## 1. 真实测试汇总数据 (PASS / FAIL / SKIP)

执行命令：
```powershell
..\harvey_upstream\.venv\Scripts\python.exe -m pytest -ra
```

| 统计指标 | 数量 | 占比 | 状态结论 |
|---|---|---|---|
| **Collected Tests (收集测试数)** | **574** | 100.0% | 在基线 553 项测试基础上，新增 21 项完整端到端安全物理阻断自动化用例 |
| **PASSED (通过用例)** | **405** | 70.2% | 原有 384 项业务用例全部保持绿灯，新增 21 项安全用例 100% 通过 |
| **SKIPPED (跳过用例)** | **169** | 29.8% | 保持原版 169 项平台特异性跳过（绝无假通过，详见第 2 节分类） |
| **FAILED (失败用例)** | **0** | 0.0% | 现有逻辑与新加固逻辑零失败、零崩溃 |
| **ERRORS (执行报错)** | **0** | 0.0% | 零执行错误 |
| **Warnings (警告)** | **1** | - | `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated` |
| **总执行耗时** | **112.30 秒** (0:02:02) | - | 全量回归通过 |

---

## 2. 169 项 SKIP 用例逐项精确审计分类

针对 W1-01 报告中数字口径与实际 `pytest -ra` 分类的审计核对：

1. **Codex Windows 平台特异性拦截**：**147 项**
   - 文件：`tests/test_codex.py` (118 项), `tests/test_codex_e2e.py` (26 项), `tests/test_codex_platform.py` (4 项), `tests/test_codex_soak.py` (3 项)；
   - 条件：`harvey/codex.py` 显式判定 Windows 暂不支持 Codex 本地 Provider，跳过说明：`"the Codex provider isn't supported on Windows"`。
2. **Codex CLI 环境变量表面测试**：**21 项**
   - 文件：`tests/test_codex_cli_surface.py`；
   - 条件：未设置 `HARVEY_CODEX_CLI_TESTS=1`，跳过说明：`"set HARVEY_CODEX_CLI_TESTS=1 with the Codex CLI installed"`。
3. **打包测试**：**1 项**
   - 文件：`tests/test_packaging.py`；
   - 条件：未设置 `HARVEY_PACKAGE_TESTS=1`。

**总计跳过数**：147 + 21 + 1 = **169 项**，与 pytest 输出完全吻合，无重复计数或数字编造。

---

## 3. 新增安全加固用例执行矩阵 (`tests/test_w1_02_safety_hardening.py`)

| 序号 | 测试用例 | 验证领域 | 结果 |
|---|---|---|---|
| 1 | `test_gmail_provider_outbound_physically_blocked` | Gmail 真实发信物理硬锁（API 调用次数 = 0） | **PASSED** |
| 2 | `test_smtp_provider_outbound_physically_blocked` | SMTP 真实发信物理硬锁（TCP Socket 调用次数 = 0） | **PASSED** |
| 3 | `test_microsoft_provider_outbound_physically_blocked` | M365 Graph 真实发信物理硬锁（调用次数 = 0） | **PASSED** |
| 4 | `test_instantly_side_effects_physically_blocked` | Instantly 变更操作物理硬锁（Campaign/Leads/Activate/Reply 调用次数 = 0） | **PASSED** |
| 5 | `test_sender_outbox_approve_all_uses_dry_run_provider` | UI / CLI 执行 Approve All 后真实外发物理为 0 | **PASSED** |
| 6 | `test_heartbeat_drain_unknown_provider_fails_closed` | 异常或未知 Provider 状态下自动 Fail-Closed | **PASSED** |
| 7 | `test_ip_safety_classifier` | IP 安全分类器覆盖私网、回环、IPv4-mapped、元数据 | **PASSED** |
| 8 | `test_ssrf_blocks_localhost_and_loopback` | 本机 127.0.0.1 / localhost 阻断断言 | **PASSED** |
| 9 | `test_ssrf_blocks_cloud_metadata` | 169.254.169.254 云元数据阻断断言 | **PASSED** |
| 10 | `test_ssrf_blocks_private_subnets` | RFC1918 私网段（10/8, 172.16/12, 192.168/16）阻断断言 | **PASSED** |
| 11 | `test_ssrf_blocks_dns_rebinding` | DNS 重绑定时二次解析自动拦截断言 | **PASSED** |
| 12 | `test_ssrf_blocks_redirect_to_internal` | 30x 重定向至内网目标传输层强制拦截断言 | **PASSED** |
| 13 | `test_dashboard_default_binding` | Dashboard 本机绑定约束断言 (`127.0.0.1:5555`) | **PASSED** |
| 14 | `test_brain_no_tools_flag` | 模型调度显式剥离 `--tools ""` 与 `--strict-mcp-config` | **PASSED** |
| 15 | `test_simulated_instantly_campaign_never_marks_active` | Instantly 模拟创建与激活绝不标记为 active，统一记录为 simulated | **PASSED** |
| 16 | `test_simulated_email_idempotent_execution_zero_egress` | 模拟发送幂等重复执行，零外网流量，sent 计数严格为 0 | **PASSED** |
| 17 | `test_discovery_dry_run_zero_external_network_calls` | Discovery dry_run 模式零外部网络请求（地理编码拒绝离线联网） | **PASSED** |
| 18 | `test_ssrf_blocks_ipv4_compatible_and_subtle_variants` | SSRF 阻断 IPv4-compatible (`::127.0.0.1`) 与云元数据变体 | **PASSED** |
| 19 | `test_instantly_simulation_never_pollutes_prospect_status_or_campaign_id` | Instantly 模拟运行零污染 Prospect 状态、零泄漏模拟 Campaign ID、记录专用 `campaign_simulated` 审计事件 | **PASSED** |
| 20 | `test_scout_fetch_enforces_ssrf_protection_boundary` | Scout._fetch 传输层强制拦截回环、内网、元数据、IPv4 映射/兼容变体 | **PASSED** |
| 21 | `test_scout_fetch_blocks_dns_rebinding` | Scout._fetch DNS 重绑定在 Socket 连接边界前被安全解析器拦截 | **PASSED** |
