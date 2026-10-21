# W105_C_BUDGET_AUDIT.md — 跨进程硬预算、出网审计与可信采集回执架构设计与验证

> **审计执行人**：Principal FinOps Architect + Python Runtime Security Engineer  
> **基线分支 (BASE)**：`frank8ai/main` (`31ab128`) (已并入 PR #2 `100345b`)  
> **交付分支 (HEAD)**：`codex/w1-05-c-budget-audit`  
> **审计日期**：2026-10-21  
> **安全防护结论**：
> - `HARD_BUDGET_COMPONENT_READY = PASS`
> - `TRUSTED_RECEIPT_COMPONENT_READY = PASS`
> - `CONTROLLED_DISCOVERY_READY = HOLD`
> - `LIVE_OUTREACH_READY = FORBIDDEN`

---

## 1. 架构目标与职责边界

本任务只实现独立组件，不执行真实公网请求，不自动合并，不修改 Agent A/B、Harvey 现有 Collector、Config 或 Brain 文件。严格遵守并行文件所有权规范：

1. `harvey/controlled_discovery/budget.py`：跨进程原子硬预算账本与结算契约。
2. `harvey/controlled_discovery/audit.py`：结构化出网操作与敏感信息脱敏审计日志。
3. `harvey/controlled_discovery/receipt.py`：可信采集回执模型、验签与凭证类别隔离契约。
4. `tests/test_w105_budget_audit.py`：针对多进程争抢、超时保守计量、凭证篡改与无授权零预算的端到端物理断言测试。
5. `docs/audit/W105_C_BUDGET_AUDIT.md`：本交付架构说明书。

---

## 2. 核心组件设计与接口契约

### A. 硬预算与原子账本 (`harvey/controlled_discovery/budget.py`)
- **存储介质**：SQLite (WAL 模式 + `busy_timeout=30000` + `BEGIN IMMEDIATE` 互斥排他锁)。
- **跨进程原子性**：基于 SQLite 单写者排他事务与 `PRAGMA journal_mode=WAL`，确保高并发或多进程竞争最后一个令牌时，绝对不会出现超出上限的并发超卖（Over-allocation）。
- **Fail-Closed 规则**：
  - 未授权模式 (`authorized=False`)：所有外部出站预算强制为 0，发起任何预算预留均立即抛出 `BudgetUnauthorizedError`。
  - 单次 Run 上限：HTTP 请求数默认限制 100；搜索 API 次数默认限制 20；模型计费上限默认 $2.0；模型 Token 上限 500,000。
  - 每日上限：按 `created_date` 统计每日 HTTP 请求数上限 500。
  - 保守结算：若请求超时、网络中断或未知计费，结算保留全部预留值，杜绝因失败请求而“免费搭车”。
  - 幂等结算：每个 `reservation_id` 只能结算一次，重复结算抛出 `BudgetAlreadySettledError`。
- **重启恢复**：数据持久化于 `budget_reservations` 表，重启或跨进程实例化时自动汇总已结算与未结算预留量，预算不归零。

### B. 结构化出网审计 (`harvey/controlled_discovery/audit.py`)
- **字段契约**：
  - `run_id`, `target_id`, `original_url`, `resolved_host`, `resolved_ip`, `resolved_port`
  - `outbound_at`, `policy_decision`, `permit_id`, `budget_reservation_id`, `status`
  - `actual_cost_usd`, `evidence_id`, `event_type`, `retry_count`, `error_message`, `details_json`
- **安全防泄露规范 (Zero Secret Leakage)**：
  - 自动正则脱敏 URL 中的敏感 Query 参数 (`api_key`, `token`, `auth`, `secret`, `password` 等)。
  - 自动剥离与脱敏 HTTP Header 字典中的敏感标头 (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` 等)。
  - 错误日志 (`error_message`) 自动脱敏 `Bearer <token>` 与 `key=<val>` 模式。
- **审计存储真实性免责**：
  - 文档与代码明确声明：普通本地 SQLite 是追加型运维审计日志，**不声称具备抗系统底层写权限篡改的密码学不可篡改性**。

### C. 可信采集回执 (`harvey/controlled_discovery/receipt.py`)
- **严格凭证类别隔离**：
  - `UNTRUSTED_IMPORTED_BUNDLE`：外部导入或未经验证的数据包，校验结果为 `is_trusted=False`。
  - `OFFLINE_FIXTURE`：测试用静态夹具，严禁伪装为真实采集，校验状态固定为 `OFFLINE_FIXTURE_ACKNOWLEDGED` (`is_trusted=False`)。
  - `TRUSTED_COLLECTOR_RECEIPT`：经授权采集器私钥签发的真实验证回执。
- **内容防篡改与验签机制**：
  - 规范化签名串：`receipt_id|kind|run_id|collector_id|collected_url|collected_at|content_sha256|permit_ref|policy_decision_ref|key_id`。
  - HMAC-SHA256 签名计算，并使用 `hmac.compare_digest` 进行恒定时间比较。
  - 严格双重校验：校验 HMAC 签名的同时校验原始响应正文的真实 SHA-256，正文篡改 1 字节立即拒绝。
  - 拒绝伪造：丢弃或忽略输入字典中的 `verified=True` 声明，仅基于密钥验证结果判定信任。
  - 密钥安全：密钥由运行时注入，禁止硬编码进仓库或夹具。

---

## 3. 验证证据矩阵 (`tests/test_w105_budget_audit.py`)

| 测试用例 | 验证目标 | 预期结果 | 实测状态 |
|---|---|---|---|
| `test_two_processes_competing_for_last_budget_tokens` | 4个独立进程争夺最后1个预算令牌 | 恰好1个成功，3个抛出 `BudgetExceededError` | **PASSED** |
| `test_budget_persistence_across_restart` | 进程重启或重新实例化 Ledger | 历史结算与在途预留完整恢复，不归零 | **PASSED** |
| `test_over_budget_fails_closed` | 累计请求超过 Run 上限 | 立即抛出 `BudgetExceededError` | **PASSED** |
| `test_actual_charge_exceeding_reservation_blocks_subsequent` | 真实扣费超过预留且击穿总预算 | 阻断后续所有预算预留请求 | **PASSED** |
| `test_failed_requests_accounted_conservatively` | 请求超时/失败且未知结算消耗 | 保留全部预留预算，防止配额绕过 | **PASSED** |
| `test_duplicate_settlement_rejected` | 重复结算同一 reservation_id | 拒绝二次结算，抛出 `BudgetAlreadySettledError` | **PASSED** |
| `test_trusted_receipt_verification_and_tamper_detection` | 正常验签、正文篡改、伪造签名与假冒 verified | 正确验签；正文修改哈希不符；篡改签名被拒；用户输入 verified=True 被忽略 | **PASSED** |
| `test_audit_log_redacts_credentials_and_headers` | 出网审计日志记录带密钥的 URL/标头 | 敏感参数与 Token 均被 `[REDACTED]` | **PASSED** |
| `test_offline_fixture_never_masquerades_as_trusted_receipt` | 离线 Fixture 声明回执 | 判定为不可信离线夹具，严禁伪装真实采集 | **PASSED** |
| `test_unauthorized_mode_strictly_forbids_budget_allocation` | 未授权模式 (`authorized=False`) 下申请外部预算 | 强制预算为0，抛出 `BudgetUnauthorizedError` | **PASSED** |
| `test_unknown_pricing_defaults_to_forbidden` | 试图传入负数或非法未知预算 | 校验拦截，抛出 `ValueError` | **PASSED** |

**回归测试矩阵**：
- `test_w105_budget_audit.py`：11 passed
- `test_w1_02_safety_hardening.py`：21 passed
- `test_devtools_signals.py`：3 passed
- `test_devtools_collector.py`：23 passed
- `test_devtools_pipeline_e2e.py`：6 passed
- **合计 64 passed in 47.10s (100% 绿灯)**

---

## 4. 残余风险与后续演进

1. **残余风险**：
   - 本地 SQLite 在极端机器掉电情况下可能产生未提交预留，后续可结合心跳定时清理超时未结算的游离 reservation（Stale Reservation Reaper）。
   - 密钥管理目前通过函数入参注入，真实生产环境需结合 KMS、Vault 或受信环境变量载入。
2. **后续演进**：
   - 待 Agent D 介入并获得出网授权后，将 `HardBudgetLedger`、`OutboundAuditLogger` 与 `sign_collector_receipt` 接入最外层受控采集器边界。
