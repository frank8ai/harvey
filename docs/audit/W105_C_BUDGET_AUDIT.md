# W105_C_BUDGET_AUDIT.md — 跨进程硬预算、出网审计与可信采集回执架构设计与安全整改验证

> **审计执行人**：Principal FinOps Architect + Python Runtime Security Engineer
> **基线分支 (BASE)**：`frank8ai/main` (`31ab128`) (已并入 PR #2 `100345b`)
> **交付分支 (HEAD)**：`codex/w1-05-c-budget-audit` (PR #4 整改闭环)
> **最新整改日期**：2026-10-24
> **安全防护结论**：
> - `HARD_BUDGET_READY = PASS`
> - `TRUSTED_RECEIPT_READY = PASS`
> - `MERGE_READY = PASS`
> - `CONTROLLED_DISCOVERY_READY = HOLD`
> - `LIVE_OUTREACH_READY = FORBIDDEN`

---

## 1. 架构目标与职责边界

本任务继续整改原有 PR #4，严格遵守并行文件所有权规范，不新建重复 PR，不执行真实公网请求，不自动合并，不修改 Agent A/B、Harvey 现有 Collector、Config 或 Brain 文件：

1. `harvey/controlled_discovery/budget.py`：跨进程原子硬预算账本与结算契约（UTC 严格日预算与 Fail-Closed 成本计量）。
2. `harvey/controlled_discovery/audit.py`：结构化出网操作与敏感信息脱敏审计日志。
3. `harvey/controlled_discovery/receipt.py`：可信采集回执模型、无歧义规范 JSON 验签与轻量业务防重放账本。
4. `tests/test_w105_budget_audit.py`：针对定界符碰撞、重放攻击防御、跨时区 UTC 边界及并发硬预算的物理断言测试。
5. `docs/audit/W105_C_BUDGET_AUDIT.md`：本整改验证说明书。

---

## 2. 核心整改与安全加固落实

### A. HMAC 规范串字段碰撞修复 (SEC-CANON-01)
- **碰撞复现根因 (Red)**：原 `_canonical_signing_string()` 使用 `|` 简单拼接字符串。当字段本身包含定界符时（如 `run_id="run|1"` 与 `collector_id="col"` 对应 `run_id="run"` 与 `collector_id="1|col"`），生成了完全相同的签名原文，产生定界符混淆风险。
- **无歧义规范编码 (Green)**：
  - 改用显式版本标注的规范化 JSON (`version="harvey-receipt-v2"`)。
  - 使用 `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`，保证键名严格排序、剔除空白、类型明确且跨平台字节序列完全确定。
  - 增加 `target_id` 显式字段绑定，确保签名与验签使用严格同一字节流。

### B. 采集回执业务防重放闭环 (SEC-REPLAY-01)
明确签名真实性（密码学有效性）与业务防重放（Business Replay Defense）是正交的两个控制维度：
- **存储介质**：复用轻量级 SQLite (`imported_receipts` 表，WAL 模式 + `BEGIN IMMEDIATE` 排他锁)，不引入大型复杂 PKI 系统。
- **正向与负向防御矩阵**：
  1. **同一 Receipt 重复导入**：`receipt_id PRIMARY KEY` 约束，首发导入成功，二次导入即报 `REJECTED_REPLAY_DUPLICATE_IMPORT`。
  2. **跨 Run 复用拦截**：比对 `receipt.run_id` 与预期的 `expected_run_id`，不匹配报 `REJECTED_REPLAY_RUN_MISMATCH`。
  3. **跨 Target 复用拦截**：比对 `receipt.target_id` 与预期的 `expected_target_id`，不匹配报 `REJECTED_REPLAY_TARGET_MISMATCH`。
  4. **Key 状态生命周期**：验签接口支持 `active_key_ids` 白名单与 `revoked_key_ids` 黑名单，已失效/撤销的 Key 立即报 `REJECTED_KEY_REVOKED_OR_INACTIVE`。
  5. **字段篡改阻断**：任何修改 `collector_id`、`collected_url`、`collected_at`、`permit_ref` 或 `target_id` 的行为均导致 HMAC 签名校验失败。
  6. **伪造 verified 声明拦截**：`from_dict()` 强制过滤 `verified` 字段，且 `verify_collector_receipt` 只根据公钥/私钥 HMAC 运算结果生成 `is_trusted`。
  7. **正文核实断言隔离**：当未提供 `raw_content_bytes` 时，`content_verified` 严格置为 `False`；若调用方声明 `require_content_reverification=True`，直接拒绝并报 `REJECTED_CONTENT_MISSING`，绝对不向外假称内容已重新核实。

### C. UTC 每日预算跨日计量 (FIN-TIME-01)
- **时区对齐**：修改 `budget.py` 中的 `_today_str()`，由原本的本地 `date.today()` 改为 `datetime.now(timezone.utc).date().isoformat()`，与 `_utcnow()` 统一在 UTC 坐标系下运转。
- **跨日边界验证**：针对跨时区场景（如 UTC 23:30 对应 Asia/Shanghai 次日 07:30）设计时间模拟测试，证明每日配额在 UTC 跨日边界精准隔离，杜绝因本地宿主时区漂移导致的限额过早耗尽或漏计。

### D. 成本与配额 Fail-Closed 结算
- **杜绝免费搭车**：未知计费、请求超时或网络异常时，结算策略保守保留全部预留值，不将未知成本当成零成本。
- **负数与非法值阻断**：在 `reserve()` 与 `settle()` 两个入口均强制校验金额与用量非负，传入负数或非法未知预算立即抛出 `ValueError`。
- **超额击穿阻断**：当实际发生额超过初始预留且击穿限额时，后续预留立即 Fail-Closed 抛出 `BudgetExceededError`。
- **幂等与持久化**：已结算的 reservation 再次结算抛出 `BudgetAlreadySettledError`；进程重启后完整加载历史结算与未结算预留，预算不归零。

---

## 3. 验证证据矩阵 (`tests/test_w105_budget_audit.py`)

| 序号 | 测试用例 | 验证目标 | 预期结果 | 实测状态 |
|---|---|---|---|---|
| 1 | `test_two_processes_competing_for_last_budget_tokens` | 4个独立进程争夺最后1个预算令牌 | 恰好1个成功，3个抛出 `BudgetExceededError` | **PASSED** |
| 2 | `test_budget_persistence_across_restart` | 进程重启或重新实例化 Ledger | 历史结算与在途预留完整恢复，不归零 | **PASSED** |
| 3 | `test_over_budget_fails_closed` | 累计请求超过 Run 上限 | 立即抛出 `BudgetExceededError` | **PASSED** |
| 4 | `test_actual_charge_exceeding_reservation_blocks_subsequent` | 真实扣费超过预留且击穿总预算 | 阻断后续所有预算预留请求 | **PASSED** |
| 5 | `test_failed_requests_accounted_conservatively` | 请求超时/失败且未知结算消耗 | 保留全部预留预算，防止配额绕过 | **PASSED** |
| 6 | `test_duplicate_settlement_rejected` | 重复结算同一 reservation_id | 拒绝二次结算，抛出 `BudgetAlreadySettledError` | **PASSED** |
| 7 | `test_trusted_receipt_verification_and_tamper_detection` | 正常验签、正文篡改、伪造签名与假冒 verified | 正确验签；正文修改哈希不符；篡改签名被拒；用户输入 verified=True 被忽略 | **PASSED** |
| 8 | `test_audit_log_redacts_credentials_and_headers` | 出网审计日志记录带密钥的 URL/标头 | 敏感参数与 Token 均被 `[REDACTED]` | **PASSED** |
| 9 | `test_offline_fixture_never_masquerades_as_trusted_receipt` | 离线 Fixture 声明回执 | 判定为不可信离线夹具，严禁伪装真实采集 | **PASSED** |
| 10 | `test_unauthorized_mode_strictly_forbids_budget_allocation` | 未授权模式 (`authorized=False`) 下申请外部预算 | 强制预算为0，抛出 `BudgetUnauthorizedError` | **PASSED** |
| 11 | `test_unknown_pricing_defaults_to_forbidden` | 试图传入负数或非法未知预算 | 校验拦截，抛出 `ValueError` | **PASSED** |
| 12 | `test_hmac_canonical_string_delimiter_collision_prevented` | Red-before-Green 定界符碰撞与规范 JSON 验签 | 证明字段交换签名相异，无定界符碰撞 | **PASSED** |
| 13 | `test_receipt_replay_prevention_and_lifecycle` | 重复导入、跨Run、跨Target、密钥吊销与字段篡改 | 严格触发对应拒绝状态，正文缺失不能假称核实 | **PASSED** |
| 14 | `test_utc_daily_budget_accounting_across_timezones` | 跨时区 UTC 日边界配额统计 | 严格按 UTC 日期归集，不受本地时区偏移干扰 | **PASSED** |
| 15 | `test_unknown_and_negative_cost_fail_closed` | 预留或结算传入负数成本 | 拦截负数成本，杜绝配额倒退与非法套利 | **PASSED** |

**专项与全量回归测试集状态**：
- `test_w105_budget_audit.py`：15 passed in 3.73s
- `test_w1_02_safety_hardening.py`：21 passed
- `test_devtools_signals.py`：3 passed
- `test_devtools_collector.py`：23 passed
- `test_devtools_pipeline_e2e.py`：6 passed
- **合计 68 passed in 63.22s (100% 绿灯，零回归失败)**

---

## 4. 残余风险与后续演进

1. **残余风险**：
   - 本地 SQLite 在极端操作系统掉电场景下可能留存孤立未结算预留，需待后续常驻后台机制接入超时巡检清理器（Stale Reservation Reaper）。
2. **后续演进**：
   - 维持公网探索 `CONTROLLED_DISCOVERY_READY = HOLD` 与邮件外联 `LIVE_OUTREACH_READY = FORBIDDEN` 绝不变更。
   - PR #4 安全整改项已全部闭环，达到可合并标准。
