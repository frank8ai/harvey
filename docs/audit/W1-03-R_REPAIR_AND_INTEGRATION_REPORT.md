# W1-03-R_REPAIR_AND_INTEGRATION_REPORT.md — DevTools 主流水线接线与真实资格语义修复裁决报告

> **执行角色**：Principal AI Sales Architect + Python Engineering Lead + Evidence Scientist
> **代码仓库**：`frank8ai/harvey`（本地 worktree `C:\Users\frank\Documents\Playground\harvey_w1_03`）
> **BASE_SHA**：`e114e95471b1bf155454fca108f0730b66a47a01`
> **修复分支**：`codex/w1-03-fetchinbox-devtools-signals`
> **PR URL**：https://github.com/frank8ai/harvey/pull/2

---

## 一、P0-A：真正接通 DevTools Pipeline

### 1. 核心修复与设计架构
原有实现中，`harvey/pipeline.py` 的 `if devtools:` 分支仅有 logger 打印语句，属于未接线的空桩。
本次实施了最小兼容的 **`DevToolsPipelineAdapter`**，达成以下硬性指标：
1. **默认关闭、可显式启用**：`run_prospecting(..., devtools=True, devtools_evidence=...)`。
2. **离线优先与安全边界**：优先从注入的离线证据包或已授权数据中获取 HTML/DNS 输入，坚决不进行未经授权的真实公网探测，完全符合 W1-02 安全边界。
3. **闭环链路打通**：
   `Company -> Evidence -> DevTools Signals -> Qualification -> SQLite Observations -> Cohort -> Opportunity Card`。
4. **失败可观测**：如适配处理出现异常，产生明确的 `errors` 记录并持久化至 `runs` 表（状态置为 `failed`），禁止仅打印 logger 却宣称处理成功。
5. **契约无破坏兼容**：严格复用已有 `evaluate_devtools_prospect()`、`record_devtools_observations()` 与 SQLite `observations` 触发器，不重建业务数据库或引入额外 CRM。

### 2. 实际流水线调用图 (Actual Pipeline Call Graph)

```
run_prospecting(state, config, devtools=True, devtools_evidence=bundle)
      │
      ├── [ Stage 1: DISCOVER ] ──► run_discovery() ──► 写入 companies 集合
      │
      ├── [ Stage 2: PROFILE ]  ──► run_profile_stage() ──► profile_companies()
      │
      └── [ Stage 3: DEVTOOLS ] ──► DevToolsPipelineAdapter.run()
                                          │
                                          ├── 1. 读取离线注入材料 / 待处理企业
                                          │
                                          ├── 2. evaluate_devtools_prospect()
                                          │      ├─ 6项技术事实信号提取 (OTP, E2E, Agent, Docs, ESP, Hiring)
                                          │      ├─ 来源去重与证据充分性评定 (VERISIG_EVIDENCE_SUFFICIENCY)
                                          │      └─ 排除项过滤 (VERISIG_DISQUALIFIED_REASON)
                                          │
                                          ├── 3. record_devtools_observations()
                                          │      └─ 批量写入 SQLite observations (带 triggers 校验)
                                          │
                                          ├── 4. build_opportunity_card()
                                          │      └─ 生成结构化 OpportunityCard 事实卡片
                                          │
                                          └── 5. 写入 runs 审计记录，返回 DevToolsStageResult
```

---

## 二、P0-B：纠正 Active Buyer 业务语义

彻底移除“活跃招聘 + 两个识别来源 = CONFIRMED_ACTIVE_BUYER”的虚假乐观规则，纠正商业事实真相：
1. **招聘 QA/SDET**：只能代表潜在技术需求与用人痛点，不等于采购商业软件。
2. **Playwright/Cypress**：只能证明可能的工程技术栈。
3. **SPF/ESP**：只能证明邮件基础配置线索。
4. **同源内容去重**：单页面或跨页面重复文本片段通过 SHA256 哈希去重，不虚增独立证据源。
5. **资格状态重定义**：
   - 强技术栈匹配 + 活跃招聘 $\Rightarrow$ `POTENTIAL_FIT`（潜在契合，列入观察）。
   - 空输入 $\Rightarrow$ `UNKNOWN`（绝不冒然断言为 `NO_AUTOMATION_NEED`）。
   - 缺少技术事实 $\Rightarrow$ `NEEDS_RESEARCH`。
   - 具备明确、独立、具体的商业采购原始资料（如 RFP 采购单据） $\Rightarrow$ `PURCHASE_CANDIDATE_PENDING_VERIFICATION`（待人工核验候选）。
   - **铁律**：`READY_FOR_OUTREACH` 绝不得从技术信号自动推出，严禁模型标签自动确认活跃买家；全流程未经授权的真实外联依然全面禁止。

---

## 三、P1：证据完整性与 Opportunity Card 规范

1. **来源真实性标记**：未经过访问采集的 URL 统一标记为 `UNKNOWN`，严禁臆测拼接 `https://domain/login` 冒充实测证据。
2. **未决字段显式暴露**：在评估结果中明确输出 `unknown_fields`，如 `["html_login", "CURRENT_E2E_EMAIL_TOOL"]`。
3. **置信度模型诚实声明**：标记为 `heuristic_rule_confidence_uncalibrated`，严禁捏造虚假置信度 `P(fit)=0.92`。
4. **OpportunityCard 与导出**：
   - 实现 `export_opportunity_cards()`，支持导出符合商业事实的 JSON 格式卡片，供后续审核与人工研判。

---

## 四、物理验收与测试证据 (Verification Evidence)

测试环境：Windows 11 Pro / Python 3.14.5 / pytest-9.1.1 / aiosqlite / FastAPI TestClient

### 1. DevTools 专属集成测试 (16 项全通)
`tests/test_devtools_signals.py` & `tests/test_devtools_collector.py`：
- 原生 23 项核心信号一个不少：`PASS`
- 8 项扩展信号（6事实 + 2派生）合法注册：`PASS`
- 未注册非法信号被 SQLite 触发器 ABORT：`PASS`
- 技术栈强匹配判定为 `POTENTIAL_FIT`，绝非 `CONFIRMED_ACTIVE_BUYER`：`PASS`
- 明确采购资料形成 `PURCHASE_CANDIDATE_PENDING_VERIFICATION`：`PASS`
- 竞品与 2C 消费级排除：`PASS`
- 空输入断言为 `UNKNOWN` 而非 `NO_AUTOMATION_NEED`：`PASS`
- 来源 URL 缺失时标记 `UNKNOWN`：`PASS`
- 重复单页不虚增独立证据：`PASS`
- DNS SPF 仅作技术线索：`PASS`
- OpportunityCard 生成与导出：`PASS`
- SQLite Cohort 集合交集查询：`PASS`
- DevToolsPipelineAdapter 离线运行：`PASS`
- 零公网网络调用守卫：`PASS`

### 2. 端到端流水线集成测试 (1 项全通)
`tests/test_devtools_pipeline_e2e.py`：
- 完整执行 `DISCOVER -> PROFILE -> DEVTOOLS PIPELINE ADAPTER`
- 检验 DevTools 评估写入 SQLite，Cohort 查询准确包含/排除对应候选：`PASS`

### 3. 原生 128 项回归套件（100% 绿色）
- `tests/test_dashboard_signals.py`
- `tests/test_signals_export.py`
- `tests/test_state.py`
- `tests/test_pipeline.py`
- `tests/test_discover.py`
- `tests/test_collectors_profile.py`
**结果**：`128 passed, 1 warning in 80.91s`。无任何回归破坏。

---

## 五、交付结论与裁决

- **PR #2 状态**：已在分支 `codex/w1-03-fetchinbox-devtools-signals` 准备更新提交。
- **READY_FOR_W1-04 判断**：
  - 本地离线流水线已完全通畅，提供真实有效的结构化 Observation 与 OpportunityCard。
  - **前置依赖提示**：PR #2 本身业务逻辑完整且自洽，但在真实出站前，必须等待安全基础层 PR #1 (`codex/w1-02-harvey-safety-hardening`) 合并以保障物理发信锁与 SSRF 安全传输；严禁在未集成 PR #1 时连接真实外网。
- **最终裁决**：**MERGE_READY**（针对 PR #2 分支自身的离线工程闭环已达标，建议通过 `gh stack` 与 PR #1 联合审查，暂不自行合入主干）。


---

## 六、W1-03-R2 升级报告：Offline Evidence-Only 严格模式与来源真实性

### 1. P0-A 真实离线入口与最外层网络阻断
1. **显式离线执行入口**：`run_offline_prospecting(state, evidence_bundle=..., limit=...)`，同时支持 `run_prospecting(..., offline_evidence_only=True)`。
2. **最外层阻断网络**：`offline_network_guard` 集中拦截 socket 连接、DNS 解析、httpcore HTTP 同步/异步请求、urllib 以及 asyncio 连接。仅允许本地回环地址（127.0.0.1、localhost、::1）供 SQLite/IPC 使用。
3. **真实调用链**：
   `run_offline_prospecting() -> offline_network_guard -> DevToolsPipelineAdapter.run() -> evaluate_devtools_prospect() -> record_devtools_observations() -> SQLite Observations -> Cohort / OpportunityCard`。
   完全规避 Discovery、Profile、DNS 查询与模型调用，禁止任何偷跑公网逻辑。
4. **状态隔离与幂等性**：相同输入重复运行不会造成 companies 表或 observations 表脏数据污染，重复运行后企业记录去重数稳定。

### 2. P1-A 证据来源真实性规范
1. **来源分类机制**：严格区分 `verified_source`、`offline_fixture` 与 `unverified_source`。
2. **拒绝未核实证据膨胀**：未提供有效真实 URL 的文本放入 `unverified_source`，其独立来源计数为 0，不能作为提升 `SUFFICIENT` 的依据。
3. **证据指纹去重**：同一来源或不同端点出现的相同内容哈希不提升独立来源计数。
4. **元数据溯源**：Evidence Bundle 记录 `source_type`、`collection_method` 与 `collected_at`；缺失时在 `unknown_fields` 记录证据缺口（如 `COLLECTED_AT_TIMESTAMP`）。
5. **采购意图硬门禁**：`purchase_evidence` 严格输出 `PURCHASE_CANDIDATE_PENDING_VERIFICATION`，绝不因技术栈或非空列表自动断言为已确认买家。
6. **负例与 UNKNOWN 保留**：空输入返回 `UNKNOWN`，9 类正负样本分类与预期契约 100% 吻合。

### 3. 测试验证数据
- **物理验收环境**：Windows 11 / Python 3.14.5 / aiosqlite / pytest-9.1.1
- **DevTools 核心与信号测试**：`tests/test_devtools_collector.py`、`tests/test_devtools_signals.py` 全部通过。
- **离线端到端测试**：`tests/test_devtools_pipeline_e2e.py` 3 项测试全部通过，外层拦截断言 outbound requests = 0。
- **Harvey 全量回归**：`403 passed, 169 skipped, 0 failed`（耗时 108.58s）。
