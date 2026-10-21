# W105_D_TARGET_20_READINESS.md — 20 家真实公司受控采集就绪度独立终审与裁决

> **执行人**：Independent Integration Architect + Principal Python CTO  
> **任务代号**：Harvey W1-05-D  
> **基线 (BASE_SHA)**：31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a  
> **分支 (HEAD_SHA)**：codex/w1-05-d-controlled-egress-integration  
> **当前状态结论**：TARGET_20_AUTHORIZED = NO / CONTROLLED_DISCOVERY_READY = HOLD

---

## 1. 20 家真实公司受控实验准入标准 (Admission Criteria)

要将 FetchInbox 20 家目标企业从离线/受限状态转入真实的受控公网采集，必须同时满足以下 **6 项刚性前置条件**：

1. **工程与安全底座接入完成 (Engineering Foundation Ready)**：
   - 统一 10 阶段出网安全网关接入完成并通过红队全量渗透测试。
   - **状态**：**PASS**（W1-05-D 已完成）。
2. **独立来源与白名单法律合规审批 (Legal & Source Authorization Approval)**：
   - 每家企业的探测范围、域名别名、 robots.txt 许可与合规声明需经独立人工合规审计并签署白名单。
   - **状态**：**PENDING_APPROVAL (未获得)**。
3. **企业目标名单明确与范围固定 (Explicit Scope Lockdown)**：
   - 20 家企业白名单需固定具体公司 ID、主域名、允许替代域名及允许抓取路径前缀，严禁模糊匹配或泛子域名继承。
   - **状态**：**PENDING_CONFIGURATION (未配置默认真实名单)**。
4. **硬预算配额独立审批 (Budget Allocation Authorization)**：
   - 单企业最大字节上限（如 2MB/家）、总实验预算（如 .00 USD 或 500 次 HTTP 请求）需获独立 FinOps 审批并在 HardBudgetLedger 中显式开账。
   - **状态**：**PENDING_ALLOCATION (未分配)**。
5. **真实发信与外呼严格物理物理锁止 (Outreach Strict Freeze)**：
   - 必须保持真实发信物理断开（lock_outbound_send=True），绝不允许将采集发现直接流入自动化外发触达。
   - **状态**：**ENFORCED (已严格锁止)**。
6. **审计日记落盘与回执追踪链路激活 (Audit & Receipt Active)**：
   - 必须保证外部日志分析工具与可信回执防伪签名可被独立审查。
   - **状态**：**PASS (代码层已就绪)**。

---

## 2. 真实采集严格禁用裁决

根据 W1-05-D 规范与“零信任”原则：
- **现阶段所有未授权 Target 严格 DENY**。
- **不建立任何默认真实公司白名单**，代码库中不预置未经批准的真实企业信息。
- **未知收费 API 默认禁用**。
- **未经授权的采集器不启用**。

即使安全网关与全部集成测试均已 100% 绿灯，系统架构师与工程团队**绝对不能自行解除 20 家真实公司采集权限**。解除权限必须依赖独立的外部审计、来源政策审批与预算授权流程。

---

## 3. 终审裁决矩阵

| 评估维度 | 当前状态判定 | 判定原因与说明 |
| :--- | :---: | :--- |
| **SECURITY_GATES_READY** | **PASS** | 统一受控出网网关、SSRF 防护、跨进程硬预算、域名限速、流式熔断与可信回执均已完成接线并经 12 项红队渗透测试验证。 |
| **CONTROLLED_DISCOVERY_READY** | **HOLD** | 受控工程底座已就绪，但 20 家目标企业合规名单、来源授权及专项预算尚在等待独立业务与合规审批，保持挂起。 |
| **LIVE_OUTREACH_READY** | **FORBIDDEN** | 生产发信通道维持物理硬锁，Instantly 变更 API 物理禁用，严禁向任何真实用户发送营销邮件。 |
| **TARGET_20_AUTHORIZED** | **NO** | 尚未批准真实 20 家企业公网探测。 |