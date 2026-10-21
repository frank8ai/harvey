# W1-03_QUALIFICATION_CONTRACT.md — 最小资格判定契约与结构化评估设计 (W1-03-R 修复版)

> **设计执行**：Principal AI Sales Architect & Evaluation Scientist
> **设计日期**：2026-10-19 (W1-03-R 业务语义纠偏更新)
> **规范目标**：确立结构化评定字段与判定状态机，彻底破除“1-10 单一主观打分”与“技术匹配自动等于采购活跃买家”缺陷，杜绝无事实支撑的伪阳性判定。

---

## 1. 结构化资格评估模型 (Structured Qualification Contract)

任何候选企业在进入销售跟进或邮件生成流水线前，必须输出标准结构化结果：

```json
{
  "company_id": "c_9f81a7b2c01",
  "domain": "example.com",
  "evaluated_at": "2026-10-19T08:30:00Z",
  "icp_fit": "TIER_1_STRONG_FIT",
  "use_case_fit": "AGENT_INBOX",
  "evidence_quality": "SUFFICIENT",
  "purchase_intent_evidence": [],
  "disqualification": {
    "is_disqualified": false,
    "reason": null
  },
  "unknown_fields": [
    "CURRENT_E2E_EMAIL_TOOL"
  ],
  "next_best_research_action": "RESEARCH_TEST_INFRASTRUCTURE",
  "qualification_status": "POTENTIAL_FIT",
  "confidence_model": "heuristic_rule_confidence_uncalibrated"
}
```

---

## 2. 字段详细规范与状态枚举

### 2.1 `ICP_FIT` (理想客户契合度)
- `TIER_1_STRONG_FIT`：明确属于 AI Agent / Browser Automation 团队或重度 E2E 自动化测试 SaaS 团队。
- `TIER_2_MODERATE_FIT`：通用开发工具 / SaaS 团队，具有自建认证系统与技术文档，但尚未确认深度自动化测试诉求。
- `TIER_3_LOW_FIT`：传统软件、边缘技术配置（如仅查到 SPF）或缺少高频认证交互。
- `NON_ICP`：完全不属于 B2B SaaS 或软件工程领域（如本地零售、个人博客、非技术服务）。
- `UNKNOWN`：尚未获取任何页面或技术指纹（空输入）。

### 2.2 `USE_CASE_FIT` (业务场景契合)
- `AGENT_INBOX`：需要为 AI Agent、自动机器人提供动态临时邮箱收发与验证码提取。
- `E2E_AUTH_TESTING`：需要自动化测试注册、登录、找回密码、Magic Link 验证流程。
- `MULTI_TENANT_QA`：外包或内部 QA 服务，需要按测试套件或客户隔离大量临时邮箱。
- `NONE`：无明确邮箱自动化使用场景。
- `UNKNOWN`：尚未获取到足够的技术特征以判断具体场景。

### 2.3 `EVIDENCE_QUALITY` (证据质量与充分性)
- `SUFFICIENT`：具备至少 2 项独立源事实证据（例如：不同正规页面分别发现 OTP 与 E2E 测试框架），且无重复内容复制。
- `PARTIAL`：具备 1 项可靠事实证据（如确认支持邮件 OTP 登录），但缺少测试框架或近期采购痛点支撑。
- `INSUFFICIENT`：仅有域名、主页基础信息、空输入或单一技术线索（如仅有 SPF 记录），不足以支撑精准推销。
- `CONFLICTING`：不同来源提取的信息存在直接矛盾（如产品宣称纯无密码登录，但注册页仅允许 Google OAuth 登录）。

### 2.4 `PURCHASE_INTENT_EVIDENCE` (真实购买意图证据列表)
- **铁律纠偏**：
  - 招聘 QA/SDET $\Rightarrow$ 仅证明潜在技术需求，**不代表当前活跃购买采购**。
  - 使用 Playwright/Cypress $\Rightarrow$ 仅证明可能的技术栈。
  - SPF/ESP $\Rightarrow$ 仅证明邮件网关配置。
  - 真实商业采购证据必须有**明确、独立、具体的商业采购原始凭证**（如正式采购招标 RFP、咨询报价邮件记录等）。
  - 没有真实采购证据时，一律为 `[]`。

### 2.5 `DISQUALIFICATION` (排除判定)
- `is_disqualified: true` 的候选将立即被封存，绝对禁止进入发信流程。
- `reason` 枚举：
  - `DIRECT_COMPETITOR`：自身是临时邮箱、邮件测试工具或反自动化防护服务。
  - `CONSUMER_ONLY`：纯 2C 消费品/娱乐/生活服务网站。
  - `NO_AUTOMATION_NEED`：明确无需自动化邮件接收（注：空输入必须标记为 UNKNOWN，严禁直接断言为 NO_AUTOMATION_NEED）。
  - `ENTERPRISE_CUSTOM_OUT_OF_SCOPE`：仅支持私有化物理部署或要求 HIPAA 专属硬件隔离。
  - `STALE_BUSINESS`：域名无法解析、长期未维护或已停止运营。

### 2.6 `QUALIFICATION_STATUS` (资格状态枚举 - W1-03-R 纠偏)
- `POTENTIAL_FIT`：技术栈与产品契合，但缺少明确采购证据，可加入观察池。
- `PURCHASE_CANDIDATE_PENDING_VERIFICATION`：具有明确采购原始资料，形成待人工复核的采购候选（**严禁模型自动确认**）。
- `NEEDS_RESEARCH`：技术线索不足，需补充研判。
- `UNKNOWN`：空数据或完全未访问状态。
- `DISQUALIFIED`：命中排除规则。
- **严禁使用**：在技术信号或招聘线索下**严禁标记为 `CONFIRMED_ACTIVE_BUYER`**；未经人工核验的商机严禁标记为已确认买家。

### 2.7 `NEXT_BEST_RESEARCH_ACTION` (下一步最佳研究动作)
- `RESEARCH_TEST_INFRASTRUCTURE`：需要进一步检索其工程博客或开源代码以确认测试环境。
- `SEARCH_CAREERS_PAGE`：需要进一步检索招聘页面。
- `HUMAN_PROCUREMENT_VERIFICATION`：存在采购意向证据，移交人工进行商业真实性复核。
- `DISCOVER_COMPANY_PROFILE`：信息为空，需先补充基础企业画像。
- `DISCARD_OR_ARCHIVE`：已排除或无潜力。
- **禁令**：`READY_FOR_OUTREACH` 绝不得从技术信号自动推出，未经授权的真实外联依然全面禁止。

---

## 3. 销售状态机流转守卫 (State Transition Guards - W1-03-R)

```
[ 新建企业发现 / 离线资料注入 ]
              │
              ├── 输入是否全为空？ ── Yes ──► [ UNKNOWN ] (标记未决字段，等待画像挖掘)
              │
              ▼ No
      [ 检查是否命中排除项？ ] ───── Yes ──► [ DISQUALIFIED ] (记录原因，归档隔离)
              │
              ▼ No
      [ 评估证据充分性与去重源 ]
              │
              ├── 证据不足 (INSUFFICIENT) ──► [ NEEDS_RESEARCH ]
              │
              └── 证据充分或部分匹配 (SUFFICIENT / PARTIAL)
                      │
                      ├── 是否有明确、真实的商业采购原始单据？
                      │         │
                      │         ├── Yes ──► [ PURCHASE_CANDIDATE_PENDING_VERIFICATION ]
                      │         │           (待人工核验候选，严禁自动发信)
                      │         │
                      │         └── No ───► [ POTENTIAL_FIT ]
                      │                     (技术匹配潜在契合，持续观察)
```
