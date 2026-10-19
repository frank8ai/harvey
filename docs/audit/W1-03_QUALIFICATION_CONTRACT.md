# W1-03_QUALIFICATION_CONTRACT.md — 最小资格判定契约与结构化评估设计

> **设计执行**：Principal AI Sales Architect & Evaluation Scientist
> **设计日期**：2026-10-19
> **规范目标**：确立结构化评定字段与判定状态机，彻底破除“1-10 单一主观打分”缺陷，杜绝无事实支撑的伪阳性判定。

---

## 1. 结构化资格评估模型 (Structured Qualification Contract)

任何候选企业在进入销售跟进或邮件生成流水线前，必须输出以下 7 个标准结构化字段：

```json
{
  "company_id": "c_9f81a7b2c01",
  "domain": "example.com",
  "evaluated_at": "2026-10-19T08:30:00Z",
  "icp_fit": "TIER_1_STRONG_FIT",
  "use_case_fit": "AGENT_INBOX",
  "evidence_quality": "SUFFICIENT",
  "purchase_intent_evidence": [
    {
      "signal_code": "HIRING_QA_OR_AGENT_INFRA",
      "summary": "Active role: Senior Browser Automation Engineer (posted 3 days ago)",
      "source_url": "https://example.com/careers#job-102",
      "confidence": 0.85
    }
  ],
  "disqualification": {
    "is_disqualified": false,
    "reason": null
  },
  "unknown_fields": [
    "CURRENT_E2E_EMAIL_TOOL"
  ],
  "next_best_research_action": "CHECK_GITHUB_OR_COMMUNITY_ISSUES"
}
```

---

## 2. 字段详细规范与状态枚举

### 2.1 `ICP_FIT` (理想客户契合度)
- `TIER_1_STRONG_FIT`：明确属于 AI Agent / Browser Automation 团队或重度 E2E 自动化测试 SaaS 团队。
- `TIER_2_MODERATE_FIT`：通用开发工具 / SaaS 团队，具有自建认证系统与技术文档，但尚未确认深度自动化测试诉求。
- `TIER_3_LOW_FIT`：传统软件或边缘场景，缺少高频认证交互。
- `NON_ICP`：完全不属于 B2B SaaS 或软件工程领域（如本地零售、个人博客、非技术服务）。

### 2.2 `USE_CASE_FIT` (业务场景契合)
- `AGENT_INBOX`：需要为 AI Agent、自动机器人提供动态临时邮箱收发与验证码提取。
- `E2E_AUTH_TESTING`：需要自动化测试注册、登录、找回密码、Magic Link 验证流程。
- `MULTI_TENANT_QA`：外包或内部 QA 服务，需要按测试套件或客户隔离大量临时邮箱。
- `NONE`：无明确邮箱自动化使用场景。
- `UNKNOWN`：尚未获取到足够的技术特征以判断具体场景。

### 2.3 `EVIDENCE_QUALITY` (证据质量与充分性)
- `SUFFICIENT`：具备至少 2 项独立源事实证据（例如：官网表单发现 OTP + 招聘发现 E2E 测试工程师），无事实冲突。
- `PARTIAL`：具备 1 项可靠事实证据（如确认支持邮件 OTP 登录），但缺少测试框架或近期采购痛点支撑。
- `INSUFFICIENT`：仅有域名、主页基础信息或单一技术线索（如仅有 SPF 记录），不足以支撑精准推销。
- `CONFLICTING`：不同来源提取的信息存在直接矛盾（如产品宣称纯无密码登录，但注册页仅允许 Google OAuth 登录）。

### 2.4 `PURCHASE_INTENT_EVIDENCE` (真实购买意图证据列表)
- 严禁空泛推断，必须记录具体、可追溯的事实片段（`summary`）、证据 URL（`source_url`）及观察置信度（`confidence`）。
- **必须区分**：
  - 仅有事实技术栈 $
ightarrow$ `purchase_intent_evidence: []`
  - 存在近期招聘、架构升级、痛点反馈 $
ightarrow$ 记录具体意向证据

### 2.5 `DISQUALIFICATION` (排除判定)
- `is_disqualified: true` 的候选将立即被封存，绝对禁止进入发信流程。
- `reason` 枚举：
  - `DIRECT_COMPETITOR`：自身是临时邮箱、邮件测试工具或反自动化防护服务。
  - `CONSUMER_ONLY`：纯 2C 消费品/娱乐/生活服务网站。
  - `NO_AUTOMATION_NEED`：纯静态单页或仅使用第三方无头托管登录，无自研认证逻辑。
  - `ENTERPRISE_CUSTOM_OUT_OF_SCOPE`：仅支持私有化物理部署或要求 HIPAA 专属硬件隔离。
  - `STALE_BUSINESS`：域名无法解析、长期未维护或已停止运营。

### 2.6 `UNKNOWN_FIELDS` (未决字段)
显式列出尚未核验的维度（如 `CURRENT_E2E_EMAIL_TOOL`, `TEAM_SIZE`, `ACTIVE_ESP`），绝不以猜测代替事实。

### 2.7 `NEXT_BEST_RESEARCH_ACTION` (下一步最佳研究动作)
- `READY_FOR_OUTREACH`：具备充分证据与意图，可进入话术生成与人类审核。
- `SEARCH_CAREERS_PAGE`：需要进一步检索其招聘页面以确认自动化工程角色。
- `INSPECT_SIGNUP_FLOW`：需要深入分析其注册页面具体表单逻辑。
- `CHECK_GITHUB_OR_COMMUNITY_ISSUES`：需要检索公开开源库或社区讨论以寻找 E2E 痛点。
- `DISCARD_OR_ARCHIVE`：已排除或证据严重匮乏，归档终止。

---

## 3. 销售状态机流转守卫 (State Transition Guards)

```
[ 新建企业发现 ]
      │
      ▼
[ DevTools 采集与特征提取 ]
      │
      ├── 是否命中排除规则？ ── Yes ──► [ DISQUALIFIED ] (记录原因，归档)
      │
      ▼ No
[ 评估证据充分性 ]
      │
      ├── EVIDENCE == INSUFFICIENT ──► [ UNKNOWN / NEEDS_ENRICHMENT ]
      │
      ├── EVIDENCE == PARTIAL ───────► [ POTENTIAL_FIT / NEEDS_REVIEW ]
      │                                (人工复核，禁止标记为 ACTIVE_BUYER)
      │
      └── EVIDENCE == SUFFICIENT ────► 检查是否有真实购买意向证据？
                                            │
                                            ├── 无购买证据 ──► [ POTENTIAL_FIT / WATCHLIST ]
                                            │
                                            └── 有可核验证据 ─► [ CONFIRMED_ACTIVE_BUYER ]
```

**铁律**：
只有同时满足 `EVIDENCE_QUALITY == SUFFICIENT` 且 `purchase_intent_evidence` 列表中至少有 1 项有效条目的企业，才允许标记为 `CONFIRMED_ACTIVE_BUYER`。缺少真实购买证据的候选企业，一律标记为 `POTENTIAL_FIT / NEEDS_REVIEW`。
