# W1-03_HARVEY_SIGNAL_MAPPING.md — Harvey 原生 23 项信号与 DevTools 扩充映射审计

> **审计执行**：Principal Python Engineer & Data Extraction Specialist
> **审计日期**：2026-10-19
> **源码真理源**：`harvey/signals.py`, `harvey/state.py`, `harvey/collectors/profile.py`, `harvey/collectors/discover.py`
> **基线准则**：严格基于实际 AST / Python 源码核验 23 项原生信号，不得捏造 Gemini 摘要中臆测的 `COMPANY_SIZE`、`RECENT_FUNDING`、`SOCIAL_ACTIVE` 等虚假原生代码；实现与文档中明确区分事实观察与派生资格。

---

## 1. 原生 23 项信号代码 AST / 源码提取真理表

通过对 `harvey/signals.py` 中 `SIGNAL_CATALOG` 对象的严格 AST 读取与单元测试执行，确认原生代码集共 23 项，分属 4 大类别：

| 序号 | Signal Code | Category | Value Type | Collector | Confidence Floor | 语义与业务定义 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `SERP_RANK` | `discovery` | `num` | `discover` | 0.0 | 搜索引擎核心关键词排名位置（11-30 为高意向甜点区） |
| 2 | `FOUND_IN_SERP` | `discovery` | `text` | `discover` | 0.0 | 首次发现该企业的搜索引擎或列表来源 |
| 3 | `NO_WEBSITE` | `discovery` | `bool` | `discover` | 0.0 | 仅有黄页/电话而无独立网站 |
| 4 | `UNCLAIMED_LISTING` | `discovery` | `bool` | `discover` | 0.0 | 未认领 Google Business Profile |
| 5 | `REVIEW_RATING` | `discovery` | `num` | `discover` | 0.0 | 平均评价星级评分 (1.0-5.0) |
| 6 | `REVIEW_COUNT` | `discovery` | `num` | `discover` | 0.0 | 累计评价数量 |
| 7 | `INCUMBENT_AGENCY` | `profile` | `text` | `profile` | 0.75 | 网页底部明确注明的建站/营销代理商（高置信提取） |
| 8 | `RUNNING_GOOGLE_ADS` | `profile` | `bool` | `profile` | 0.0 | 网站埋有 Google Ads 转化追踪代码（正在花钱买流量） |
| 9 | `RUNNING_META_ADS` | `profile` | `bool` | `profile` | 0.0 | 网站埋有 Meta Pixel 追踪（正在投放社交广告） |
| 10 | `TECH_STACK` | `profile` | `text` | `profile` | 0.0 | 网站前端/CMS/分析组件技术栈（WordPress, Shopify, etc.） |
| 11 | `NO_SCHEMA_MARKUP` | `profile` | `bool` | `profile` | 0.0 | 缺失 JSON-LD 结构化数据 |
| 12 | `NO_ONLINE_BOOKING` | `profile` | `bool` | `profile` | 0.0 | 缺失在线预约/表单组件 |
| 13 | `SITE_PAGE_COUNT` | `profile` | `num` | `profile` | 0.0 | Sitemap 中声明的页面总数 |
| 14 | `BLOG_STALE` | `profile` | `num` | `profile` | 0.0 | 博客内容废弃未更新天数 |
| 15 | `BLOCKS_AI_CRAWLERS` | `profile` | `bool` | `profile` | 0.0 | robots.txt 明确封禁 GPTBot / ClaudeBot 等 AI 爬虫 |
| 16 | `HIRING_ROLE` | `profile` | `text` | `profile` | 0.0 | 招聘页面发现的与采购意图相关的职位 |
| 17 | `CONTACT_FOUND` | `people` | `text` | `people` | 0.0 | 团队页提取的具名联系人姓名与职位 |
| 18 | `DECISION_MAKER_TITLE` | `people` | `text` | `people` | 0.0 | 职位符合决策人特征 (Owner, Founder, VP, Director) |
| 19 | `REGISTRY_VERIFIED` | `people` | `text` | `people` | 0.0 | 官方公开执照或工商注册登记核实 |
| 20 | `LIKELY_OWNER` | `people` | `bool` | `people` | 0.0 | 工商登记显示该人大概率为企业实际控制人 |
| 21 | `EMAIL_PATTERN` | `verification` | `text` | `verify` | 0.0 | 企业邮箱前缀命名规律 (`first.last`, `first`, etc.) |
| 22 | `EMAIL_STATUS` | `verification` | `text` | `verify` | 0.0 | 邮箱有效性状态 (`verified`, `risky`, `guess`, `invalid`) |
| 23 | `CONTACT_FORM_URL` | `verification` | `text` | `profile` | 0.0 | 网站上可直接提交留言的联系表单 URL |

### 1.2 纠偏与防伪说明
部分 LLM 生成摘要或外部文档错误声称 Harvey 存在 `COMPANY_SIZE`、`RECENT_FUNDING`、`SOCIAL_ACTIVE` 等原生信号。经全面代码检索，这些仅存在于历史 Prompt 文本或通用概念，**在 `SIGNAL_CATALOG` 与 SQLite 治理触发器中从未作为合法信号代码存在**。任何试图将此类非注册代码直接插入 `observations` 表的操作均会被 SQLite 触发器 `trg_observations_signal_known` 强制拦截抛出 `ABORT` 异常。

---

## 2. DevTools 专属扩充信号 (6 项事实信号 + 2 项派生资格状态)

为满足 FetchInbox 针对 B2B SaaS 与 DevTools 客户的精准定位，在维持前 23 项原生信号 100% 兼容的前提下，扩充以下 8 项标准词汇表：

### 2.1 6 项事实/上下文观察信号 (Fact / Context Observations)

| Signal Code | Category | Value Type | Collector | 置信度基线 | 证据提取规则与限制 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HAS_SIGNUP_OTP_OR_MAGIC_LINK` | `devtools` | `bool` | `devtools` | 0.80 | **事实依据**：注册/登录页面中存在邮箱验证码输入框、"send verification code"、"magic link"、"check your email for a 6-digit code" 特征。<br>**限制**：普通账号密码登录页面或单一 OAuth (Google/GitHub) 按钮不可断言为本信号。 |
| `USES_E2E_TEST_FRAMEWORK` | `devtools` | `text` | `devtools` | 0.85 | **事实依据**：GitHub 公开仓库 package.json/requirements、工程博客或技术招聘中明确出现 `Playwright`, `Cypress`, `Selenium`, `Puppeteer`。<br>**限制**：仅代表测试技术栈，绝不自动等于采购意图。 |
| `BUILDS_AI_OR_BROWSER_AGENTS` | `devtools` | `bool` | `devtools` | 0.85 | **事实依据**：产品功能文档、SDK 或核心说明包含 Browser Automation, Computer Use, Headless Agent, Multi-step Web Agent 等可落地工程实现。<br>**限制**：拒绝纯营销套话（如仅提及“AI-powered SaaS”而无任何自主执行或自动化能力的泛化描述）。 |
| `HAS_DEVELOPER_DOCS_OR_API` | `devtools` | `bool` | `devtools` | 0.90 | **事实依据**：存在公开 API 文档路径（如 `/docs`, `/api-reference`, Mintlify, Fern, Swagger 等）或提供官方 SDK/Webhooks 说明。<br>**限制**：普通的帮助中心（Help Center/Zendesk FAQ）不可视为开发文档。 |
| `USES_TRANSACTIONAL_EMAIL_ESP` | `devtools` | `text` | `devtools` | 0.70 | **事实依据**：DNS SPF 记录或网站代码中出现 Postmark, SendGrid, Resend, Mailgun, Amazon SES, Brevo 等事务邮件提供商指纹。<br>**限制**：SPF 指纹仅为域名基础配置线索，不代表当下正在高频发送事务邮件；不可作为购买 FetchInbox 的充要证据。 |
| `HIRING_QA_OR_AGENT_INFRA` | `devtools` | `text` | `devtools` | 0.80 | **事实依据**：活跃招聘职位中包含 QA Automation Engineer, SDET, E2E Test Engineer, Agent Platform Engineer 等角色。<br>**限制**：必须核实职位为活跃状态（未归档）；同一 JD 中多次出现仅算一次证据。 |

### 2.2 2 项派生资格状态 (Derived Qualification State)

**关键架构隔离原则**：
资格信号是由事实信号经过规则引擎评估后计算得出的**派生判定 (Derived Judgments)**，严禁混同为独立事实证据。

| Signal Code | Category | Value Type | Collector | 状态值枚举 | 判定语义与约束 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `VERISIG_EVIDENCE_SUFFICIENCY` | `qualification` | `text` | `qualification` | `SUFFICIENT`<br>`PARTIAL`<br>`INSUFFICIENT`<br>`CONFLICTING` | **派生语义**：衡量候选企业当前所拥有的独立证据源数量与质量是否足以支撑销售动作。<br>**约束**：单一网页的多处描述视为单源；仅有 SPF 记录不可标记为 `SUFFICIENT`。 |
| `VERISIG_DISQUALIFIED_REASON` | `qualification` | `text` | `qualification` | `DIRECT_COMPETITOR`<br>`CONSUMER_ONLY`<br>`NO_AUTOMATION_NEED`<br>`ENTERPRISE_CUSTOM_OUT_OF_SCOPE`<br>`STALE_BUSINESS` | **派生语义**：命中明确排除项的根本原因。<br>**约束**：一旦产生排除原因，整机流水线将其隔离到排除队列，不得进入 Outbox 外发。 |

---

## 3. 兼容性与迁移保障

1. **零破坏性改动**：
   - 保持 `SIGNAL_CATALOG` 原生 23 项的定义、类别与置信度完全不变；
   - 扩充信号通过 `harvey/signals.py` 追加，并在 `state.init_db()` 或 `seed_signal_catalog` 时平滑写入 SQLite `signal_codes` 表；
2. **触发器兼容性**：
   - 新增的 8 项信号合法注册后，SQLite 触发器 `trg_observations_signal_known` 自动放行；
   - 尝试写入未经注册的杂乱字符串仍将被 100% 严格拦截；
3. **数据隔离性**：
   - 其他行业历史数据不受任何影响；
   - DevTools 采集器输出的 Observations 携带 `collector="devtools"` 或 `collector="qualification"`，便于索引和审计回溯。
