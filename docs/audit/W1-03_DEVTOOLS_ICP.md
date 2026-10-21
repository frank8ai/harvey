# W1-03_DEVTOOLS_ICP.md — FetchInbox 开发者与 B2B SaaS 理想客户画像 (ICP) 规范

> **编写者**：Principal AI Sales Architect & B2B DevTools Growth Engineer
> **编写日期**：2026-10-19
> **适用范围**：Harvey 智能线索发现、DevTools 采集器与资格判定引擎
> **核心原则**：严禁泛化，绝不将整个英文 SaaS 行业或泛 AI 营销概念当作 ICP。必须基于技术栈证据、业务场景契合度与真实购买意图实施分层判定。

---

## 1. 核心定位与三类重点目标画像 (Three Target Cohorts)

FetchInbox 解决的是**自动化认证流程中的入站邮箱生成与验证码 (OTP) / Magic Link 即时提取痛点**。
因此，目标受众严格收敛于具有明确自动化测试或自动化 Agent 运行诉求的三类核心团队：

```
                              ┌────────────────────────────────────────┐
                              │     FetchInbox DevTools ICP Core       │
                              └──────────────────┬─────────────────────┘
                                                 │
         ┌───────────────────────────────────────┼───────────────────────────────────────┐
         ▼                                       ▼                                       ▼
┌──────────────────┐                   ┌──────────────────┐                    ┌──────────────────┐
│ Cohort A:        │                   │ Cohort B:        │                    │ Cohort C:        │
│ AI Agent /       │                   │ E2E 测试重度团队 │                    │ 自动化测试与     │
│ Browser 自动化团队│                   │ (SaaS / Web App) │                    │ 软件质效服务机构 │
└──────────────────┘                   └──────────────────┘                    └──────────────────┘
```

---

## 2. 三类候选画像深度定义矩阵

### 2.1 Cohort A: AI Agent / Browser Automation 产品团队

- **产品使用场景**：
  AI Agent（如自主表单填写、自动注册、Web 自动化操作员）需要在执行任务过程中动态创建临时邮箱，接收外部服务的验证邮件或一次性验证码 (OTP)，自动完成注册闭环，无需人类手动干预。
- **必要匹配条件 (Must-Have)**：
  1. 核心产品或开源项目包含自动化 Browser / Computer Use / Web Agent 执行能力；
  2. 存在需要第三方账号创建或外部网站交互的实际工作流；
  3. 提供开发者 API 或需要后台自动化调度。
- **可核验的技术证据 (Verifiable Evidence)**：
  - 代码库/博客/文档包含 `browser-use`, `playwright`, `puppeteer`, `selenium`, `stagehand`, `skyvern`, `agentops` 等依赖；
  - 官网文档显式提及 "Autonomous Web Agent", "Browser Automation", "Sign up on behalf of user"；
  - 开放 MCP (Model Context Protocol) 工具调用或 REST Webhook 接口。
- **排除条件 (Disqualification)**：
  - 纯聊天机器人（泛聊天/客服问答），无任何外部工具调用或浏览器操作逻辑；
  - 核心产品为一次性营销网页，无持续自动化执行环境；
  - 竞品（如自身已提供临时邮箱中继服务）。
- **潜在购买职位 (Target Buyer Titles)**：
  - `Founding Engineer`, `Lead AI Engineer`, `Head of AI / Autonomous Agents`, `VP of Engineering`, `CTO`
- **常见替代工具**：
  - 自建 Gmail/Outlook 别名（极易被风控封禁）；
  - 自建 AWS SES / Mailgun 接收脚本（开发维护繁重）；
  - 消费级临时邮箱（不稳定、API 经常宕机）。
- **不确定状态 (UNKNOWN States)**：
  - 仅在主页写有 "AI Agent" 标语，但未开放任何 API 文档、白皮书或技术博客细节（标记为 `UNKNOWN_AGENT_CAPABILITY`）。
- **产生购买意图的强信号 (Strong Intent Signals)**：
  - 正在招聘 "Agent Infra Engineer" 或 "Browser Automation Specialist"；
  - GitHub Issue / Twitter / Discord 讨论区中提及 "bypass email verification", "automated account creation flaky", "handling email OTP in agents"。

---

### 2.2 Cohort B: 使用 Playwright/Cypress 构建复杂认证流的 SaaS 研发团队

- **产品使用场景**：
  在持续集成 (CI/CD) 流水线中，端到端 (E2E) 测试用例需要自动化验证新用户注册、密码重置、双因素邮件验证 (Magic Link / OTP) 以及事务通知邮件送达情况。
- **必要匹配条件 (Must-Have)**：
  1. 产品具备邮箱注册入口，且启用了邮件验证码或 Magic Link 机制；
  2. 具有规范的研发与自动化质效工程体系；
  3. 频繁迭代发布，CI 流水线运行高频。
- **可核验的技术证据 (Verifiable Evidence)**：
  - 登录/注册页面表单明确存在 "Enter the 6-digit code sent to your email" 或 "Magic Link"；
  - 技术博客/招聘职位中明确提及 `Playwright`, `Cypress`, `Selenium` 用于 E2E 自动化测试；
  - 域名 SPF 记录或 HTTP 响应中存在 Postmark, SendGrid, Resend 等事务邮件提供商指纹。
- **排除条件 (Disqualification)**：
  - 仅支持企业 SSO (SAML/Okta) 或单一第三方登录 (Google/GitHub/Apple OAuth)，完全无邮箱自建注册流；
  - 纯静态内容展示网站，无任何登录注册与会员体系；
  - 已经重度集成并购买了 Mailosaur / Mailtrap 商业合同且对现状高度满意（无切换诉求）。
- **潜在购买职位 (Target Buyer Titles)**：
  - `Head of QA`, `QA Automation Lead`, `Staff SDET`, `Director of Engineering (Platform/Quality)`, `DevOps Lead`
- **常见替代工具**：
  - Mailosaur, Mailtrap, Testmail.app;
  - 本地 Docker 部署的 MailHog / Mailpit（无法用于公网实际发信验证）；
  - 团队公用真实测试邮箱（测试用例并发执行时极易产生邮箱锁与验证码竞争冲突）。
- **不确定状态 (UNKNOWN States)**：
  - 仅查到域名 SPF 包含 SendGrid，但未探测到公开的注册页面或 E2E 框架线索（标记为 `UNKNOWN_TEST_STACK`）。
- **产生购买意图的强信号 (Strong Intent Signals)**：
  - 正在招聘 "QA Automation Engineer (Playwright/Cypress)" 并在 JD 中强调 "auth & onboarding flow testing"；
  - 近期改版了注册登录认证流（如上线了无密码 Magic Link 登录）；
  - 工程团队公开发表关于 "Flaky E2E tests caused by email delay" 的复盘。

---

### 2.3 Cohort C: 专业自动化测试服务机构与 QA 咨询公司 (QA Agencies & Consultancy)

- **产品使用场景**：
  为多家外部客户搭建并维护自动化回归测试套件。需要多租户、隔离、低成本的临时邮箱基础设施，供多个客户项目同时调用，按项目隔离测试结果。
- **必要匹配条件 (Must-Have)**：
  1. 主营业务为软件自动化测试交付、外包质效工程、独立测试实验室；
  2. 交付物包含 Playwright / Cypress / Selenium 测试脚本与 CI 流水线；
  3. 服务多个 Web SaaS 客户。
- **可核验的技术证据 (Verifiable Evidence)**：
  - 官网主营业务与案例为 "QA Automation Services", "Software Testing Consultancy", "Continuous Testing";
  - 案例集 (Case Studies) 中提及复杂电商、SaaS、金融客户的登录与注册流程测试；
  - 博客或文档中展示对 Playwright / Cypress 邮件拦截方案的探索。
- **排除条件 (Disqualification)**：
  - 纯人工测试外包机构（仅提供众包功能测试、本地化测试，无任何自动化脚本编写能力）；
  - 纯硬件、嵌入式或移动端 Native App 测试公司（无 Web 邮件测试需求）。
- **潜在购买职位 (Target Buyer Titles)**：
  - `Managing Director`, `Head of QA Practice`, `Principal QA Consultant`, `Technical Director`
- **常见替代工具**：
  - 要求甲方客户自备测试账号与内部邮件网关；
  - 免费临时邮箱脚本（经常失效被甲方投诉）。
- **不确定状态 (UNKNOWN States)**：
  - 机构主页宣称全栈测试，但无法验证其自动化测试占比（标记为 `UNKNOWN_AUTOMATION_MATURITY`）。
- **产生购买意图的强信号 (Strong Intent Signals)**：
  - 正在扩张自动化测试工程团队，批量招聘自动化测试开发；
  - 发布过关于解决 E2E 邮件验证痛点的白皮书或客户案例。

---

## 3. 证据链严密性与防伪规则 (Evidence Anti-Hallucination Rules)

1. **非对称推导禁令**：
   - 发现网站使用 Playwright $
Rightarrow$ 正在采购 FetchInbox；
   - 发现域名 SPF 有 Postmark $
Rightarrow$ 正在采购 FetchInbox；
   - 仅当 **[存在 OTP/MagicLink 认证场景] + [存在 E2E/Agent 自动化需求] + [出现近期招聘/架构改版/痛点反馈]** 形成交集时，才构成高价值线索。
2. **证据独立性准则**：
   - 同一页面中 3 次提及 Playwright，计为 **1 项证据**，不得膨胀为多项；
   - 必须区分不同来源（如：官网页面、GitHub 仓库、独立招聘平台）。
3. **时效性准则**：
   - 招聘职位必须处于有效开启状态（超过 90 天未更新或标记 Closed 的职位不可作为即时意向依据）；
   - 技术博客发布时间超过 24 个月的历史记录，置信度下调至 0.3。
