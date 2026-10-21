# FETCHINBOX_PRODUCT_TRUTH.md — FetchInbox 真实产品能力与技术边界审计

> **审计视角**：Principal AI Sales Architect & Independent Evaluation Scientist
> **审计日期**：2026-10-19
> **审计对象**：`frank8ai/cloudflare_temp_email` 物理代码库（HEAD `3cd1b3b`）、配置与生产对齐规范
> **基线准则**：区分 `IMPLEMENTED / DEPLOYED / TESTED / PLANNED / NOT_VERIFIED`，杜绝将开源模板或臆测能力冒充为实际交付事实。

---

## 1. 核心产品定位与架构真相 (Product Truth)

FetchInbox（工程代码库 `cloudflare_temp_email`）是一个基于 Cloudflare Workers + D1 + Email Routing + KV 构建的**开发者临时邮箱接收与自动化验证码 (OTP) / Magic Link 提取中枢**。

### 1.1 核心价值定位
- **不是什么**：不是大规模营销外发邮件平台（SendGrid/Mailgun 竞品），不是人工日常办公邮箱客户端（Gmail/Outlook 竞品），不是永久个人身份邮箱。
- **是什么**：面向自动化测试工程师（Playwright/Cypress/Selenium）、AI Agent / 浏览器自动化开发者、多租户测试团队的**可编程接收邮箱 API**，专门解决端到端（E2E）注册认证流、验证码拦截、邮箱隔离生命周期痛点。

---

## 2. 功能清单与状态判定矩阵 (Feature Status Matrix)

| 功能模块 | 具体能力项 | 证据代码位置 | 状态判定 | 约束与边界说明 |
| :--- | :--- | :--- | :--- | :--- |
| **邮箱创建与管理** | 匿名随机邮箱生成 (`POST /api/new_address`) | `worker/src/mails_api/new_address.ts:10-70` | `DEPLOYED` / `TESTED` | 受每日 IP / 凭证配额限制 (`acc_anon_*` 封顶，`admitAddressCreation`)。 |
| | 认证用户创建邮箱 (`userPayload`) | `worker/src/mails_api/new_address.ts:50` | `DEPLOYED` / `TESTED` | 绑定 `acc_user_${user_id}`，按商业套餐配额准入。 |
| | 自定义前缀与名称 | `worker/src/common.ts`, `new_address.ts:57` | `DEPLOYED` / `TESTED` | 受 `DISABLE_CUSTOM_ADDRESS_NAME` 与 `ADDRESS_BLOCK_LIST` 限制。 |
| | 随机子域名支持 | `new_address.ts:59` (`enableRandomSubdomain`) | `IMPLEMENTED` / `TESTED` | 依赖 Cloudflare 泛解析配置。 |
| **邮件接收与读取** | 实时邮件入库 (Cloudflare Email Worker) | `worker/src/email/storage.ts`, `worker/src/worker.ts` | `DEPLOYED` / `TESTED` | 邮件正文解析存储在 D1 `raw_mails`，附件支持 S3/R2 离线存储。 |
| | 邮件列表与详情读取 (`GET /api/mails`, `GET /api/mail/:id`) | `worker/src/mails_api/mails_crud.ts` | `DEPLOYED` / `TESTED` | 依赖邮箱凭证 JWT (`addressJwtAuth`) 或 API Key。 |
| | 原始邮件 MIME / Raw Blob 解析 | `worker/src/gzip.ts`, `db/2026-04-03-raw-blob.sql` | `DEPLOYED` / `TESTED` | 支持 RFC822 原始数据压缩还原与解析。 |
| **验证码 / 链接提取** | 自动化 4-8 位 OTP 正则提取 | `worker/src/email/extract_code.ts:1-120` | `DEPLOYED` / `TESTED` | 支持中英文上下文、多重过滤；区分验证码提取失败与配额耗尽。 |
| | Magic Link 提取 | `worker/src/control_plane/matcher.ts:40-90` | `DEPLOYED` / `TESTED` | 自动匹配并提取确认链接、重置密码链接。 |
| | 单次阻塞等待验证码 (`GET /api/wait_for_otp`) | `worker/src/mails_api/wait_for_otp.ts:25-110` | `DEPLOYED` / `TESTED` | 轮询等待 3-8 秒，超时自动返回，免去客户端高频轮询。 |
| **自动化与集成** | 商业 Run 自动化周期 (`POST /v1/runs`) | `worker/src/control_plane/api.ts:45-90` | `DEPLOYED` / `TESTED` | 自动分配临时邮箱，按租期 (`lease_expires_at`) 自动隔离与回收。 |
| | Webhook 实时推送 (邮件到达推送) | `worker/src/admin_api/mail_webhook_settings.ts`, `utils/webhook.ts` | `IMPLEMENTED` / `TESTED` | 支持邮件入库后向用户自定义 Webhook URL 触发 HTTP POST。 |
| | MCP (Model Context Protocol) 服务端 | `worker/src/mcp/index.ts:1-90` | `DEPLOYED` / `TESTED` | 原生开放 `/mcp`，提供 `create_temp_inbox` 等无状态工具调用。 |
| **商业计费与配额** | Stripe 订阅与 Webhook 自动对账 | `worker/src/control_plane/api.ts:350-700` | `DEPLOYED` / `TESTED` | 支持 Developer / Team 套餐自动开通与生命周期更新（PR #51 / PR #58）。 |
| | 商业 API Key 双模鉴权 (`fi_live_*`, `getotp_live_*`) | `worker/src/control_plane/service.ts:31-48` | `DEPLOYED` / `TESTED` | SHA256 哈希比对，支持 `Authorization: Bearer` 与 `x-api-key`。 |
| | 自助账单控制台 (Stripe Customer Portal) | `POST /user_api/commercial/billing_portal` | `DEPLOYED` / `TESTED` | 用户可自主取消订阅、更新信用卡。 |
| **未实现 / 规划中** | 自定义企业私有域直接托管 (Bring Your Own Domain API) | - | `PLANNED` | 当前仅支持官方预配置的接收域名池轮换，不支持企业一键绑定自身主域。 |
| | 外部 SMTP 发信中继（主动向外发送营销邮件） | `smtp_proxy_server/` | `NOT_VERIFIED` / `DEPRECATED` | 仅为辅助代理原型，生产核心聚焦**收信与验证**，禁止作为出站营销主力。 |
| | 全球多区域物理专线合规归档 (HIPAA / SOC2 专有存储) | - | `PLANNED` | 目前依赖 Cloudflare 默认多租户边缘，未提供专有隔离硬件版。 |

---

## 3. 计费套餐与资源限制真相 (Plan Truth & Limits)

依据 `worker/src/control_plane/types.ts` 与 PR #58 交付成果：

1. **Free / 匿名体验层 (Anonymous / Free)**：
   - 每日邮箱创建限额（防刷守卫）：`acc_anon_*` 严格每日频控；
   - 提取配额：有限的每日免费 OTP 提取，达到上限返回 HTTP 429 (`quota_exceeded`)。
2. **Developer 套餐 ($19/mo 或等价计费)**：
   - 支持商业 API Key (`fi_live_*`)；
   - 每月固定额度收信与自动化 Run 创建；
   - 专属并发控制通道（`PLAN_CONCURRENCY_LIMITS.developer`）；
   - 官方 MCP 协议支持与 Playwright 自动化优先通道。
3. **Team 套餐 ($49/mo 或等价计费)**：
   - 更高的并发 Run 限制与提取吞吐量；
   - 多成员共享与增强型 Webhook 支持；
   - 优先客服支持与高可用域名池。

---

## 4. 真实客户价值主张与采购痛点 (Pain Point & Value Proposition)

### 4.1 核心买点 (Why Buy FetchInbox?)
1. **无需自建维护复杂的邮件服务器**：免去自建 Postfix/Haraka/Caddy SMTP 或配置 AWS SES 接收规则的巨大运维开销；
2. **免除测试中的图形界面验证码与手动查收**：直接通过 `POST /v1/runs` 或 `GET /api/wait_for_otp` 在 3 秒内拿到提取出的验证码或链接，CI/CD 流水线不会卡死；
3. **彻底隔离真实测试账号**：每个测试用例使用专属干净邮箱，解决测试账号脏数据、邮箱唯一性冲突和密码找回碰撞；
4. **AI Agent / 自动化操作的即插即用收件箱**：通过 MCP 协议或 REST API，AI Agent 可以自主完成 SaaS 注册、邮件验证、报告查收，无需人类干预。

### 4.2 替代竞品对比分析
- **Mailosaur / Mailtrap**：老牌 E2E 邮件测试平台，价格昂贵（企业版往往 $100+/mo），且偏向传统虚拟 SMTP 捕获，缺少原生轻量级 Agent/MCP 适配；
- **10MinuteMail / GuerrillaMail 等消费级临时邮箱**：界面充斥广告，无稳定商业 API，无并发保障，IP/域名常年被各大 SaaS 列入黑名单；
- **自建 Cloudflare Email Routing / AWS SES**：开发团队需要自己写 Worker、D1 存储、正则解析、去重对账与过期清理，耗费数十人天工程成本。

---

## 5. 对销售智能商机识别 (Harvey Lead Qualification) 的指导约束

1. **不可承诺未部署能力**：不得向客户推销“企业自定义域名托管发信”或“无限量高并发外发”，FetchInbox 是**入站验证码与自动化收件箱 API**；
2. **不可将技术重叠误认为购买意图**：
   - 发现对方使用 SendGrid/Postmark -> 说明有事务邮件场景，但不证明在买 FetchInbox；
   - 发现对方使用 Playwright/Cypress -> 说明有自动化测试栈，需进一步寻找是否存在“注册流程/邮件通知测试痛点”；
3. **最高转化潜力的线索特征**：
   - 正在招聘 QA 自动化工程师或 AI Agent 工程师，且 JD 中明确提及“E2E testing, authentication flow, browser automation”；
   - 产品具有公开的邮箱注册入口、邮件 OTP 登录，或其核心产品本身就是 Browser/AI Agent 工具。
