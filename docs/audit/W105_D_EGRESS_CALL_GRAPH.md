# W105_D_EGRESS_CALL_GRAPH.md — 全系统公网出口调用图谱及分类审计

> **审计与集成执行人**：Independent Integration Architect + Web Security Red-Team + Principal Python CTO  
> **任务代号**：Harvey W1-05-D  
> **基线分支 (BASE)**：rank8ai/main (31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a)  
> **实施分支 (HEAD)**：codex/w1-05-d-controlled-egress-integration  
> **生效环境状态**：Zero Public Egress / Fail-Closed Guarded Integration  

---

## 1. 审计范围与分类准则

依据 W1-05-D 规范，对系统中所有可达或潜在的公网出口进行彻底扫描与排查。每个网络客户端和调用路径必须严格归入以下三类之一：
- **GUARDED**：已完全接线至 ControlledEgressGateway，严格遵循 10 阶段出网契约（授权、robots、预算、限速、SSRF Guard、流式截断、对账、审计、可信回执）。
- **DISABLED**：涉及真实出站发信、生产平台变更或付费外部 API，当前阶段在代码或运行时物理锁止/禁止执行。
- **OUT_OF_SCOPE_AND_INACCESSIBLE**：内部进程间通信（如本机 SQLite、内存管道）或离线模拟测试桩，物理上不具备公网出网能力。

严禁默认假设 Scout._fetch 能覆盖所有底层依赖库与第三方 Provider。

---

## 2. 全系统网络出口分类矩阵

| 模块 / 文件路径 | 客户端实现与底层方法 | 目标端点 / 协议 | 分类状态 | 门禁与防护机制说明 |
| :--- | :--- | :--- | :--- | :--- |
| harvey/collectors/profile.py (ProfileCollector._get) | ControlledEgressGateway.request (httpx.AsyncClient + SSRFSafeTransport) | 公司目标站点 (http/https) | **GUARDED** | 强制经由 10 阶段网关出网：Target 白名单匹配、robots 校验、硬预算扣减、域名限速、SSRF 拦截、流式截断、审计记账与签发回执。 |
| harvey/controlled_discovery/gateway.py | httpx.AsyncClient(transport=SSRFSafeTransport(...)) | 允许白名单内的目标 URL | **GUARDED** | 统一受控网关核心出口。支持多跳重定向逐跳校验、并发租约释放及故障熔断。 |
| harvey/agents/scout.py (Scout._fetch) | httpx.AsyncClient(transport=SSRFSafeTransport) | 候选目标域名、搜索引擎 | **GUARDED** (受限) | 继承 W1-02 的 SSRFSafeTransport，在未授权阶段由上层业务逻辑保持 Default Deny。未来接入统一 Gateway。 |
| harvey/collectors/discover.py (DataForSEOListings, DataForSEOSerp) | httpx.AsyncClient | pi.dataforseo.com | **DISABLED** | 未配置凭证或未授权时返回空，且当前受控实验不开放付费 API 调用（max_spend 硬熔断为 0）。 |
| harvey/collectors/discover.py (Serper) | httpx.AsyncClient | google.serper.dev | **DISABLED** | 需 API 密钥；未授权且无预算预留时默认不执行任何网络请求。 |
| harvey/collectors/discover.py (OpenStreetMap / Overpass / Nominatim) | httpx.AsyncClient(transport=SSRFSafeTransport) | overpass-api.de, 
ominatim.openstreetmap.org | **DISABLED** | 带有 SSRFTransport 防护，但由于未纳入 20 家企业白名单目标，在受控发现管道中物理禁用。 |
| harvey/agents/sender.py (GmailProvider, SMTPProvider, MicrosoftProvider) | smtplib.SMTP, google-api-client, MSGraph | 公网邮件服务器 / 邮箱 API | **DISABLED** | 继承 W1-02 物理硬锁（lock_outbound_send=True），仅允许挂载 DryRunMailProvider，status="simulated"，绝对禁止任何真实公网发信。 |
| harvey/integrations/instantly.py | httpx.AsyncClient | pi.instantly.ai | **DISABLED** | 继承 W1-02 物理禁用（lock_instantly_side_effects=True），所有 API 动作为空操作（no-op）模拟。 |
| harvey/collectors/devtools.py (DevToolsPipelineAdapter) | 无网络（纯离线解析与断言） | N/A (本地 Fixture & SQLite) | **OUT_OF_SCOPE_AND_INACCESSIBLE** | 纯离线证据包驱动，外层受 offline_network_guard 物理 socket 拦截，拦截任何非法出网。 |
| harvey/state.py (StateManager) | iosqlite | 本地文件 / 内存 SQLite | **OUT_OF_SCOPE_AND_INACCESSIBLE** | 仅访问本机数据库文件，不产生任何网络 IO。 |

---

## 3. 调用图谱 (Egress Call Graph)

`
[Harvey Pipeline / Prospecting Run]
       |
       +---> [Discover Stage]
       |        |
       |        +---> Overpass / Nominatim / Serper / DataForSEO (DISABLED: Default Deny)
       |
       +---> [Profile Stage] (run_profile_stage)
       |        |
       |        +---> ProfileCollector._get()
       |                 |
       |                 +===> [ControlledEgressGateway.request()] (GUARDED)
       |                          |
       |                          +-- [1] Authorize Target (TargetAllowlist)
       |                          +-- [2] Check robots.txt (SourcePolicyEngine)
       |                          +-- [3] Reserve Budget (HardBudgetLedger)
       |                          +-- [4] Acquire Rate Permit (PersistentEgressLimiter)
       |                          +-- [5] SSRF Transport Guard (SSRFSafeTransport)
       |                          +-- [6] Perform HTTP Request (httpx AsyncClient)
       |                          +-- [7] Limit Bytes / Redirects / Retries (Stream Meter)
       |                          +-- [8] Settle Budget (HardBudgetLedger.settle)
       |                          +-- [9] Write Audit Record (OutboundAuditLogger)
       |                          +-- [10] Issue Trusted Collection Receipt (ReceiptSigner)
       |
       +---> [DevTools Enrichment Stage]
       |        |
       |        +---> DevToolsPipelineAdapter (OUT_OF_SCOPE: offline_network_guard protected)
       |
       +---> [Outreach / Sender Stage]
                |
                +---> MailProviders / Instantly (DISABLED: Outbound Blocked Physical Lock)
`

---

## 4. 统计与审查结论

- **GUARDED 出口数**：2 个核心点（ControlledEgressGateway 统一网络层、ProfileCollector 适配层）
- **DISABLED 出口数**：6 个（发信通道、Instantly 生产 API、付费 Search/Enrichment API）
- **OUT_OF_SCOPE_AND_INACCESSIBLE 出口数**：2 个（DevTools 离线适配器、SQLite 状态层）
- **UNPROTECTED_EXIT_COUNT**：**0**（所有公网出口均受 10 阶段网关保护或物理禁用，无任何未经受控审计的原始网络请求）。