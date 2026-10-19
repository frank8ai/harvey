# W1-02_OUTBOUND_CALL_GRAPH.md — 全域出站外联调用链与副作用阻断拓扑

> **审计执行人**：Principal Python Security Engineer & Independent Security Auditor  
> **基准 SHA**：`e114e95471b1bf155454fca108f0730b66a47a01` (Upstream HEAD)  
> **加固分支**：`codex/w1-02-harvey-safety-hardening`  
> **审计日期**：2026-10-19  
> **安全裁决状态**：`OUTBOUND_SEND_PHYSICALLY_BLOCKED: TRUE` / `INSTANTLY_SIDE_EFFECTS_BLOCKED: TRUE`

---

## 1. 真实出站外发调用拓扑 (Outbound Call Graph)

在原版 Harvey 中，外发出站请求存在两条独立主路径：**Native Mail Provider** 与 **Instantly.ai Legacy REST API**。

```
                       [ Trigger Surfaces ]
         ┌───────────────────────┬────────────────────────┐
         │                       │                        │
  Dashboard UI               CLI Commands              Heartbeat Loop
(Approve / Approve All)    (harvey outbox / run)   (Sender._drain_due)
         │                       │                        │
         └───────────────────────┴────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
       [ Native Providers Path ]        [ Instantly Legacy Path ]
                 │                               │
        Sender._drain_due()             Sender._deploy_campaign()
                 │                      Handler.send_reply()
                 │                               │
        Sender.provider (Guard)         InstantlyClient (Guard)
                 │                               │
      ┌──────────┴──────────┐            ┌───────┴───────┐
      │                     │            │               │
  [Gmail]               [SMTP]       [Campaigns]     [Leads / Replies]
GmailProvider.send    SmtpProvider    /campaigns      /leads, /emails/reply
      │                     │            │               │
  [M365 Graph]          [DryRun]         │               │
MicrosoftProvider   DryRunMailProvider   │               │
      │                     │            │               │
      X                     │            X               X
[BLOCKED: Fail-Closed]  [In-Memory]  [BLOCKED: DryRun] [BLOCKED: DryRun]
```

---

## 2. 详细调用链路剖析

### 2.1 Native Mail Provider 链路 (Gmail, Microsoft Graph, SMTP)
1. **触发层**：
   - Dashboard: `/api/outbox/approve-all` 或 `/api/outbox/{id}/approve` -> `state.approve_outbox()`
   - CLI: `harvey outbox --approve-all` / `harvey outbox --approve <id>`
   - Heartbeat: `harvey/main.py` 调度 `sender.run()` -> `Sender._drain_due()`
2. **调度层**：
   - `Sender._drain_due()` 抓取状态为 `approved` 且 `send_at <= now` 的出件箱记录；
   - 经过 `pre_send_check` 文本、合规审查（Precleared）；
   - 执行 `await self.provider.send_email(to_email, subject, body, ...)`.
3. **加固阻断边界**：
   - **门禁 1 (Provider 注入拦截)**：`Sender.__init__` 与 `Handler.__init__` 在检测到实验安全模式生效时，自动将除 Mock/DryRun 之外的任何 Provider（即使用户在 `harvey.yaml` 设置了 `gmail` 或 `smtp`）替换为 `DryRunMailProvider`，外发数据包真实调用次数物理为 0。
   - **门禁 2 (底层 Provider 物理硬锁)**：
     - `GmailProvider.send_email()`：直接返回 `SendResult(ok=False, error="PHYSICALLY BLOCKED: Gmail live sending is physically disabled...")`，绝不调用 `POST /messages/send`；
     - `SmtpImapProvider.send_email()`：直接返回 `SendResult(ok=False, error="PHYSICALLY BLOCKED: SMTP live sending is physically disabled...")`，绝不初始化 `aiosmtplib.send` Socket；
     - `MicrosoftProvider.send_email()`：当 `self._transport is None`（即非测试 Mock 传输时）直接拦截，绝不调用 Graph `sendMail` API。

### 2.2 Instantly.ai 侧效应链路
1. **独立触发入口**：
   - `Sender._deploy_campaign()`:
     - `client.create_campaign(name)` -> `POST /campaigns`
     - `client.set_campaign_emails(id, sequences)` -> `POST /campaigns/{id}/emails`
     - `client.add_leads(id, leads)` -> `POST /leads`
     - `client.activate_campaign(id)` -> `POST /campaigns/{id}/activate`
   - `Handler._process_reply()`:
     - `client.send_reply(uuid, response)` -> `POST /emails/reply`
2. **加固阻断边界**：
   - 在 `harvey/integrations/instantly.py` 的底层 `_request()` 方法中：
     - 所有变更性请求方法（`POST`, `PATCH`, `DELETE`, `PUT`）全部被拦截断流；
     - 返回模拟成功且标记 `dry_run: True` 的虚拟结构，绝不发出任何外部 HTTP 流量；
     - 避免向 Instantly 生产服务器创建 Campaign、上传真实线索或自动回复。

### 2.3 Email Verification 外部 SMTP 探测链路
- 原版 `harvey/integrations/email_finder.py` 中 `verify_email_smtp(email)` 会尝试对目标域名的 MX 服务器 25 端口建立真实 TCP 连接并发送 `HELO/MAIL FROM/RCPT TO` 进行收件人探测。
- **加固阻断边界**：
  - `verify_email_smtp(email)` 顶部注入物理阻断门禁，直接记录安全日志并返回 `None`；
  - 彻底杜绝在验证邮箱时向外部邮件网关泄露 IP 或触碰反垃圾邮件蜜罐。

---

## 3. 回复 Agent 自动外发路径核查

1. **Native 模式下的回复**：
   - `Handler._queue_native_reply()` 将回复写入 `outbox`，类型为 `kind="reply"`；
   - 必须同样经过 `require_approval` 与 `Sender._drain_due()` 流程；
   - 依赖统一的 Provider 发送门禁，被物理锁定为 `DryRunMailProvider`。
2. **Instantly 模式下的自动回复**：
   - 原版通过 `self.instantly.send_reply(reply_uuid, response)` 立即发出；
   - 现已被 `InstantlyClient._request` 物理阻断，不会在外部产生实际外发流量。
