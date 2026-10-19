# W1-02_SSRF_TEST_REPORT.md — SSRF 传输层防御、全入口覆盖矩阵与安全评测报告

> **审计执行人**：Principal Python Security Engineer & Independent Security Auditor
> **评测对象**：Harvey 传输层 HTTP 客户端与不可信 URL 解析模块 (`harvey/security_ssrf.py`, `harvey/collectors/discover.py`, `harvey/collectors/profile.py`)
> **基准 SHA**：`e114e95471b1bf155454fca108f0730b66a47a01`
> **加固分支**：`codex/w1-02-harvey-safety-hardening`
> **测试状态**：18/18 安全测试全通过，零失败
> **安全裁决状态**：`SSRF_TRANSPORT_GUARD_VERIFIED: TRUE` / `READY_FOR_CONTROLLED_DISCOVERY: FALSE (BLOCKED)`

---

## 1. 威胁建模与全入口覆盖矩阵 (Ingress Coverage Matrix)

Harvey 涉及对外 HTTP 请求的入口已进行系统性梳理与防御分类：

| 模块/函数 | 目标 URL 类型 | 防护机制 | 状态/保护级别 |
|---|---|---|---|
| `harvey/collectors/profile.py` (`ProfileCollector.profile`) | 目标企业官网、不可信重定向目标、`robots.txt`、`sitemap.xml` | `SSRFSafeTransport` 强绑定 Socket 层 IP 检查 | **PROTECTED (Fully Guarded)** |
| `harvey/collectors/discover.py` (`geocode_city`) | Nominatim 地理编码服务 (`nominatim.openstreetmap.org`) | `SSRFSafeTransport` 强绑定 Socket 层 IP 检查 | **PROTECTED (Fully Guarded)** |
| `harvey/collectors/discover.py` (`run_discovery`) | SERP / Overpass / DataForSEO 采集网关 | `SSRFSafeTransport` 强绑定 Socket 层 IP 检查 | **PROTECTED (Fully Guarded)** |
| `harvey/collectors/discover.py` (`run_discovery(dry_run=True)`) | 离线评估模式 | 拦截联网地理编码，仅用本地缓存，严格 0 网络请求 | **PROTECTED (Offline Airgap)** |
| `harvey/integrations/instantly.py` | Instantly SaaS API | 所有变更方法 (`POST`, `PATCH`, `DELETE`, `PUT`) 物理拦截断流 | **BLOCKED (Zero Mutation)** |
| `harvey/integrations/email_finder.py` (`verify_email_smtp`) | 外部 MX 25 端口主动探测 | 物理拦截断流，记录日志直接返回 None | **BLOCKED (Zero Outbound)** |
| `harvey/integrations/gmail.py` (`GmailProvider.send_email`) | Google Workspace REST API | 物理拦截硬锁，直接返回 Fail-Closed SendResult | **BLOCKED (Zero Outbound)** |
| `harvey/integrations/smtp_mail.py` (`SmtpImapProvider.send_email`) | 外部 SMTP 服务器 (25/465/587) | 物理拦截硬锁，直接返回 Fail-Closed SendResult | **BLOCKED (Zero Outbound)** |
| `harvey/integrations/microsoft.py` (`MicrosoftProvider.send_email`) | Microsoft Graph API | 物理拦截硬锁，直接返回 Fail-Closed SendResult | **BLOCKED (Zero Outbound)** |
| `harvey/agents/scout.py` | 外部商机抓取 (Scout) | 实验禁发与 W1-04 离线门禁限制，未在受控白名单前禁发 | **BLOCKED (Stage Gated)** |

---

## 2. 传输层阻断架构实现 (`harvey/security_ssrf.py`)

为根治 TOCTOU 与重定向穿透，本方案放弃脆弱的应用层字符串正则匹配，选择在底层 Socket 连接边界实施拦截：

### 2.1 架构设计
- **`SSRFSafeNetworkBackend(httpcore.AnyIOBackend)`**：
  在 `connect_tcp(host, port)` 时执行确定性 DNS 解析；
- **全网段与协议变体合法性断言 (`is_safe_ip`)**：
  利用 Python 原生 `ipaddress.ip_address` 对解析出的全部目标 IP 逐一检查：
  ```python
  if ip.version == 6:
      if ip.ipv4_mapped:
          return is_safe_ip(str(ip.ipv4_mapped))
      if ip.packed.startswith(b"\x00" * 12) and ip != ipaddress.IPv6Address("::"):
          return is_safe_ip(str(ipaddress.IPv4Address(ip.packed[12:])))
      if ip.sixtofour:
          return is_safe_ip(str(ip.sixtofour))
      if ip.teredo:
          server, client = ip.teredo
          if not is_safe_ip(str(server)) or not is_safe_ip(str(client)):
              return False
  if not ip.is_global:
      return False
  if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
      return False
  ```
- **绑定已验证 IP 直连 (Anti-Rebinding Pinning)**：
  将 `connect_tcp` 目标直接切换为首个已通过安全断言的物理 IP，使 HTTP 请求与 TLS 握手均向该绝对安全的 IP 发起（同时通过 SNI 保留原始 Host 头），彻底消除二次解析导致的 DNS Rebinding。
- **重定向链条强制受控**：
  `httpx.AsyncClient(transport=SSRFSafeTransport(), follow_redirects=True)` 在遵循每一个 301/302/307/308 重定向跳转时，底层仍旧必须通过 `SSRFSafeNetworkBackend` 发起新的 TCP 连接，因此任何跳转至内网的请求都会在传输建立瞬间被抛出 `SSRFBlockedError` 强行终止。

---

## 3. 自动化测试与用例矩阵验证

以下用例已在 `tests/test_w1_02_safety_hardening.py` 中 100% 验证通过：

| 测试用例名称 | 测试目标与输入 | 预期结果 | 实际执行状态 |
|---|---|---|---|
| `test_ip_safety_classifier` | `127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `::1`, `::ffff:127.0.0.1`, `0.0.0.0`, `100.64.0.1`, `8.8.8.8` | 私网/元数据/保留网段返回 False，公网返回 True | **PASS** |
| `test_ssrf_blocks_localhost_and_loopback` | `http://127.0.0.1:80`, `http://localhost:80` | 抛出 `SSRFBlockedError`，零 Socket 建立 | **PASS** |
| `test_ssrf_blocks_cloud_metadata` | `http://169.254.169.254/latest/meta-data/` | 抛出 `SSRFBlockedError`，严格阻断 | **PASS** |
| `test_ssrf_blocks_private_subnets` | `10.200.1.5`, `172.20.10.2`, `192.168.100.50` | 抛出 `SSRFBlockedError`，严格阻断 | **PASS** |
| `test_ssrf_blocks_dns_rebinding` | 模拟首包返回 `93.184.216.34`，二次解析返回 `127.0.0.1` | 在重绑定为回环地址时抛出 `SSRFBlockedError` | **PASS** |
| `test_ssrf_blocks_redirect_to_internal` | 302 Redirect 跳转至 `http://127.0.0.1:8080/secret` | 在遵循重定向发起新 TCP 连接时被传输层拦截 | **PASS** |
| `test_ssrf_blocks_ipv4_compatible_and_subtle_variants` | `::127.0.0.1`, `::169.254.169.254`, `::10.0.0.1`, `fd00:ec2::254` | 深度 IPv6 兼容与云元数据格式识别并阻断 | **PASS** |
| `test_discovery_dry_run_zero_external_network_calls` | Discovery dry_run 评估 | 零外部网络请求，坐标缺失时拒绝离线联网 | **PASS** |

---

## 4. 残留风险与公网采集解锁裁决

1. **当前阶段裁决**：
   `READY_FOR_CONTROLLED_DISCOVERY: FALSE (BLOCKED)`
2. **原因说明**：
   虽然 Discover 与 Profile 采集器传输层已经具备 SSRF 物理拦截器且覆盖全入口，但在未证明全路径安全、未获得上级明确授权、未配置特定可信白名单以及未建立每日出网流量硬顶前，`CONTROLLED_DISCOVERY` 必须保持严格 `BLOCKED`。
