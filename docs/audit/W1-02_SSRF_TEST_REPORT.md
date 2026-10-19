# W1-02_SSRF_TEST_REPORT.md — SSRF 传输层防御与不可信 URL 安全评测报告

> **审计执行人**：Principal Python Security Engineer & Independent Security Auditor  
> **评测对象**：Harvey 传输层 HTTP 客户端与不可信 URL 解析模块 (`harvey/security_ssrf.py`, `harvey/collectors/profile.py`)  
> **基准 SHA**：`e114e95471b1bf155454fca108f0730b66a47a01`  
> **测试状态**：14/14 全通过，零失败  
> **安全裁决状态**：`SSRF_TRANSPORT_GUARD_VERIFIED: TRUE` / `READY_FOR_CONTROLLED_DISCOVERY: FALSE (BLOCKED)`

---

## 1. 威胁建模与攻击面分析 (Threat Modeling)

Harvey 的 FetchInbox 自用阶段涉及对潜在客户企业官网及其 `sitemap.xml`、`robots.txt`、careers 页面发起 HTTP 抓取。潜在攻击者可能通过以下手段实施 SSRF：
1. **本机回环访问 (Localhost / Loopback Probe)**：
   指向 `127.0.0.1`、`localhost`、`::1`、`0.0.0.0`，试图刺探 Harvey 自身开放的本地 Dashboard (`127.0.0.1:5555`) 或宿主机其他微服务。
2. **私有内网探测 (RFC1918 Private Subnets)**：
   指向 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`，探测局域网内部未授权服务。
3. **云厂商元数据盗取 (Cloud Metadata Exfiltration)**：
   指向 `169.254.169.254`（AWS/GCP/Azure/OpenStack Instance Metadata），试图盗取 IAM 凭证与主机密钥。
4. **IPv4 映射的 IPv6 规避 (IPv4-mapped IPv6 Bypass)**：
   使用 `::ffff:127.0.0.1` 或 `::ffff:169.254.169.254` 绕过仅检查点分十进制的简陋正则表达式。
5. **DNS 重绑定攻击 (DNS Rebinding TOCTOU)**：
   域名第一次 DNS 查询返回公网 IP，在连接建立前 DNS 记录被篡改为 `127.0.0.1`；如果先做 URL 检查再发起 HTTP 请求，将产生经典 TOCTOU 漏洞。
6. **HTTP 30x 重定向绕过 (Open Redirect SSRF)**：
   初次请求公网合法 URL，服务端返回 302 重定向至内网目标 `http://169.254.169.254/latest/meta-data/`。

---

## 2. 传输层阻断架构实现 (`harvey/security_ssrf.py`)

为根治 TOCTOU 与重定向穿透，本方案放弃应用层字符串正则匹配，选择在底层 Socket 连接边界实施拦截：

### 2.1 架构设计
- **`SSRFSafeNetworkBackend(httpcore.AnyIOBackend)`**：
  在 `connect_tcp(host, port)` 时执行确定性 DNS 解析；
- **全网段合法性断言 (`is_safe_ip`)**：
  利用 Python 原生 `ipaddress.ip_address` 对解析出的全部目标 IP 逐一检查：
  ```python
  if ip.version == 6 and ip.ipv4_mapped:
      ip = ip.ipv4_mapped
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

---

## 4. 残留风险与公网采集解锁裁决

1. **当前阶段裁决**：
   `READY_FOR_CONTROLLED_DISCOVERY: FALSE (BLOCKED)`
2. **原因说明**：
   虽然 Profile 采集器传输层已经具备 SSRF 物理拦截器，但在未获得上级明确授权、未配置特定可信白名单以及未建立每日出网流量硬顶前，Harvey 依然禁止发起未经受控的真实公网爬取。
