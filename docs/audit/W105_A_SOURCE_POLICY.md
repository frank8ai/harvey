# W1-05-A Source Policy & Robots Gating Architecture Audit

**Status**: REMEDIATION_COMPLETE (W1-05-A-R Closed)  
**Module**: `harvey.controlled_discovery.policy`  
**Execution Context**: Offline Rules Engine / Zero Public Network Egress  
**Target Gate**: FetchInbox 20 Controlled Study Inbound & Outbound Access Control  

---

## 1. 核心架构与设计原则

为未来 FetchInbox 20 家受控企业研究建立可验证的来源授权与访问政策引擎（Source Policy Engine）。
本任务为纯规则计算引擎，严禁发起任何真实公网采集。

### 1.1 授权状态正交分离 (Orthogonal Status Separation)
严禁将“公开可访问”等同于“商业用途或采集授权”。引擎严格区分 6 个维度的独立状态：
1. `SOURCE_DISCOVERED`：实体/域名被发现。
2. `PUBLICLY_ACCESSIBLE`：网络拓扑上公网可通。
3. `ROBOTS_ALLOWED`：目标站点 `robots.txt` 规则明确允许。
4. `TERMS_REVIEWED`：服务条款（ToS/Robots/Legal）已完成法律与合规审查。
5. `DATA_USE_AUTHORIZED`：数据采集与分析目的已获得合规授权。
6. `APPROVED_FOR_EXPERIMENT`：进入受控实验清单并通过安全委员会审批。

只有当全部必要授权维度满足时，系统方可放行访问。

---

## 2. 默认安全配置 (Fail-Closed Default Deny)

1. **白名单机制**：
  - 全部真实企业目标默认 `DENY`。
  - 默认不预置任何可直接使用的真实 20 家目标企业名单（零生产名单硬编码）。
2. **子域名隔离**：
  - 子域名不自动继承主域名授权（例如授权 `acme-corp.test`，`sub.acme-corp.test` 默认拒绝），必须显式配置 `allow_subdomains=True` 或显式注册。
3. **URL 规范化与严格过滤**：
  - 拒绝含有账号凭据的 URL（`http://user:pass@host/`）。
  - 仅允许 `http` 与 `https` Scheme。
  - 阻断直接 IP 地址抓取（IPv4/IPv6 Literal 均被拒，防止绕过域名白名单审计）。
  - 阻断非标端口，默认仅放行注册的目标端口（如 80, 443, 8443）。
  - 自动处理大小写规范化、尾随点（FQDN）剥离、IDN/Punycode 转换及 Query 参数排序。
4. **离线 robots.txt 评估**：
  - 绝不自动发起公网网络请求下载 `robots.txt`。
  - 接受离线文本注入（`inject_robots_txt`）或 Mock Fetcher 回调注入。
  - 当 robots 状态为 `UNKNOWN` 或 `FETCH_FAILED` 时，执行 **Fail-Closed**，拒绝访问。
5. **重定向防御 (Redirect Re-Authorization)**：
  - 每一个重定向 Jump 目标均视为独立出站请求，重新通过白名单、Company ID、路径前缀及 robots 校验。
  - 跨域名或跨企业重定向直接被拦截。
6. **互补 SSRFSafeTransport**：
  - 位于应用层/政策层，先行进行合规与授权裁决；下层由 `SSRFSafeTransport` 在套接字连接层拦截 DNS 重绑定与内网回环，形成纵深防御。

---

## 3. 核心契约与接口定义

### 3.1 PolicyDecision
```python
@dataclass(frozen=True)
class PolicyDecision:
   decision: DecisionCode
   allowed: bool
   company_id: Optional[str]
   url: str
   normalized_url: Optional[NormalizedUrl]
   reason: str
   authorization_statuses: Set[AuthorizationStatus]
   robots_status: RobotsFetchStatus
   audit_timestamp: str
```

### 3.2 DecisionCode 枚举
- `ALLOWED`: 判定通过
- `DENIED_NOT_IN_ALLOWLIST`: 域名未注册
- `DENIED_COMPANY_MISMATCH`: 域名归属企业与请求企业不一致
- `DENIED_SUBDOMAIN_NOT_PERMITTED`: 未显式授权的子域名
- `DENIED_SCHEME_UNSUPPORTED`: 非 HTTP/HTTPS
- `DENIED_CREDENTIALS_PRESENT`: URL 含有嵌入凭据
- `DENIED_PORT_PROHIBITED`: 端口不在允许范围
- `DENIED_IP_LITERAL`: 直接使用 IP 地址
- `DENIED_MALFORMED_URL`: 格式错误
- `DENIED_PATH_OUT_OF_SCOPE`: 路径越界
- `DENIED_DISALLOWED_CONTENT_TYPE`: 禁止的内容类型 (如 PDF, ZIP, 媒体文件)
- `DENIED_SOURCE_STATUS_FAIL_CLOSED`: 来源审核状态未通过
- `DENIED_PURPOSE_NOT_AUTHORIZED`: 访问目的未获授权
- `DENIED_AUTHORIZATION_EXPIRED`: 授权已过期
- `DENIED_INSUFFICIENT_PERMISSIONS`: 缺失法定授权维度
- `DENIED_ROBOTS_DISALLOWED`: 被 robots.txt Disallow
- `DENIED_ROBOTS_FETCH_FAILED`: robots 读取失败 (Fail-Closed)
- `DENIED_ROBOTS_POLICY_UNKNOWN`: 未提供 robots 策略 (Fail-Closed)
- `DENIED_REDIRECT_TARGET`: 重定向目标不合规

---

## 4. 下游 Agent D 接入指引 (Integration Manifest)

后续 Agent D 将本规则引擎挂载至爬虫与采集管道时，必须按以下契约接线：
1. **注入点 1 (Pre-Flight Gate)**：
  在 `harvey.collectors` 或网络调用之前，实例化 `SourcePolicyEngine` 并调用 `evaluate_url(url, company_id=..., purpose=...)`。若 `decision.allowed is False`，立即抛出异常或返回阻断记录，严禁进入网络层。
2. **注入点 2 (Redirect Hook)**：
  在 HTTP Client（如 `httpx.AsyncClient` 的 `event_hooks={'response': [...]}`）或重定向跟踪逻辑中，针对 HTTP 301/302/307/308 Location 头调用 `evaluate_redirect(initial_url, location_url, company_id=...)`。
3. **注入点 3 (Robots Cache 载入)**：
  在任务启动阶段，通过受控存储载入该目标企业的离线 robots 文本，通过 `engine.inject_robots_txt(domain, content)` 灌入。

---

## 5. 验收裁决

- `SOURCE_POLICY_COMPONENT_READY = PASS`
- `CONTROLLED_DISCOVERY_READY = HOLD` (维持暂停，待下游 Agent 调度与受控环境就绪)
- `LIVE_OUTREACH_READY = FORBIDDEN` (严禁公网主动发信与采集)

---

## 6. 安全审计缺陷终验与整改记录 (W1-05-A-R Remediation)

针对独立安全审计与 Red Team 报告发现的 4 项关键安全缺陷（SEC-01 至 SEC-04），本阶段完成了严格的 Red-before-Green 复现、代码修复与闭环断言。

### 6.1 缺陷整改与加固措施矩阵
| 缺陷编号 | 威胁级别 | 缺陷类型与攻击场景 | 修复与加固实现 (Fail-Closed) |
| :--- | :--- | :--- | :--- |
| **SEC-01** | **P0** | 编码路径穿越与歧义转义 (`%2e`, `%2f`, `%5c`, `%25`, 多层编码, 反斜杠, 空字节) 绕过白名单路径检查 | 在 `normalize_url` 引入严格 Fail-Closed 过滤：URL 含 `\`、空字节或路径含 `%2E`, `%2F`, `%5C`, `%25`, `%00` 及畸形 `%` 编码直接拒绝，抛出 `ValueError` (映射为 `DENIED_MALFORMED_URL`)；路径采用 `posixpath.normpath` 严格规范化。 |
| **SEC-02** | **P1** | 空白名单放行漏洞 (`allowed_path_prefixes = []` 漏判放行任意路径) | `evaluate_url` 增加 Fail-Closed 判定：当 `allowed_path_prefixes` 为空时直接返回 `DENIED_PATH_OUT_OF_SCOPE`。若确需授权全站，必须显式配置 `["/"]`。 |
| **SEC-03** | **P1** | `urllib.robotparser` 标准库缺陷 (不支持最长规则优先、同长度 Allow > Disallow 颠倒、不支持通配符 `*` 与行尾 `$`、忽略大小写敏感性) | 实现无依赖的 `RFC9309RobotsParser`、`RFC9309Group` 与 `RFC9309Rule` 纯 Python 引擎：严格遵循 RFC 9309 最具体规则匹配 (Longest Match)、同长 Allow 胜出、`*` 与 `$` 正则编译、区分大小写路径比对及 User-Agent 精确匹配优先于通配。 |
| **SEC-04** | **P1** | 前缀边界混淆漏洞 (`/public` 误放行 `/publicity`, `/public_notes`) | 引入 `_matches_path_prefix(path, prefix)` 严格目录边界匹配：仅当路径与前缀完全一致或后接 `/` 时放行，彻底阻断字符串前缀混淆。 |

### 6.2 Red-before-Green 验证证据
- **Red 阶段**：在 `tests/test_w105_source_policy.py` 中编写 `TestSecurityDefectsRedReproductions`，在原缺陷版本下精准复现全部 6 项失败（SEC-01 编码穿越放行、SEC-02 空前缀放行、SEC-03 顺序相关/通配符失效、SEC-04 前缀混淆越界）。
- **Green 阶段**：加固代码落地后，35 项专项用例 100% 通过；联合 109 项安全与业务回归用例 100% 绿灯通过，0 真实网络套接字请求。

### 6.3 最终门禁状态
- `MERGE_READY = PASS`
- `CONTROLLED_DISCOVERY_READY = HOLD` (维持暂停，待下游 Agent 调度与受控环境就绪)
- `LIVE_OUTREACH_READY = FORBIDDEN` (严禁公网主动发信与采集)
