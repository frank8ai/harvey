# W105_B_RATE_LIMIT_REPORT.md — 可持久化请求限速、并发控制与资源熔断审计报告

> **审计与实施人**：Principal Distributed Systems Engineer & Python Networking Architect  
> **任务代号**：Harvey W1-05-B  
> **分支**：`codex/w1-05-b-egress-limiter`  
> **依赖前置状态**：PR #2 已于 2026-10-21T05:05:37Z 合并至 main (`31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a`)，门禁放行  
> **BASE_SHA**：`31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a`  
> **HEAD_SHA**：3cd3c96d92b00a5d8408e0633b79fab1276386b  
> **组件状态**：
> - `EGRESS_LIMITER_COMPONENT_READY = PASS`
> - `CONTROLLED_DISCOVERY_READY = HOLD`
> - `LIVE_OUTREACH_READY = FORBIDDEN`

---

## 1. 架构目标与设计原则

Harvey 系统的 Discovery、Profile 与 Scout 组件需要对外部 HTTP 请求实施严格的流量配额管制与并发防线，以避免因爬虫失控导致的封禁、目标站点压力过载或资源枯竭。

本模块 (`harvey/controlled_discovery/limiter.py`) 提供了独立、无损、且**完全离线优先**的请求资源协调器：
1. **真实跨进程约束**：拒绝使用单进程内部易伪造的 `asyncio.Semaphore`，而是基于 SQLite WAL 模式 + `BEGIN IMMEDIATE` 互斥排他事务建立租约账本 (`egress_leases`) 与域名状态表 (`egress_domain_state`)，在多 Worker 进程同时竞争时杜绝超发。
2. **先领许可再发请求**：必须在执行任何网络请求前通过 `limiter.acquire(url)` 成功获取 `RequestLease`；无论请求成功、超时、被拒还是抛出异常，均通过异步上下文管理器 (`async with`) 或显式 `release()` 结算，失败亦计入域名配额。
3. **安全离线阻断 (Fail-Closed)**：默认 `offline_mode=True`，任何试图获取真实网络许可的操作直接抛出 `OfflineEgressBlockedError`，物理杜绝意外流量外溢。
4. **租约时效与崩溃恢复**：引入租约 TTL (`lease_ttl_seconds=30.0`) 与过期原子清理机制，当任一 Worker 进程意外崩溃或死锁退出后，其持有的租约自动释放，避免容量永久锁死。
5. **时间防御**：引入 `Clock` 协议与单调时钟防范，当系统时间回拨或时钟跳跃时不产生死循环；支持 `FakeClock` 用于纳秒级模拟测试。

---

## 2. 请求许可接口与参数契约 (API Contract)

### 2.1 核心配置契约 (`LimiterConfig`)

```python
@dataclass(frozen=True)
class LimiterConfig:
    global_concurrency: int = 1               # 全局最大并发请求许可数
    per_domain_concurrency: int = 1           # 单域名最大并发请求许可数
    min_domain_interval_seconds: float = 2.0  # 同域名两次请求间最短间隔 (秒)
    request_timeout_seconds: float = 15.0     # 单次请求超时时间 (秒)
    max_redirects: int = 3                    # 最大重定向次数限制
    max_response_bytes: int = 2 * 1024 * 1024 # 单响应体最大字节数 (2 MiB)
    max_retries: int = 3                      # 最大重试次数
    base_retry_backoff_seconds: float = 1.0   # 退避基础秒数
    max_retry_backoff_seconds: float = 30.0   # 退避最大秒数
    lease_ttl_seconds: float = 30.0           # 租约有效生存时间 (TTL)
    offline_mode: bool = True                 # 离线保护锁 (默认开启)
```

### 2.2 请求许可与生命周期接口 (`RequestLease` & `PersistentEgressLimiter`)

```python
# 1. 申请许可 (支持超时控制与重试次数检查)
lease = await limiter.acquire(
    url_or_domain="https://target-company.com/api",
    attempt=1,
    timeout=5.0,
)

# 2. 异步上下文自动释放保护 (支持任务取消、超时、异常归还)
async with lease:
    # 计量流式响应体
    meter = lease.new_meter()
    async for chunk in response.stream():
        meter.update(chunk)  # 超过 2 MiB 抛出 ResponseSizeLimitExceededError
        ...
    # 重定向步进 (超过 3 次抛出 RedirectLimitExceededError)
    await lease.record_redirect("https://target-company.com/next")

# 3. 显式归还与结算 (可记录 429 Retry-After 冷却窗口)
await lease.release(
    outcome=LeaseReleaseOutcome.RATE_LIMITED,
    retry_after_seconds=120.0,
    http_status=429,
    bytes_metered=meter.bytes_metered,
)
```

---

## 3. 持久化存储契约 (SQLite Schema Contract)

所有状态均持久化存储于本地 SQLite 数据库（开启 WAL 模式、NORMAL 同步与 busy_timeout 10000ms），具备 ACID 保证：

```sql
-- 1. 活跃请求租约表 (记录正在占用并发配额的 Worker 租约)
CREATE TABLE IF NOT EXISTS egress_leases (
    lease_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    worker_pid INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    acquired_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_egress_leases_domain ON egress_leases(domain);
CREATE INDEX IF NOT EXISTS idx_egress_leases_expires ON egress_leases(expires_at);

-- 2. 域名速率与熔断状态表 (记录各域名最短间隔、连续失败退避与 429 冷却)
CREATE TABLE IF NOT EXISTS egress_domain_state (
    domain TEXT PRIMARY KEY,
    last_request_at REAL NOT NULL DEFAULT 0.0,
    cooldown_until REAL NOT NULL DEFAULT 0.0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

-- 3. 审计对账与结算流水表 (对每一次申请释放进行不可篡改的最终结算审计)
CREATE TABLE IF NOT EXISTS egress_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lease_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    worker_pid INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    redirects INTEGER NOT NULL,
    bytes_metered INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,
    http_status INTEGER,
    duration_seconds REAL NOT NULL,
    recorded_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_egress_audit_domain ON egress_audit_log(domain);
CREATE INDEX IF NOT EXISTS idx_egress_audit_recorded ON egress_audit_log(recorded_at);
```

---

## 4. 测试与验证矩阵 (Verification Matrix)

在 Windows 11 / Python 3.13 环境下，运行包含真实多进程故障注入的测试套件：

```bash
python -m pytest tests/test_w105_egress_limiter.py -v
```

| 测试用例分类 | 测试用例名称 | 验证断言与防护机制 | 测试结果 |
|---|---|---|---|
| **离线阻断保护** | `test_offline_mode_fails_closed` | `offline_mode=True` 时尝试申请网络许可立即 Fail-Closed 抛出 `OfflineEgressBlockedError` | **PASS** |
| **单域并发控制** | `test_per_domain_concurrency_limit` | 单域并发为 1 时，同域第二次申请被挂起或超时；异域不受影响；释放后立即解锁 | **PASS** |
| **全局并发控制** | `test_global_concurrency_limit` | 全局并发为 2 时，跨域名第三个并发申请被阻止并抛出 `ConcurrencyTimeoutError` | **PASS** |
| **单域请求节拍** | `test_min_domain_interval_pacing` | 同域名两次请求强制等待 `min_domain_interval_seconds` (2.0s)，FakeClock 精准对齐 | **PASS** |
| **重试与指数退避** | `test_max_retries_and_backoff_calculation` | `attempt > max_retries` 抛出 `MaxRetriesExceededError`；退避时间呈确定性指数增长且上限受控 | **PASS** |
| **429 与 Retry-After** | `test_429_retry_after_cooldown` | 记录 429 响应并设置 `cooldown_until`；冷却期内所有请求均被阻断；时间推进后自愈 | **PASS** |
| **标头格式解析** | `test_parse_retry_after_formats` | 准确解析整型秒数 (`"120"`) 与 RFC-1123 HTTP-Date 时间戳 | **PASS** |
| **任务取消安全** | `test_task_cancellation_releases_lease` | `asyncio.CancelledError` 发生时，`__aexit__` 捕获并将活跃租约安全归还，无泄漏 | **PASS** |
| **崩溃自动恢复** | `test_crash_recovery_expired_leases` | 进程未 release 即死锁退出后，超过 `lease_ttl_seconds` 下一个申请者原子清除非法死锁租约 | **PASS** |
| **显式回收扫描** | `test_explicit_recover_stale_leases` | 调用 `recover_stale_leases()` 批量回收已死租约并返回准确回收计数 | **PASS** |
| **字节计量契约** | `test_response_body_meter_incremental` | `ResponseBodyMeter` 逐块累加；超过 `max_response_bytes` 立即抛出 `ResponseSizeLimitExceededError` | **PASS** |
| **流式切断阻断** | `test_response_body_meter_async_stream` | 异步迭代器切块计量，在超限瞬间中断流并阻断后续传输，杜绝大包内存 DOS | **PASS** |
| **重定向与跨域迁移** | `test_redirect_limit_and_domain_tracking` | 超过 `max_redirects` 抛出 `RedirectLimitExceededError`；跨域跳转时原子迁移租约归属域名 | **PASS** |
| **幂等结算与审计** | `test_idempotent_release_and_audit_log` | 租约支持重复 `release()` 保持幂等；审计日志精确沉淀流量、状态与耗时数据 | **PASS** |
| **多进程并发竞态** | `test_cross_process_concurrency_race_condition` | 启动 4 个独立 OS 进程 (`multiprocessing.Process`) 强并发竞争共享 SQLite，并发绝不超发 | **PASS** |

### 全量基线回归测试
```bash
python -m pytest -v
================== 452 passed, 169 skipped, 1 warning in 139.65s ==================
```
- 新增用例全部通过（15/15）。
- 既有 437 项用例 100% 通过，零回归。

---

## 5. 残余并发风险与应对策略 (Residual Concurrency Risks)

1. **SQLite 进程排他锁与高并发争抢重试**：
   - *风险分析*：当跨进程 Worker 数量极高（如 > 50 进程并发密集申请）时，SQLite 数据库在写入阶段可能产生 `OperationalError: database is locked`。
   - *应对措施*：已配置 `PRAGMA busy_timeout=10000;`，并在 `_try_acquire_transaction` 中捕获锁定异常执行带微小抖动的时间退避重试；由于本系统设计初衷为受控采集（初始并发为 1），不会遭遇超大规模进程写饥饿。
2. **极端系统时间前移或 NTP 阶跃**：
   - *风险分析*：若主机时间出现大幅度跳变，可能影响 `cooldown_until` 或 `expires_at` 的判断。
   - *应对措施*：在判定逻辑中引入时钟倒退自愈保护（若 `now < start_wait` 自动对齐重置）以及时钟前跳防御阈值 (`cooldown_until > now + max_backoff`)。
3. **僵尸租约占用窗口 (TTL Window)**：
   - *风险分析*：若 Worker 进程因被操作系统 `kill -9` 硬中断导致未能执行 `__aexit__`，其租约必须在 `lease_ttl_seconds` (默认 30s) 到期后才能被自愈回收。
   - *应对措施*：对于正常 Python 异常或任务取消，`__aexit__` 保证毫秒级立即释放；对于硬崩溃，30 秒 TTL 在爬虫领域属于安全合理的自愈回收窗口，亦可通过定时守护调用 `recover_stale_leases()` 批量回收。

---

## 6. 最终交付结论

- **`EGRESS_LIMITER_COMPONENT_READY = PASS`**：持久化限速器、并发控制器与资源熔断器模块已完整实施并通过全部 15 项专项及 452 项全量回归测试。
- **`CONTROLLED_DISCOVERY_READY = HOLD`**：上层受控采集策略及审计闭环仍待后续 PR 协同验收。
- **`LIVE_OUTREACH_READY = FORBIDDEN`**：严禁连接真实公网出口，继续保持物理离线与网络硬封锁。
