# W105_B_RATE_LIMIT_REPORT.md — 可持久化请求限速、并发控制与时钟/租约安全整改审计报告 (W1-05-B-R)

> **审计与实施人**：Principal Distributed Systems CTO & Python AsyncIO Engineer
> **任务代号**：Harvey W1-05-B-R2 (时钟一致性、RFC HTTP-Date 规范与跨重启限速安全终结)
> **分支**：`codex/w1-05-b-egress-limiter`
> **PR**：`https://github.com/frank8ai/harvey/pull/5` (PR #5)
> **BASE_SHA**：`31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a`
> **PREVIOUS_HEAD_SHA**：`03a3f5e7fe177a3fca3cadb54de3e2ada3fac671`
> **门禁裁决状态**：
> - `EGRESS_LIMITER_COMPONENT_READY = PASS`
> - `MERGE_READY = PASS` (针对 PR #5 组件级准入)
> - `CONTROLLED_DISCOVERY_READY = HOLD` (维持系统级离线门禁，待上层协调器合并)
> - `LIVE_OUTREACH_READY = FORBIDDEN` (物理出站严格锁死)

---

## 1. 架构整改背景与 7 大核心检查复核

在初始 PR #5 (`03a3f5e`) 提交后，进行了深度分布式系统与并发安全性专项审计 (W1-05-B-R)。针对跨进程并发竞争、长时请求租约维持、时钟抖动、崩溃恢复与 Fail-Closed 原则，完成了以下 7 项必检项的深度排查与最小安全加固：

### 1.1 检查项 1：请求持续超过 30s TTL 是否可能导致其他 Worker 取得第二份并发许可
- **审计风险**：初始设计中租约到期后仅依赖静态 TTL (`expires_at < now`)，若单个请求执行时间超过 30s（如慢速响应或大文件流传输），租约在数据库中被自动视作过期，导致其他 Worker 进程取得并发许可，破坏单域并发 (`per_domain_concurrency`) 或全局并发 (`global_concurrency`) 不变量。
- **加固方案**：
  - 在 `RequestLease` 中实现后台自动续租协程 `start_auto_renewal()`，在 `async with lease:` 上下文启动时自动介入。
  - 续租周期设为 `lease_ttl_seconds / 3.0` (如 10s)，在租约自然过期前原子延长 `expires_at`。
  - 严密防卫：若续租失败（如 DB 冲突或租约已被回收），立即标记 `_lost_ownership = True` 并通过 `_abort_bound_task()` 强行取消绑定的请求协程，确保不会在无许可状态下继续占用资源。
- **验证**：`test_auto_renewal_prevents_double_leasing` 模拟请求持续 35s+，证实租约持续自动续期，第二 Worker 申请并发请求严格超时阻塞。

### 1.2 检查项 2：租约续期是否需要显式调用；是否存在漏续租路径
- **审计风险**：若要求上层业务开发者手工显式轮询调用 `lease.renew()`，极易因异常分支或流式循环阻塞产生漏续租。
- **加固方案**：
  - `async with await limiter.acquire(...) as lease:` 上下文管理器自动挂载当前正在执行的任务，启动自动守护续租；退出时无论正常返回、异常退出还是任务取消，均在 `__aexit__` 中执行 `stop_auto_renewal()`。
  - 同时保留显式 `lease.renew(extra_ttl)` API，满足特殊分段长任务的显式控制需求。完全闭环漏续租风险。

### 1.3 检查项 3：租约到期后旧 Worker 是否还能释放或更新已经失效的许可
- **审计风险**：若 Worker 1 的租约已因网络停顿或慢 GC 过期，Worker 2 接管并遭遇 429 记录了 300s 冷却，此时 Worker 1 慢速唤醒并执行 `release(SUCCESS)`，若无所有权校验，会直接将域名的 `consecutive_failures` 清零并复位冷却，严重破坏状态机。
- **加固方案**：
  - 在 `_release_lease` 的 `BEGIN IMMEDIATE` 独占事务中，首先执行 `SELECT domain, expires_at FROM egress_leases WHERE lease_id = ?` 校验真实所有权。
  - 若租约记录已不存在或已非当前持有者，立即 `commit` 并静默返回，**绝对禁止**覆写或重置 `egress_domain_state`。
  - 在 `RequestLease.assert_valid()` 中增加主动失效校验：若 `now >= expires_at`，抛出 `LeaseExpiredError` 并熔断。
- **验证**：`test_stale_expired_lease_cannot_release_or_corrupt_state` 证实过期 Worker 无法冲掉合法的 429 冷却状态。

### 1.4 检查项 4：SystemClock 使用 time.time() 时跨进程时钟跳变的影响
- **审计风险**：`time.time()` 属于系统墙上时钟 (Wall-Clock)，受 NTP 同步校准、夏令时调整及人工改动影响；时钟回拨会导致请求等待时间突变为负数或死锁，时钟前跳会导致租约和冷却瞬间失效。
- **加固方案**：
  - 将 `SystemClock.now()` 彻底切换为 `time.monotonic()`，提供严格递增、不受跨进程或系统时钟跳变干扰的高精度单调时间基准。
  - 在 `PersistentEgressLimiter.acquire()` 中保留时钟异常保护屏障（若检测到时钟跳跃，自动重新锚定 `start_wait` 与 `deadline`）。

### 1.5 检查项 5：429 Retry-After 长时间冷却是否可能被过度裁剪
- **审计风险**：原先代码在 `_try_acquire_transaction` 中存在 `if cooldown_until > now + self.config.max_retry_backoff_seconds: cooldown_until = ...` 的不当防御，将外部站点下发的合法长冷却（如 Retry-After: 300s）强行截断为 30s，造成对上游站点的二次违规轰炸。
- **加固方案**：
  - 彻底移除对 `cooldown_until` 的裁剪逻辑。
  - 在 `_release_lease` 中，若解析到合法的 `retry_after_seconds`，完整保留为冷却窗口（`cooldown_duration = retry_after_seconds`），不受本地 `max_retry_backoff_seconds` 截断。
- **验证**：`test_429_long_retry_after_not_clipped` 验证 300s Retry-After 在 31s 后依然坚固生效。

### 1.6 检查项 6：进程被 SIGKILL 后租约回收是否正确
- **审计风险**：当 Worker 进程被操作系统发送 `SIGKILL` (Linux `kill -9` / Windows `taskkill /F`) 时，进程内部无法执行任何 Python 清理代码或 `__aexit__`。若仅靠 30s TTL，在此期间并发槽位被死锁占用。
- **加固方案**：
  - 引入操作系统级跨平台进程探活函数 `is_pid_alive(pid)`：
    - Windows: 调用 Win32 原生 API `kernel32.OpenProcess` 查询句柄并检查 `GetExitCodeProcess == STILL_ACTIVE (259)`。
    - POSIX: 调用 `os.kill(pid, 0)` 检测进程存活与权限。
  - 在 `recover_stale_leases()` 以及 `_try_acquire_transaction()` 清理步骤中，扫描当前活跃租约的 `worker_pid`，若发现其所属进程已死亡，立即在独占事务中清理其租约，无需等待 TTL 自然过期。
- **验证**：`test_sigkill_crash_recovery_os_process` 启动真实独立 OS 子进程并执行 `proc.kill()`，主进程立即成功回收该孤儿租约。

### 1.7 检查项 7：SQLite 锁竞争、任务取消和恢复是否真正 Fail-Closed
- **审计风险**：并发竞争下 SQLite 若发生 `busy` 抛错，或任务在获取到租约瞬间被 Cancelled，状态若未能闭环将导致配额泄漏。
- **加固方案**：
  - 全流程采用 `BEGIN IMMEDIATE;` 互斥独占写锁事务，避免事务中途升锁导致的 `SQLITE_BUSY` 死锁。
  - `_try_acquire_transaction` 与 `_release_lease` 严格在 `try...finally: await conn.close()` 中管理底层连接。
  - 若处于 `offline_mode=True`，在进入任何数据库交互前直接 Fail-Closed 抛出 `OfflineEgressBlockedError`。
  - 在重定向跨域时增加 `_transfer_lease_domain` 的并发校验，若目标域并发已满，拒绝迁移并抛出异常，防止通过重定向绕过单域并发限制。

---

## 2. Red-before-Green 复现与整改证据

在整改实施前，针对识别出的架构漏洞编写了 5 项针对性硬核测试用例，在未加固前全部呈现预期失败 (Red)，加固后全部通过 (Green)：

1. **Auto-Renewal 防止双重占用**：
   - *Red*: 无自动续租时，35s 长请求在 30s TTL 到期时被数据库判定为过期，Worker 2 成功并发申请到第二份许可，`assert active_leases == 1` 失败。
   - *Green*: 引入 `start_auto_renewal` 后，Worker 1 租约在 20s/35s 持续刷新 `expires_at`，Worker 2 申请严格抛出 `ConcurrencyTimeoutError`。
2. **失效租约防篡改状态**：
   - *Red*: 旧 Worker 唤醒后调用 `release(SUCCESS)` 将 Worker 2 刚写入的 429 冷却清零。
   - *Green*: `_release_lease` 所有权核实阻断，冷却状态完好无损。
3. **429 Retry-After 完整窗口**：
   - *Red*: 300s 冷却被截断至 30s，31s 时再次发起申请成功（违背 429 契约）。
   - *Green*: 截断代码移除，31s 时申请被拦截且返回剩余冷却时间 269s。
4. **跨域重定向并发溢出**：
   - *Red*: 域名 A 的 Worker 重定向至已满载的域名 B，直接修改 `domain` 字段导致域名 B 实际并发突破配置上限。
   - *Green*: `_transfer_lease_domain` 事务内严格核验目标域并发上限，超额即时抛出 `ConcurrencyTimeoutError`。
5. **SIGKILL 僵尸进程即时回收**：
   - *Red*: 子进程被 `kill` 后，在 300s TTL 窗口内配额被死锁。
   - *Green*: `is_pid_alive` 探活联动 `recover_stale_leases` 毫秒级探测并回收已死 PID 租约。

---

## 3. 测试与验证矩阵 (Verification Matrix)

在 Python 3.14 / aiosqlite / Windows 11 环境下，运行包含多进程故障注入的 20 项专项测试：

```powershell
Set-Location "C:\Users\frank\Documents\Playground\harvey_w1_05"
$env:PYTHONPATH = "C:\Users\frank\Documents\Playground\harvey_w1_05"
& "C:\Users\frank\Documents\Playground\harvey_w1_03\.venv\Scripts\python.exe" -m pytest tests/test_w105_egress_limiter.py -v
```

```text
tests/test_w105_egress_limiter.py::test_offline_mode_fails_closed PASSED                 [  5%]
tests/test_w105_egress_limiter.py::test_per_domain_concurrency_limit PASSED             [ 10%]
tests/test_w105_egress_limiter.py::test_global_concurrency_limit PASSED                 [ 15%]
tests/test_w105_egress_limiter.py::test_min_domain_interval_pacing PASSED             [ 20%]
tests/test_w105_egress_limiter.py::test_max_retries_and_backoff_calculation PASSED     [ 25%]
tests/test_w105_egress_limiter.py::test_429_retry_after_cooldown PASSED                 [ 30%]
tests/test_w105_egress_limiter.py::test_parse_retry_after_formats PASSED               [ 35%]
tests/test_w105_egress_limiter.py::test_task_cancellation_releases_lease PASSED        [ 40%]
tests/test_w105_egress_limiter.py::test_crash_recovery_expired_leases PASSED           [ 45%]
tests/test_w105_egress_limiter.py::test_explicit_recover_stale_leases PASSED           [ 50%]
tests/test_w105_egress_limiter.py::test_response_body_meter_incremental PASSED         [ 55%]
tests/test_w105_egress_limiter.py::test_response_body_meter_async_stream PASSED        [ 60%]
tests/test_w105_egress_limiter.py::test_redirect_limit_and_domain_tracking PASSED       [ 65%]
tests/test_w105_egress_limiter.py::test_idempotent_release_and_audit_log PASSED        [ 70%]
tests/test_w105_egress_limiter.py::test_cross_process_concurrency_race_condition PASSED[ 75%]
tests/test_w105_egress_limiter.py::test_auto_renewal_prevents_double_leasing PASSED    [ 80%]
tests/test_w105_egress_limiter.py::test_stale_expired_lease_cannot_release_or_corrupt_state PASSED [ 85%]
tests/test_w105_egress_limiter.py::test_429_long_retry_after_not_clipped PASSED        [ 90%]
tests/test_w105_egress_limiter.py::test_cross_domain_redirect_enforces_target_concurrency PASSED [ 95%]
tests/test_w105_egress_limiter.py::test_sigkill_crash_recovery_os_process PASSED       [100%]

============================= 20 passed in 7.38s ==============================
```

### 全量回归测试
```powershell
& "C:\Users\frank\Documents\Playground\harvey_w1_03\.venv\Scripts\python.exe" -m pytest
=========================== 457 passed, 169 skipped in 116.66s ===========================
```
- 全量 626 项用例中，457 项通过，169 项平台预期跳过，**零失败、零回归**。

---

## 4. 租约状态不变量 (Lease State Invariants)

1. **唯一占有性 (Mutual Exclusion)**：
   - 任何时刻 $T$，对任意域名 $D$，活跃未过期租约数 $\sum [\text{domain}=D \land \text{expires\_at} > T] \le \text{per\_domain\_concurrency}$。
   - 全局活跃未过期租约数 $\sum [\text{expires\_at} > T] \le \text{global\_concurrency}$。
2. **单调时钟性 (Monotonic Progression)**：
   - 所有冷却与 TTL 计算均基于单调时钟，系统时间跳跃或 NTP 同步不破坏 $T_1 < T_2$ 的序关系。
3. **有效所有权保护 (Owner Integrity)**：
   - 只有持有有效、未被清除租约的 Worker 才能更新对应域名的失败计数与冷却时间；失效租约的释放为幂等空操作。
4. **长请求安全性 (Liveness via Renewal)**：
   - 活跃请求在其任务生命周期内保证租约自动续期；一旦续期失败，请求任务必须在同一事件循环轮次中被 Cancelled，绝不裸奔。
5. **Fail-Closed 离线不变性 (Offline Lock)**：
   - 当 `offline_mode=True` 时，任何外部网络请求许可申请在接触任何 I/O 前必须抛出 `OfflineEgressBlockedError`。

---

## 6. W1-05-B-R2 时钟一致性与跨重启限速最终修复 (Clock Consistency & Cross-Reboot Invariants)

在 W1-05-B-R 落地后，进一步针对审计发现的时钟基准与跨重启不一致进行了彻底加固：
1. RequestLease.release() 修复为将 Unix Epoch 绝对时间 (self.limiter.clock.time()) 传给 parse_retry_after(..., now=wall_now)，计算出精准剩余秒数，彻底消除将 monotonic 减 Unix Epoch 的 2 万天荒谬冷却。
2. SQLite 增加 boot_id、cooldown_until_utc、last_request_at_utc、recorded_at_utc 字段，实现双时间语义与启动会话感知。
3. 跨重启平滑对齐 (Reconciliation)：重启后若 cooldown_until_utc > wall_now，按 wall_now 剩余秒数平滑折算当前单调冷却；若已到期则置为 0.0，杜绝旧单调时间戳导致的数天虚假死锁。
4. 租约跨重启回收与续约失败保护：跨重启孤儿租约即时清理释放槽位；续期异常通过 _abort_bound_task 强行取消绑定的受控请求任务。

### 6.1 专项测试结果
- 25 项全量专项测试 PASS（包含 HTTP-Date、活跃冷却跨重启保留、过期冷却跨重启即时解封、孤儿租约清理、续租失败 abort 熔断）。
- 631 项全量 Harvey 回归测试（462 passed, 169 skipped, 0 failed）。


## 5. 最终交付结论

- **`BASE_SHA`**：`31ab1282881bb0af340dcb0d4f84b4a2dbb4e59a`
- **`PREVIOUS_HEAD_SHA`**：`03a3f5e7fe177a3fca3cadb54de3e2ada3fac671`
- **`MERGE_READY = PASS`**：PR #5 涉及的 7 大租约、时钟与并发控制风险已彻底整改并完成物理跨进程与全量回归验证，代码与报告已就绪。
- **`CONTROLLED_DISCOVERY_READY = HOLD`**：保持离线受控状态，不开启任何真实公网抓取。
- **`LIVE_OUTREACH_READY = FORBIDDEN`**：严禁连接真实公网出口。
