# W1-03_TEST_RESULTS.md — FetchInbox DevTools 信号与资格评估物理验收测试报告

> **测试执行环境**：Windows 11 Pro 64-bit / Python 3.13.13 / pytest-8.4.2 / aiosqlite / FastAPI TestClient
> **分支与 Worktree**：`codex/w1-03-fetchinbox-devtools-signals`（物理路径 `C:\Users\frank\Documents\Playground\harvey_w1_03`）
> **测试原则**：100% 离线运行，零真实公网外发、零第三方网站扫描，严格可重复验证。

---

## 1. 核心门禁验收概览 (Gate Summary)

| 门禁项 | 覆盖测试用例 | 预期行为 | 实测结果 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **1. 原生 23 项信号保全** | `tests/test_devtools_signals.py::test_harvey_core_23_signals_fully_retained` | 原生 23 项代码一个不少，定义与置信度完全兼容 | 23 项完全保留 (31 总数) | **PASS** |
| **2. 8 项新增信号合法注册** | `tests/test_devtools_signals.py::test_devtools_and_qualification_signals_registered` | 6 项事实信号 + 2 项派生资格状态正确写入 signal_codes | 全部合法注册 | **PASS** |
| **3. 未注册信号触发器阻断** | `tests/test_devtools_signals.py::test_unregistered_signal_rejected_by_trigger` | 插入任意未注册杂乱代码必须被 SQLite 触发器 ABORT | 成功触发 `unknown signal_code` 异常 | **PASS** |
| **4. 正样本具体技术证据提取** | `tests/test_devtools_collector.py::test_positive_saas_otp_and_playwright`<br>`test_positive_ai_browser_agent` | 精准识别 OTP、Playwright/Cypress、Agent SDK 并判定为 ACTIVE_BUYER | 准确定位事实片段并判定为 ACTIVE_BUYER | **PASS** |
| **5. 负样本严密排除防误判** | `tests/test_devtools_collector.py::test_competitor_disqualified`<br>`test_consumer_retail_disqualified` | 临时邮箱竞品与消费级零售网站被判定为 DISQUALIFIED | 判定为 DIRECT_COMPETITOR / CONSUMER_ONLY | **PASS** |
| **6. 空文本防刷与低 ICP 约束** | `tests/test_devtools_collector.py::test_empty_text_cannot_become_high_icp` | 空文本/无内容页面绝对不能成为高价值线索 | 判定为 NON_ICP / DISQUALIFIED | **PASS** |
| **7. 历史/过期招聘意图降级** | `tests/test_devtools_collector.py::test_stale_job_not_treated_as_active_intent` | 历史归档或已关闭的招聘不作为当下购买证据 | 保持 POTENTIAL_FIT，严禁标记 ACTIVE_BUYER | **PASS** |
| **8. 单网页重复出现防膨胀** | `tests/test_devtools_collector.py::test_single_page_duplication_counts_as_one_source` | 同一页面多次提及关键词仅算 1 项独立来源 | 证据充分性判定为 PARTIAL，非 SUFFICIENT | **PASS** |
| **9. DNS SPF 仅作技术线索** | `tests/test_devtools_collector.py::test_dns_spf_alone_is_technical_lead_only` | 仅有 Postmark/SendGrid SPF 不产生购买意向结论 | 判定为 INSUFFICIENT，无买家结论 | **PASS** |
| **10. 技术信号 Cohort 集合筛选** | `tests/test_devtools_collector.py::test_cohort_filtering_by_devtools_signals` | SQL 集合交集根据技术信号和排除规则正确筛选公司 | 正确过滤 Agent 团队并排除竞品 | **PASS** |
| **11. 时序与确定性冲突处理** | `tests/test_devtools_collector.py::test_observation_timestamp_and_deterministic_conflict` | 多次观察根据置信度与时间戳产生确定性裁决，无随机性 | 高置信/最新记录确定胜出 | **PASS** |
| **12. 零真实网络调用守卫** | `tests/test_devtools_collector.py::test_zero_network_access_guarantee` | 注入网络阻断 MonkeyPatch，确保评估全流程零 HTTP 外部请求 | 100% 纯内存/本地运行通过 | **PASS** |

---

## 2. 独立测试运行详情 (Execution Logs)

```bash
$ python -m pytest tests/test_devtools_signals.py tests/test_devtools_collector.py -v
============================= test session starts =============================
platform win32 -- Python 3.13.13, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\frank\Documents\Playground\harvey_w1_03
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-0.26.0
asyncio: mode=Mode.STRICT
collected 14 items

tests/test_devtools_signals.py::test_harvey_core_23_signals_fully_retained PASSED [  7%]
tests/test_devtools_signals.py::test_devtools_and_qualification_signals_registered PASSED [ 14%]
tests/test_devtools_signals.py::test_unregistered_signal_rejected_by_trigger PASSED [ 21%]
tests/test_devtools_collector.py::test_positive_saas_otp_and_playwright PASSED [ 28%]
tests/test_devtools_collector.py::test_positive_ai_browser_agent PASSED [ 35%]
tests/test_devtools_collector.py::test_competitor_disqualified PASSED [ 42%]
tests/test_devtools_collector.py::test_consumer_retail_disqualified PASSED [ 50%]
tests/test_devtools_collector.py::test_empty_text_cannot_become_high_icp PASSED [ 57%]
tests/test_devtools_collector.py::test_stale_job_not_treated_as_active_intent PASSED [ 64%]
tests/test_devtools_collector.py::test_single_page_duplication_counts_as_one_source PASSED [ 71%]
tests/test_devtools_collector.py::test_dns_spf_alone_is_technical_lead_only PASSED [ 78%]
tests/test_devtools_collector.py::test_cohort_filtering_by_devtools_signals PASSED [ 85%]
tests/test_devtools_collector.py::test_observation_timestamp_and_deterministic_conflict PASSED [ 92%]
tests/test_devtools_collector.py::test_zero_network_access_guarantee PASSED [100%]

============================= 14 passed in 2.27s ==============================
```

---

## 3. 回归测试套件验证 (Regression Suite Verification)

运行涉及信号目录与流水线的所有既有测试（共 128 项）：
- `tests/test_dashboard_signals.py`
- `tests/test_signals_export.py`
- `tests/test_state.py`
- `tests/test_pipeline.py`
- `tests/test_discover.py`
- `tests/test_collectors_profile.py`

**结果**：`128 passed, 0 failed, 1 warning in 49.41s`。
全量原有测试均完美兼容通过，未引起任何功能倒退。
