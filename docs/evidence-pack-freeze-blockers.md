# 证据包 v0 冻结阻塞项与冻结测试矩阵（v0.3）

**日期**：2026-10-21　**状态**：未冻结　**产品版本**：0.6.1（未改动）

本版完成 B3 schema 实例校验与 B8 独立交叉验证，并按上轮意见补 B4 边界、B9 正例与边界证据。以下数字都是本轮在本机实跑的结果；评审方仍需独立复跑。

## 0. 本轮独立复跑结果

| 检查 | 命令 | 结果 |
|---|---|---|
| 产品测试套件 | `tests/run_*` | **74/74**（30+11+12+11+10） |
| 冻结矩阵 | `python3 tools/test_pack_vectors.py` | **16/16** |
| 向量重建一致性 | `python3 tools/check_vector_rebuild.py` | **101/101 字节一致** |
| schema 实例校验 | `python3 tools/test_schema_validation.py` | **valid 11/11；invalid 6/6 拒绝** |
| schema 静态一致性 | `python3 tools/check_schema_consistency.py` | **26/26** |
| 独立交叉验证 | `.venv/bin/python tools/crosscheck_vectors.py` | **11/11** |

## 1. B3：真实 JSON Schema 校验（CLOSED）

- 使用 **Ajv 8.20.0**（draft 2020-12 入口）与 **ajv-formats 3.0.1**，不用自研子集。
- 11 个真实 manifest 全部通过；6 个故意破坏的 manifest 分别被对应关键字拒绝：

| 用例 | 破坏方式 | 命中关键字 |
|---|---|---|
| missing-required | 删除 `ledger` | `required` |
| wrong-type | `ledger_seq` 改为字符串 | `type` |
| bad-enum | `content_mode` 改为 `full` | `const` |
| bad-decision | 验收 `decision` 改为 `maybe` | `enum` |
| bad-time | `created_at` 改为非日期 | `format` |
| extra-field | 增加 `records` 字段 | `additionalProperties` |

**依赖说明**：Ajv 安装在 `/tmp/ajv`，版本已钉住；脚本用 `AJV_PATH` 指定入口。CI 需执行 `npm install ajv@8.20.0 ajv-formats@3.0.1`，离线环境需预置。

## 2. B8：独立实现交叉验证（CLOSED）

- 独立实现**不导入** `packjcs.py` 或 `agentbridge.signing`：自带规范化器，签名用 `cryptography` 的 Ed25519（50.0.2）。
- 对 11 个向量重算文件哈希、账本链摘要、manifest/信封/验收/状态/回执签名与账本绑定，结果与预期一致：
  - `tampered-sig`：信封签名独立判为无效，绑定不一致；
  - `tampered-binding`：签名独立判为有效，仅绑定不一致；
  - `forged-selfconsistent`：全部数学验证通过——但外部信任不变，身份仍为 unknown（由验证器判定）。
- 该交叉验证覆盖密码学与规范化，不覆盖信任判断；信任由 forged 负例覆盖。
- 剩余共同点：fixtures 由 generator 用 `agentbridge.signing` 生成，但交叉验证用的是独立实现，因此生成器与签名库的共同缺陷会被发现；generator 自身逻辑仍共享，需要评审复核 fixtures。

## 3. B4：撤销与可信时间（CLOSED，含边界）

**比较规则（写入协议前先固定）**：

| 情形 | 判断 |
|---|---|
| 正常退役 | `signed_at <= effective_at` 视为有效（等号允许） |
| 疑似泄露，起点已知 | 受信边界要求 `anchor.received_at < suspected_leak_at`（严格小于） |
| 疑似泄露，起点未知 | 一律 unknown（`E-KEY-COMPROMISE-START-UNKNOWN`），**即使锚点早于发现时间** |
| 已撤销 | `effective_at <= signed_at` → fail（`E-KEY-REVOKED`） |

**新增边界用例**：

| 用例 | 构造 | 结果 | 退出 |
|---|---|---|---|
| compromised-start-unknown | 疑似泄露但 `suspected_leak_at` 缺失，锚点早于发现 | identity unknown | 2 |
| compromise-boundary-equal | 锚点时间 **等于** 泄露起点（严格小于不成立） | identity unknown | 2 |
| retirement-boundary-equal | 退役时间 **等于** 签署时间（等号允许） | identity pass | 2 |

“发现泄露的时间”不等于“最早可能失效时间”；起点未知时，早于发现时间的签名不能自动判为可信。该规则已写进验证器与用例。

## 4. B9：检查点（CLOSED）

| 用例 | 结论 |
|---|---|
| normal（正确检查点） | `anchoring.checkpoint = pass`（正例已包含在 normal 断言中） |
| checkpoint-wrong-bridge | 同序号、错误桥身份 → `E-CHECKPOINT-BRIDGE-MISMATCH`，退出 1 |
| checkpoint-out-of-range | 检查点超出所提供链范围 → `E-CHECKPOINT-OUT-OF-RANGE`，退出 1 |
| minimum-too-high | `minimum_checkpoint_seq=6` 独立生效 → `E-ANCHOR-BELOW-MINIMUM`，退出 1 |

`latest` 在离线场景恒为 unknown，只作报告字段，不影响轴状态。

## 5. 包内信任文件检查的定位

`E-TRUST-INSIDE-PACK` 只是**加载约束，不是信任保证**：攻击者可以把 `trust.json` 复制到包外，路径检查就会通过。真正的测试是 `forged-selfconsistent`：攻击者整套自洽重签、外部信任不变，验证器必须判 identity unknown。

协议要求（写入 v0.1 正文）：接收方必须通过独立渠道确认信任输入的**来源与内容**（指纹核对、预置配置或合同约定）；包外路径只防止“包自己给自己作证”。

## 6. 冻结测试矩阵（16 用例）

| 用例 | 六轴要点 | 退出 |
|---|---|---|
| normal | 五轴 pass，content not_executed | 2 |
| tampered-sig | integrity fail；identity unknown | 1 |
| tampered-binding | integrity fail；identity pass | 1 |
| missing-evidence | acceptance fail；anchoring unknown | 1 |
| retired-key | identity pass | 2 |
| compromised-no-anchor | identity unknown；anchoring unknown | 2 |
| compromised-with-anchor | identity pass | 2 |
| compromised-start-unknown | identity unknown | 2 |
| compromise-boundary-equal | identity unknown | 2 |
| retirement-boundary-equal | identity pass | 2 |
| forged-selfconsistent | integrity pass；identity unknown | 2 |
| checkpoint-mismatch | anchoring fail | 1 |
| checkpoint-wrong-bridge | anchoring fail | 1 |
| checkpoint-out-of-range | anchoring fail | 1 |
| minimum-too-high | anchoring fail | 1 |
| trust-inside-pack | 协议错误 | 3 |

## 7. 阻塞状态

| # | 阻塞项 | 状态 | 说明 |
|---|---|---|---|
| B1 | 裁决未写回 v0.1 正文 | **OPEN** | 需小改第 2/3/4/5/6 节 |
| B2 | 新旧签名协议缺版本标识 | **OPEN** | 需加字段或明确限定格式/发行版本 |
| B3 | schema 实例校验 | **CLOSED** | Ajv 11/11 + 6/6；依赖版本已钉住 |
| B4 | 撤销/可信时间 | **CLOSED** | 三个边界用例；规则已固定 |
| B5 | 外部信任输入 | **PARTIAL** | 协议要求已明确；分发方式作为试点准入条件 |
| B6 | 内容边界 | **OPEN** | 归入 B1 文字同步 |
| B7 | `bridge_id` 位置 | **OPEN** | 只在回执文件；需 schema/文档统一 |
| B8 | 独立交叉验证 | **CLOSED** | 独立规范化 + cryptography，11/11 |
| B9 | 检查点 | **CLOSED** | 正例、错桥、越界、最低序号四类 |

## 8. 冻结门槛

- [ ] B1 裁决写回 v0.1 正文（含 B6 内容边界）。
- [ ] B2 固定旧格式支持范围（精确到格式版本或已核对发行版）。
- [x] B3 schema 实例校验。
- [x] B4 撤销/可信时间边界。
- [ ] B5 协议要求与试点准入分开记录（协议要求已定，渠道待定）。
- [ ] B7 统一 `bridge_id` 位置。
- [x] B8 独立实现交叉验证。
- [x] B9 检查点四类证据。
- [x] 矩阵 16/16、重建 101/101、Ajv 11+6、交叉 11/11、产品 74/74。

## 9. 复跑命令

```text
python3 tools/test_pack_vectors.py
python3 tools/check_vector_rebuild.py
python3 tools/test_schema_validation.py
python3 tools/check_schema_consistency.py
.venv/bin/python tools/crosscheck_vectors.py
```

## 10. D4 spike：真实 0.6.1 桥导出（2026-10-21）

- 用真实桥完成：genesis → 注册 worker/client → send → deliver → 新增 `accept` 条目；
  导出 `originals/`（账本、两封信封、验收记录、状态、回执）与 manifest，外部信任文件放包外。
- 运行现有参考验证器：**integrity / identity / acceptance / coverage / anchoring 全部 pass**，
  `content` 为 `not_executed`，退出 2（符合 v0 的 hashes_only 约定）。
- 该 spike 验证了四个实现决定：
  1. 旧对象按旧规则验证（账本对 digest 签名、信封无域、回执无域），新对象用新域；
  2. `accept` 条目 + 原始验收记录文件的存储形态可行；
  3. `bridge_id` 只放在回执文件、由 manifest 引用即可；
  4. 真实账本/信封/回执能无损映射到 v0 manifest。
- 产物：`tools/spike_export_real_pack.py`（不作为产品代码）；包在 `/tmp/ab-spike`，未入库。
- 结论：D4 映射可落地，具备进入 D1–D4 产品实现的条件。
