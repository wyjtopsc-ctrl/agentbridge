# 证据包 v0.1 协议修订与验收用例

**状态**：草案，**不冻结**　**基线**：产品 0.6.1（仅作差距对照）　**依据**：v0 文档评审六项 + 收敛四项

本版只做**协议收敛**，不扩企业功能。冻结门槛见第 9 节；未完成前不写实现代码。

## 0. 本版改了什么

| 评审问题 | 本版处理 |
|---|---|
| AC-02b 自动触发 unknown | 拆成「验收声明核验」与「是否符合预期版本」两件事；没有外部预期版本时显示“未评估”，不判断真实意图 |
| AC-02a 混淆签名无效与绑定错误 | 拆出独立签名错误码；四种操作分别判断 |
| 缺少“原始记录→账本→锚点”的证明结构 | 第 2 节：原始字节不重签、账本切片即证明、锚点覆盖判定、验证算法 |
| 序列化/签名范围不可实现 | 第 3 节：规范化、签名域、编码、覆盖范围、单一布局、内容模式 |
| 撤销信息只有 as_of | 第 4 节：发布者签名、有效期、最大陈旧期、冲突规则 |
| 输出自相矛盾 | 第 5 节：统一状态枚举与退出码；AC-03c 拆「内部一致性」与「历史完整性」 |

## 1. 修订清单

| ID | 来源 | 修订 |
|---|---|---|
| RC-01 | 评审 1 | 验收声明核验与预期版本检查分离；意图不判断 |
| RC-02 | 评审 2 | 增加 `E-SIG-INVALID`、`E-SIG-UNTRUSTED-KEY`；区分重签与绑定错误 |
| RC-03 | 评审 3 | 定义“原始签名记录 → 账本条目 → 锚点回执”的证明关系；原始字节不重签 |
| RC-04 | 评审 4 | 固定序列化、签名范围、编码、单一布局、内容模式 |
| RC-05 | 评审 5 | 撤销状态文件由发布者签名，带有效期与最大陈旧期 |
| RC-06 | 评审 6 | 状态枚举去掉旧值，统一为 pass/fail/unknown/not_applicable/not_evaluated/not_executed |
| RC-07 | 收敛 1 | 第 2 节完整证明关系与验证步骤 |
| RC-08 | 收敛 2 | 重写 AC-02、AC-03 |
| RC-09 | 收敛 3 | 第 3、5 节固定序列化与退出码 |
| RC-10 | 收敛 4 | 第 8 节定义三组固定样例；冻结前必须由样例检查器给出同一结论 |
| RC-11 | 一致性 | 包签名只覆盖 manifest；原始记录签名在原始字节上验证，禁止重签 |
| RC-12 | 一致性 | 删除“缺少信任输入即通过/失败”的模糊表述，统一为身份轴 unknown + 原因码 |

## 2. 证明关系：原始签名记录 → 账本 → 锚点

### 2.1 原则：原始字节不重签

- 导出**不重新签名**任何原始记录；原始文件逐字节放入 `originals/`。
- 包签名只覆盖 `manifest.json`；manifest 用 `sha256` 引用每个原始文件。
- 若导出过程改变了原始字节（改格式、裁剪、加密），验证器必须报 `E-ORIGINAL-SIG-UNVERIFIABLE`，**不得**声称原始签名已核验。

### 2.2 包布局（v0.1 唯一布局：split）

```
pack/
├── manifest.json
└── originals/
    ├── ledger.jsonl                  # 从 genesis 到 tip 的原始账本行
    ├── envelopes/<envelope_id>.json  # 原始信封字节
    ├── acceptances/<acceptance_id>.json  # 接收方签名的验收记录原始字节
    ├── receipts/<log_index>.json     # 原始锚点回执字节
    └── status.json                   # 撤销状态文件（发布者签名）
```

禁止内联记录；`manifest` 中不得出现 `records` 字段。`content_mode` 在 v0.1 仅为 `hashes_only`；其他值直接拒绝（`E-CONTENT-MODE-UNSUPPORTED`）。

### 2.3 三个绑定

1. **原始记录 → 账本条目**：manifest 中每条 delivery/acceptance 记录给出 `ledger_seq`；验证器在账本切片中找到该条目，核对其 `id` 与记录一致，且记录文件哈希等于条目中的 `envelope_sha256`（交付）或验收记录的 `record_sha256`。
2. **账本条目 → 信封/验收文件**：信封与验收文件是原始签名对象；验证器在原始字节上验证 actor 签名，并用 manifest 中的 `sha256` 确认字节未被替换。
3. **账本 → 锚点回执**：回执签名覆盖 `(bridge_id, seq, digest, log_index, received_at, prev)`。验证器要求回执的 `seq`/`digest` 等于账本切片中该 `seq` 条目的 `digest`；回执的 `seq` 即“锚点覆盖到的位置”。

### 2.4 验证算法（顺序固定）

V1 序列化检查（重复键、NaN/Inf、类型、NFC 字符串）；失败 → `E-SERIALIZATION`，退出 3。
V2 验证包签名：`canon(manifest 去掉 signatures)` 对 `signatures.exporter` 验签；失败 → `E-PACK-SIG`。
V3 验证每个 `signed_files` 的 `sha256` 与文件实际字节；失败 → `E-PACK-FILE-MISMATCH`。
V4 解析 `originals/ledger.jsonl`：要求从 `seq=0` 的 genesis 开始、`seq` 连续、`prev` 链接、`digest` 重算一致；失败 → `E-CHAIN-GAP`。核对 tip 与 manifest `tip_seq/tip_digest`；失败 → `E-TIP-MISMATCH`。
V5 验证账本条目签名：使用 manifest 中 `identity.actors` 的公钥，逐条验证 `digest` 签名；未注册 actor → `E-SIG-UNTRUSTED-KEY`。
V6 验证每个 delivery/acceptance：按 2.3 的绑定逐项核对；交付签名无效 → `E-SIG-INVALID`；验收哈希集合不一致 → `E-ACC-BINDING`；引用不存在的交付 → `E-ACC-DANGLING`。
V7 验证锚点回执：服务公钥必须来自**外部信任输入**；签名无效 → `E-ANCHOR-UNTRUSTED`；覆盖位置低于记录 seq → 该记录的锚定状态 `unknown`（`E-ANCHOR-MISSING`）。
V8 验证撤销状态文件：发布者公钥来自外部信任输入；签名、有效期、最大陈旧期；状态冲突 → `unknown`（`E-KEY-STATUS-CONFLICT`）。
V9 汇总五轴 + 内容轴；按第 5 节输出机器摘要、人读报告与退出码。

### 2.5 v0.1 的边界

- **不使用 Merkle 成员证明**：用全链切片直接证明，规模上限由试点约定（建议 ≤ 10 万条）。
- 锚点只能证明“到 `covers_seq` 为止的链”。之后的记录锚定状态为 `unknown`，不得暗示已覆盖。
- 未锚定尾部被整体回滚时，**无法发现**（见 AC-03c）；这不是缺陷，是保证边界。

## 3. 序列化与签名范围

- **编码**：所有文件 UTF-8、无 BOM；JSON 采用 RFC 8785 的确定性序列化子集：无重复键、无 NaN/Infinity、数字不超出 IEEE-754 安全范围、字符串 Unicode NFC、对象键按码点排序、分隔符无空格、`ensure_ascii=false`。
- **数组**：保留声明顺序；“哈希集合”类字段（`artifacts_sha256`）按 sha256 升序排列，且禁止重复。
- **签名域**：`"agentbridge-evidence/0.1\n" + record_type + "\n" + canonical_bytes`，`record_type` ∈ `manifest | delivery-record | acceptance-record | status | receipt`。
- **签名编码**：Ed25519；公钥 32 字节、签名 64 字节，均为小写 hex。
- **包签名范围**：`signatures.exporter` 覆盖 canonical manifest **整体移除 `signatures` 键之后**的内容；`signed_files` 列出除 manifest 外的所有参与文件（路径 + sha256）。
- **原始签名**：只在 `originals/` 的原始字节上验证；manifest 中的记录只是索引，不参与原始签名验证。
- **单一布局**：禁止内联与拆分混用；出现无法识别的字段 → `E-SERIALIZATION`。

## 4. 信任来源与撤销状态

### 4.1 外部信任输入（验证器提供，不在包内）

| 字段 | 含义 |
|---|---|
| `expected_actors[]` | `{actor, fingerprint}`：接收方预确认或独立渠道确认的签署方 |
| `anchor_service_pubs[]` | 接收方独立确认的锚点服务公钥 |
| `status_publisher_pub` | 撤销状态发布者公钥 |
| `max_status_age_hours` | 允许的最大陈旧期 |
| `expected_versions` | 可选：外部预期版本规则（交付 ID → 版本）；没有则预期检查“未评估” |

包内任何公钥、签名、回执彼此匹配，**只证明内部一致性**，不建立身份可信性。缺少信任输入 → 身份轴 `unknown`（`E-TRUST-NOT-ESTABLISHED`），整体不得显示“通过”。

### 4.2 撤销状态文件

- 必须由 `status_publisher_pub` 对应私钥签名；签名覆盖 `(published_at, valid_until, revocations[])`。
- `valid_until` 过期，或 `now - published_at > max_status_age_hours` → `unknown`（`E-KEY-STATUS-STALE`）。
- 多份状态冲突（同一 actor/fingerprint 结论不同）→ `unknown`（`E-KEY-STATUS-CONFLICT`），不擅自取最新。
- 报告显示 `key_status_as_of = published_at`，不得暗示已确认最新。

## 5. 状态枚举与退出码

**六轴**：`integrity`、`identity`、`acceptance`、`coverage`、`anchoring`、`content`。

**状态**：`pass | fail | unknown | not_applicable | not_evaluated | not_executed`。

- `not_evaluated`：缺少外部规则（如预期版本），不是通过。
- `not_executed`：`hashes_only` 下未做内容复核，不是通过。

| 退出码 | 含义 |
|---|---|
| 0 | 所有适用轴均为 pass / not_applicable |
| 1 | 任一轴 fail |
| 2 | 无 fail，但存在 unknown / not_evaluated / not_executed |
| 3 | 协议或 I/O 错误（序列化失败、文件不可读、schema 不符） |

机器摘要始终输出六轴 JSON；人读报告固定三段：已证明 / 未证明 / 未覆盖。退出码只是汇总，不替代分轴。

## 6. 重写的验收用例

| ID | 操作 | 应判断 | 不应判断 | 结果 | 原因码 | 退出 |
|---|---|---|---|---|---|---|
| AC-01 | 交付后替换附件内容 | 该附件现内容与声明摘要不符；列出附件、声明版本、预期/实际摘要 | 替换过程、时间、实施者 | integrity fail；content not_executed（hashes_only） | E-ART-MISMATCH | 1 |
| AC-02a | 修改记录内容，保留原签名 | 签名校验失败 | 是否有人重签、动机 | integrity fail | E-SIG-INVALID | 1 |
| AC-02b | 用未获信任的密钥重签 | 签名在数学上成立，但签署身份不在信任集 | 是否篡改 | identity unknown；内部一致性 pass | E-SIG-UNTRUSTED-KEY / E-TRUST-NOT-ESTABLISHED | 2 |
| AC-02c | 受信且获授权的密钥签署另一条内部一致记录 | 这是一条新的有效签署声明；列出全部验收，冲突时报告 | 哪次是“真实意图” | acceptance pass 或 conflict | E-ACC-CONFLICT（如有冲突） | 2 |
| AC-02d | 验收声明的哈希集合与被引用交付不一致 | 绑定错误 | 意图 | acceptance fail | E-ACC-BINDING | 1 |
| AC-02e | 接收方签署时选错版本 | 声明核验：签名有效、引用一致，pass；预期检查：无外部规则时 not_evaluated | 是否选错版本、真实意图 | acceptance pass；expectation not_evaluated | — | 2 |
| AC-03a | 删除账本中间记录 | 链不连续 | 删除者 | integrity fail | E-CHAIN-GAP | 1 |
| AC-03b | 删除已锚定的尾部记录 | 呈现的链 tip 与回执覆盖位置不一致 | 删除时间 | integrity pass（切片内部一致）；anchoring fail | E-ANCHOR-MISMATCH | 1 |
| AC-03c | 删除未锚定尾部并重写 head | 呈现记录内部一致；历史完整性无法保证 | 是否发生回滚 | integrity pass；anchoring unknown | E-TAIL-UNANCHORED | 2 |
| AC-04a | 正常退役密钥 | 历史签名仍有效；该钥不再用于新记录 | 追溯否定历史 | identity pass | — | 0 |
| AC-04b | 疑似泄露密钥 | 数学验签结果保留；身份可信性未知；给出泄露时间窗 | 断定具体泄露时刻 | identity unknown | E-KEY-COMPROMISE-SUSPECTED | 2 |
| AC-04c | 撤销时间早于签名时间 | 签名不被信任 | 是否伪造 | identity fail | E-KEY-REVOKED | 1 |
| AC-04d | 撤销状态过期/缺失 | 状态未知；显示 as_of 与最大陈旧期 | 最新状态 | identity unknown | E-KEY-STATUS-STALE / E-KEY-STATUS-UNKNOWN | 2 |
| AC-05 | 锚点不可用后继续交付 | 锚定 unknown；证据标“未完成”；`requires_anchoring=true` 的验收 fail | 业务是否继续 | anchoring unknown；acceptance fail（若要求锚定） | E-ANCHOR-MISSING / E-ACC-REQUIRES-ANCHOR | 1 或 2 |
| AC-06 | 验证器缺少外部信任输入 | 身份可信性未建立 | 包内自洽等于可信 | identity unknown；其余轴照常 | E-TRUST-NOT-ESTABLISHED | 2 |
| AC-07 | 完全离线运行 | 无网络调用；报告可生成 | 已确认最新撤销状态 | 按各轴 | — | 0/1/2 |
| AC-08 | 内容模式不受支持（加密/裁剪） | 拒绝该包 | 转换后与原文比对 | integrity fail | E-CONTENT-MODE-UNSUPPORTED | 1 |
| AC-09 | 重复 JSON 键或非法数字 | 协议错误 | 业务结论 | 不产出轴结果 | E-SERIALIZATION | 3 |
| AC-10 | 信封与账本条目不一致 | 绑定失败 | 哪一方说谎 | integrity fail | E-ENVELOPE-MISMATCH | 1 |
| AC-11 | 包签名无效 | manifest 被改 | 具体改动者 | integrity fail | E-PACK-SIG | 1 |

## 7. Schema 一致性检查

### 7.1 工具与结果

`tools/check_schema_consistency.py` 对 `docs/evidence-pack-v0.1.schema.json` 做静态一致性检查（字段存在性、必填集、枚举、已废弃概念）。运行结果：**26/26 通过**。
该检查只证明文档与 schema 的字段约定一致，**不验证样例数据**；样例验证见第 8 节。

### 7.2 v0 schema 中发现并修正的不一致

| v0 问题 | v0.1 修正 |
|---|---|
| 缺少 `ledger` / `envelopes` / `anchors` 的原始文件引用 | 新增 `ledger`、`envelopes[]`、`anchors[]`，均带 `path + sha256` |
| 记录自带新签名，无法证明原始签名 | 交付/验收改为引用 `originals/` 原始字节；manifest 不重签 |
| 状态枚举含旧值，与文档不一致 | 统一为六种状态；旧值删除 |
| 包签名排除规则写“移除单数 signature”，歧义 | 排除整个 `signatures` 键，覆盖范围由 `signed_files` 明确 |
| 内联记录与拆分文件关系未定义 | v0.1 只允许 split；禁止 `records` 字段 |
| 缺 `content_mode`、`signed_files`、`requires_anchoring` | 均已加入 schema |
| 撤销状态无发布者/有效期 | 新增 `identity.status`（发布者、有效期、签名） |
| `acceptances` 被根级必填 | 改为可选（允许尚无验收的记录） |

## 8. 三组固定样例（冻结前必须建立）

| 样例 | 内容 | 期望结论 | 退出码 |
|---|---|---|---|
| `normal` | 全链、信封、验收、锚点、撤销状态齐全且可信输入匹配 | 六轴 pass / not_executed（content） | 2（因 content not_executed） |
| `tampered` | 在 normal 上替换一个附件内容，保留记录 | integrity fail（E-ART-MISMATCH） | 1 |
| `missing-evidence` | 在 normal 上去掉锚点回执，且某验收 `requires_anchoring=true` | anchoring unknown；acceptance fail | 1 |

**通过标准**：样例检查器对三组样例给出的轴状态、原因码、退出码与本表一致；协议文档、schema、检查器三者结论一致。

## 9. 冻结门槛

- [ ] 第 2 节证明关系经实现方复核，确认可用全链切片实现（不接受“大概可以”）。
- [ ] AC-02、AC-03 的判断范围无歧义，特别是 AC-02e 与 AC-03c 的“不判断/无法判断”。
- [ ] 序列化、签名范围、状态枚举、退出码固定并写入 schema。
- [ ] 三组固定样例由检查器跑通，结论与第 8 节一致。
- [ ] 外部信任输入与撤销状态文件的提供方式与首个试点确认。

完成以上五项后，才冻结 v0.1 并开始实现（D/E/K/X 任务）。

## 10. 与 v0 的差异

- 新增：原始字节不重签、账本切片证明、锚点覆盖判定、验证算法九步。
- 新增：外部信任输入字段表、撤销状态签名与陈旧度、冲突处理。
- 新增：六轴状态枚举与退出码表；`not_evaluated` / `not_executed` 与 unknown 区分。
- 改写：AC-02 拆五种情形；AC-03 拆三种删除；删除“自动 unknown”的错误要求。
- 删除：v0 中“包内公钥可建立身份”“记录自带签名”的隐含假设。
- 保留：外部信任输入、as_of、错误码、差距清单的方向。
