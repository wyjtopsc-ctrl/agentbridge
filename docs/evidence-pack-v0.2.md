# 证据包 v0.2 协议（冻结候选）

**状态**：技术冻结（2026-10-21）；批准签署见冻结记录　**替代**：v0.1 草案　**代码基线**：0.9.3（提交 641a53a）
**冻结条件**：正文、schema、验证器、固定向量一致，并绑定具体提交与测试结果（见冻结记录）。

## 0. 支持范围

- 支持 **bridge 0.9.x+** 的导出；旧包按 v0.1 规则继续可验（0.6.1 黄金语料为证）；
- 只支持单任务、单逻辑交付（可多版本）、`hashes_only` 内容模式；
- **不支持**：附件内容复核、K3 紧急恢复、多任务批量导出、项目隔离/保留/加密、跨桥密钥联邦；
- 不支持的内容模式、未知版本、未知拒绝类型必须显式拒绝，不得静默通过。

## 1. 包结构

`manifest.json` + `originals/`（账本切片从 genesis、信封、验收记录、状态、回执逐字节保留）。
manifest 必填：`pack_version`、`created_at`、`as_of`、`bridge_id`、`task`、`deliveries`、
`acceptances`、`identity`、`ledger`、`envelopes`、`anchors`、`coverage`、`content_mode`、
`limits`、`signed_files`、`signatures`。

## 2. 密钥历史与轮换授权

`identity.history` 每个事件绑定 `ledger_seq + digest`，顺序为 register / rotate / revoke：

- **register**：首次注册的钥；外部信任输入必须匹配它的指纹；
- **rotate**：必须由**当前有效旧钥**签名，并携带新钥对同一 digest 的证明（`new_sig`）；
- **revoke**：`normal_retirement / suspected_compromise / revoked`，带生效时间与疑似泄露时间。

验证规则：

1. 历史必须与原始账本逐项一致（类型、摘要、公钥/撤销字段）；不一致 `E-HISTORY-MISMATCH`，
   账本中每条密钥事件缺失于 history 同样失败；
2. 按记录所在账本序号选择当时有效的钥；
3. **已撤销的钥不能再授权轮换**，也不能继续传播信任：`E-ROTATE-AFTER-REVOCATION`；
4. **疑似泄露的可信时间只用于判断“记录是否早于最早可能失效边界”，不恢复密钥可信**：
   - 锚点能证明某条记录早于确定的失效边界 → 可按策略认可**该条历史记录**（记录级）；
   - 泄露起点不明 → 不能因后来获得锚点而变为 pass，身份保持 `unknown`；
   - 泄露后的轮换即使旧钥签名有效也不自动恢复信任（`E-ROTATE-AFTER-COMPROMISE`）；
     恢复需要 K3 独立机制；K3 未实现时按人工流程停止相关操作；
5. 撤销不追溯否定历史签名；历史记录仍按签署时的钥与状态核验。

## 3. 修订与验收语义

- 逻辑交付用 `bridge_id + delivery_id` 定位，`version` 区分版本，`previous_version` 指向上一版；
- 验收绑定 `delivery_id + version + artifacts_sha256`，验收 v1 不会自动成为验收 v2；
- 导出者不能通过重签 manifest 改写修订历史：每个 delivery 行必须与原始账本条目逐项一致
  （`type/id/delivery_id/version/previous_delivery`），不一致 `E-DELIVERY-BINDING`；
- 重复版本号 `E-DUPLICATE-VERSION`；断裂/指向不存在的 `previous_version` `E-REVISION-CHAIN`；
- 验收引用不存在的版本 `E-ACC-DANGLING`；
- 同版本冲突验收（accepted 与 rejected 并存）→ 验收轴 `unknown`（`E-ACC-CONFLICT`）；
- **superseded 只描述版本地位**：旧版本不再是当前目标，但其签名、绑定、历史验收仍全量核验；
  仅“预期版本”检查标 `not_applicable`，不得跳过任何签名或绑定检查。

## 4. 六轴、退出码与拒绝规则

六轴 `integrity / identity / acceptance / coverage / anchoring / content`；
状态 `pass / fail / unknown / not_applicable / not_evaluated / not_executed`；
退出码 0（全 pass）、1（有 fail）、2（无 fail 但有 unknown/not_evaluated/not_executed）、
3（协议或 I/O 错误）。

新增原因码：`E-HISTORY-MISMATCH`、`E-ROTATE-AFTER-REVOCATION`、`E-DELIVERY-BINDING`、
`E-DUPLICATE-VERSION`、`E-REVISION-CHAIN`、`E-ACC-DANGLING`、`E-ACC-CONFLICT`、
`E-SUPERSEDED-VERSION`、`E-KEY-COMPROMISE-SUSPECTED`。

## 5. hashes_only 披露（强制）

接收方报告必须直接写出：

> `content_mode=hashes_only`：核验的是交付摘要与签署记录，未复核文件内容。

验证器输出 `disclosure` 字段承载该句；任何面向人的摘要不得省略。接收方演练时必须复述：
能否确认文件内容被复核（不能）、是否最新全部历史（取决于外部检查点与证据范围）、
业务交付质量（密码学校验不能判断）、哪些身份/锚点/状态依赖外部信任。

## 6. 并发导出

- 导出对账本持有**共享锁**，写入方需要独占锁，因此导出读取期间写入被阻塞；
- 导出前后记录并核对检查点（`bridge_id + seq + digest`），作为辅助检查；不一致则重试；
- 已用并发测试 V12 验证导出快照与账本 tip 一致；
- 仍**未覆盖**崩溃、磁盘满、跨机复制等故障注入；试点操作仍需固定检查点，不能把“导出成功”当成并发安全证明。

## 7. 里程碑

| 里程碑 | 完成依据 |
|---|---|
| 协议冻结 | 正文、schema、验证器、固定向量一致；支持范围与拒绝规则明确；绑定具体代码提交与测试结果 |
| 试点有效 | 真实接收方独立完成核验，记录耗时、求助次数、结果理解，并确认是否愿意付费 |

## 8. 冻结检查表

- [x] 真实端到端：提交 v1 → 拒收 → 轮换 → 修订 v2 → 验收 → 导出 → 离线核验；
- [x] 撤销场景：正常退役 pass；疑似泄露 unknown；
- [x] schema v0.2 与真实导出固定样例（Ajv 12/12）；
- [x] 协议/验证器/固定向量一致：17/17 矩阵、109 条测试；
- [x] 并发导出：共享锁 + V12 快照一致性；
- [x] 拒绝规则与原因码；
- [x] 冻结记录：绑定提交哈希、协议/schema/发行物 SHA-256 与 CI 结果（见 `docs/freeze-record-2026-10-21.md` 与 `frozen/evidence-pack-v0.2/`）。
