# agentbridge

[English](README.md) | [中文](README.zh-CN.md)

**Agent 协作的交付证据层。** 一个零运行时依赖的 Python 库 + CLI：让两个 Agent（或代表它们的两个进程）
交换工作，并在事后向第三方证明「哪一版交给了谁、对方验收了没有、记录有没有被改过」。

- 没有共识链、没有代币：哈希链账本 + 内容寻址附件 + 一个由人保管在机器之外的锚点。
- 不做裁判：不判断交付质量、不裁决谁对谁错，只把「承诺—交付—验收」固定成可核验的事实。
- 当前版本 **0.9.4**；证据包协议 **v0.2（技术冻结）**。

> 边界说明：产品是 pre-1.0 组件，不是安全认证产品。当前只有本地 CI 证据，没有第三方审计，
> 也没有客户付费验证。默认 `hashes_only`：只核验摘要与签署记录，**不复核附件内容**。

## 能力

| 能力 | 说明 |
|---|---|
| 哈希链账本 | `seq/prev/digest` 连续；中间改行与尾截断可发现；追加失败关闭 |
| 信封与工件 | 请求/交付正文签名；附件按 sha256 内容寻址存储 |
| 身份 | Ed25519、actor 注册、密钥轮换/撤销、按记录选择当时有效钥 |
| 交付与验收 | 逻辑交付 + 版本 + 修订关系；验收绑定版本与工件哈希集合 |
| 证据包 v0.2 | 账本切片、信封、验收、密钥历史、外部回执逐字节保留；manifest 签名 |
| 离线核验 | 六轴：完整性 / 身份 / 验收 / 覆盖 / 锚定 / 内容；输出原因码与披露 |
| 接入 | CLI、Python API、MCP stdio、HTTP 单写序列器、托管锚点 |

## 安装

```console
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # 源码；零运行时依赖
agentbridge --help
```

Python 3.9+，POSIX（依赖 `fcntl`）。也可从发行包安装 wheel。

## 快速开始

```console
$ mkdir -p keys shared
$ agentbridge keygen --actor client --out keys
$ agentbridge keygen --actor worker --out keys
$ agentbridge --root shared init --actor client
$ agentbridge --root shared --key keys/client.key register
$ agentbridge --root shared --key keys/worker.key register

$ agentbridge --root shared --key keys/client.key \
    send --to worker --intent review --body "复核这个模块" --attach ./module.py
$ agentbridge --root shared --key keys/worker.key \
    deliver --to client --in-reply-to <id> --body "交付 v1" --attach ./findings.md
```

验收记录目前通过 Python API 写入：

```python
from agentbridge import Bridge
b = Bridge("shared")
b.accept_delivery("client", "<delivery envelope id>", version="v1",
                  decision="accepted", reason="")
```

修订与再验收：`deliver --version v2 --revises <v1 id>`，然后对新版本重新 `accept_delivery`。

## 证据包：导出与离线核验

```console
$ agentbridge --root shared --key keys/exporter.key \
    evidence export --delivery <v2 id> --out ./pack \
    --status ./status.json --receipt ./receipt.json \
    --task-system jira --task-id ABC-123

$ agentbridge evidence verify --pack ./pack --trust ./trust.json
```

输出六轴状态、原因码与 `disclosure`（例如：`hashes_only` 未复核文件内容）。信任文件必须在包外，
由接收方独立确认；退出码 0/1/2/3 分别表示全通过、有失败、有未知/未执行、协议错误。

## 设计要点

- **信封**：`wire/outbox`（请求）/ `wire/inbox`（交付），含签名与附件清单。
- **工件库**：附件复制到 `wire/artifacts/<sha256>`；核验针对副本，原路径变化只显示 `drifted`。
- **账本**：`ledger.jsonl` 追加式哈希链；`wire/head.json` 记录 tip，追加 fail-closed。
- **外部锚点**：`anchor` 输出 `(seq, digest)`，由人抄到机器之外；这是对抗「账本 + head 一起被改」的唯一手段。
- **密钥时间线**：register/rotate/revoke 绑定账本序号与摘要；已撤销密钥不能继续授权轮换。
- **修订**：同一 `delivery_id` 可多版本；旧版本被标记 superseded，但签名与绑定仍全量核验。

## 测试

```console
make ci     # 9 套测试 + 协议矩阵 + 重建 + schema + fuzz + 独立交叉验证
```

依赖：Node + Ajv（schema 校验）、Python `cryptography`（独立交叉验证）；缺失时对应步骤 SKIP，不冒充 PASS。
当前本地结果：产品测试 111/111、冻结矩阵 17/17、独立交叉验证 11/11、fuzz 300/300。

## 已知限制

- `hashes_only`：不复核附件内容；签名有效不代表内容正确。
- K3 紧急恢复未实现：密钥丢失/泄露按人工流程停止与重新接入。
- 未锚定的尾部整体回滚不可发现；离线不能自行确认「最新全部历史」。
- 导出对账本加共享锁阻塞写入，但崩溃、磁盘满、跨机复制未覆盖。
- 多任务批量导出、项目隔离、保留与加密未实现。

## 文档

- [协议](docs/protocol.md) · [威胁模型](docs/threat-model.md) · [MCP](docs/mcp.md)
- [证据包 v0.2 协议](docs/evidence-pack-v0.2.md) · [schema](docs/evidence-pack-v0.2.schema.json)
- [冻结记录](docs/freeze-record-2026-10-21.md) · [版本更迭](docs/version-history.md)
- 白皮书/手册/版本记录：`docs/exports/`（公开快照）或 `deliverables/`（开发工作区）

## License

MIT，见 [LICENSE](LICENSE)。
