# agentbridge 已知开放问题

只列还没修的。每条都应在 docs/threat-model.md 或 CHANGELOG 中有对应说明。

## 已知开放

- head.json 无保护：同用户同时改写账本与 head 时，verify 发现不了；只有外部锚点能抓。
- 没有 TLS、限流、审计日志轮转；sequencer 只适合本地或反向代理之后。
- 没有密钥轮换与吊销协议；actor 注册表是 TOFU，换钥会被报为冲突。
- 锚点服务没有透明日志 gossip：不诚实的服务可能对不同人展示不同日志。
- 单机单写者：没有多副本、故障转移或离线队列。
- POSIX only（依赖 fcntl），Windows 不支持。
- MCP server 的资源/提示为空，只暴露工具；prompt 注入防护不在范围内（那是 prevention）。
- 打包工具链：`python -m build` 在构建环境卡住，当前用 tools/build_release.py 直接产 wheel。

## 已知边界（不是待办）

- 不裁决谁对谁错；不做资金托管；不做通用区块链存证。
- `verified` 只表示“与账本一致”，不表示“来源可信”。
- 用户如果丢掉外部锚点，就只能依赖链内自洽。

- **Evidence packs and key lifecycle (K4)**: packs currently list actor public keys from
  `actor_register` only. A pack exported after a rotation will report identity uncertainty until
  the key timeline (rotate/revoke entries) is carried in the manifest and checked by the verifier.
