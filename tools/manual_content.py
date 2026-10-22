"""Content blocks for the agentbridge user manual (0.9.3 / evidence-pack v0.2)."""

TITLE = "agentbridge 产品使用手册"
SUBTITLE = "安装、交付与验收、证据包导出、离线核验、密钥生命周期、MCP 集成"
VERSION = "0.9.3"

BLOCKS = [
    ("toc", ["1　关于本文档", "2　安装", "3　五分钟快速开始", "4　核心概念",
             "5　交付、验收与修订", "6　CLI 参考", "7　Python API",
             "8　证据包与离线核验", "9　密钥生命周期", "10　MCP 与网络部署",
             "11　验证、退出码与已知限制", "12　故障排查", "13　安全清单", "14　FAQ",
             "附录 A　退出码与原因码", "附录 B　路径与环境变量"]),

    ("h1", "1　关于本文档"),
    ("p", "本文档面向第一次使用 agentbridge 的开发者与运维人员，覆盖从安装到「交付 → 验收 → "
          "证据包 → 离线核验」的完整路径。示例基于 0.9.3 与 evidence-pack v0.2。"),
    ("muted", "约定：$ 开头为 shell 命令；<尖括号> 为需要替换的参数；示例路径请按实际环境调整。"),

    ("h1", "2　安装"),
    ("h2", "2.1　环境要求"),
    ("table", ["项目", "要求"],
     [["Python", "3.9 及以上"],
      ["操作系统", "POSIX（依赖 fcntl；Windows 不支持）"],
      ["依赖", "零运行时依赖"],
      ["磁盘", "账本、附件副本与证据包输出目录"]],
     ),
    ("h2", "2.2　从发行包安装"),
    ("code", "$ unzip agentbridge-0.9.3-release.zip && cd agentbridge-0.9.3-release\n"
             "$ python3 -m venv .venv && . .venv/bin/activate\n"
             "$ pip install dist/agentbridge-0.9.3-py3-none-any.whl\n"
             "$ agentbridge --help | head"),
    ("h2", "2.3　从源码安装"),
    ("code", "$ cd agentbridge\n"
             "$ python3 -m venv .venv && . .venv/bin/activate\n"
             "$ pip install -e .\n"
             "$ agentbridge --help"),
    ("muted", "不安装也可运行：把 src 加入 PYTHONPATH，用 python3 -m agentbridge 调用。"),
    ("h2", "2.4　安装后自检"),
    ("code", "$ agentbridge key-status --help\n"
             "$ agentbridge evidence --help\n"
             "$ make ci            # 源码树内：9 套测试 + 协议矩阵 + schema + fuzz + 交叉验证"),

    ("h1", "3　五分钟快速开始"),
    ("p", "建立本地桥，完成一次「请求 → 交付 → 验收 → 导出 → 核验」。"),
    ("h2", "3.1　初始化与身份"),
    ("code", "$ mkdir -p keys shared\n"
             "$ agentbridge keygen --actor client --out keys\n"
             "$ agentbridge keygen --actor worker --out keys\n"
             "$ agentbridge --root shared init --actor client\n"
             "$ agentbridge --root shared --key keys/client.key register\n"
             "$ agentbridge --root shared --key keys/worker.key register"),
    ("h2", "3.2　发送请求与交付"),
    ("code", "$ agentbridge --root shared --key keys/client.key \\\n"
             "    send --to worker --intent review --body \"复核这个模块\" --attach ./module.py\n"
             "$ agentbridge --root shared --key keys/worker.key \\\n"
             "    deliver --to client --in-reply-to <上一步的 id> \\\n"
             "    --body \"交付 v1\" --attach ./findings.md"),
    ("h2", "3.3　验收（Python API）"),
    ("p", "0.9.3 的验收记录通过 Python API 写入（CLI 尚未提供 accept 子命令）："),
    ("code", "from agentbridge import Bridge\n"
             "b = Bridge('shared')\n"
             "b.accept_delivery('client', '<交付信封 id>', version='v1',\n"
             "                  decision='accepted', reason='')\n"),
    ("h2", "3.4　导出证据包并离线核验"),
    ("code", "$ agentbridge --root shared --key keys/export.key \\\n"
             "    evidence export --delivery <交付信封 id> --out ./pack \\\n"
             "    --status ./status.json --receipt ./receipt.json \\\n"
             "    --task-system jira --task-id ABC-123\n"
             "$ agentbridge evidence verify --pack ./pack --trust ./trust.json"),
    ("muted", "verify 输出六轴与 disclosure；退出码 0/1/2/3 见附录 A。信任文件必须在包外，"
              "由接收方独立确认。"),

    ("h1", "4　核心概念"),
    ("table", ["概念", "说明", "相关命令/API"],
     [["bridge", "共享目录：账本、信封、附件库", "init / doctor"],
      ["entry 条目", "账本一行：类型、actor、seq、prev、digest、签名", "ledger"],
      ["envelope 信封", "请求/交付正文与附件清单，含签名", "send / deliver / show"],
      ["artifact 工件", "附件按 sha256 内容寻址存储副本", "send --attach"],
      ["head", "账本 tip 的 (seq, digest)", "anchor"],
      ["actor", "身份名，注册后绑定 Ed25519 公钥", "keygen / register"],
      ["delivery 交付", "逻辑交付；可多版本，version + previous_version", "deliver --version --revises"],
      ["acceptance 验收", "接收方对某版本与哈希集合的接受/拒收记录", "Bridge.accept_delivery"],
      ["key timeline", "register/rotate/revoke 事件，按账本序号选钥", "rotate / revoke / key-status"],
      ["evidence pack", "可离线核验的证据包（manifest + originals）", "evidence export/verify"]]),
    ("h2", "4.1　交付与验收的关系"),
    ("p", "一次交付由 `delivery_id`（逻辑对象）+ `version` 定位；验收必须绑定这两个值以及附件哈希集合。"
          "验收 v1 不会自动变成验收 v2；v2 需要重新验收。"),

    ("h1", "5　交付、验收与修订"),
    ("h2", "5.1　v1 → 拒收 → v2 → 再验收"),
    ("code", "from agentbridge import Bridge, signing\n"
             "client = signing.load_keyfile('keys/client.key')\n"
             "worker = signing.load_keyfile('keys/worker.key')\n"
             "b = Bridge('shared', client)\n"
             "req = b.send(actor='client', to='worker', body='do it', attach=['req.md'])\n"
             "v1 = Bridge('shared', worker).deliver(actor='worker', to='client',\n"
             "        in_reply_to=req['id'], body='v1', attach=['v1.md'])\n"
             "b.accept_delivery('client', v1['id'], decision='rejected', reason='缺测试')\n"
             "v2 = Bridge('shared', worker).deliver(actor='worker', to='client',\n"
             "        in_reply_to=req['id'], body='v2', attach=['v2.md'],\n"
             "        version='v2', revises=v1['id'])\n"
             "b.accept_delivery('client', v2['id'], decision='accepted')\n"),
    ("p", "导出时以 v2 的 envelope id 作为 `--delivery`，包内会包含 v1/v2 两个版本、v1 的拒收、"
          "v2 的验收与密钥时间线。"),
    ("h2", "5.2　规则"),
    ("bullet", "同一逻辑交付的 version 必须唯一；重复版本导出/核验会被拒绝。"),
    ("bullet", "previous_version 必须指向已存在的上一版；断链会被拒绝。"),
    ("bullet", "旧版本验收被标记 superseded（仅“预期版本”检查为 not_applicable），签名与绑定仍全量核验。"),
    ("bullet", "同版本同时出现 accepted 与 rejected → 验收轴 unknown（冲突）。"),
    ("bullet", "验收引用不存在的版本 → E-ACC-DANGLING。"),

    ("h1", "6　CLI 参考"),
    ("table", ["命令", "用途"],
     [["keygen / register", "生成密钥、注册 actor"],
      ["init / doctor", "初始化/自检桥"],
      ["send / deliver", "发送请求、交付（支持 --version/--revises）"],
      ["requests / poll", "读取请求与收件箱"],
      ["verify", "校验链、信封、工件、锚点"],
      ["ledger / show", "查看账本与单条信封"],
      ["commit", "记录承诺"],
      ["anchor / anchor-service / anchor-submit / anchor-verify", "本地锚点、托管锚点与回执"],
      ["serve / mcp", "HTTP 单写序列器、MCP stdio 服务"],
      ["rotate / revoke / key-status", "密钥轮换、撤销、状态查询"],
      ["evidence export", "导出证据包（v0.2）"],
      ["evidence verify", "离线核验证据包"],
      ["repair", "head 写失败后的显式修复"]],
     ),
    ("p", "常用参数：`--root` 指定桥目录，`--key` 指定签名密钥（全局参数放在子命令前）。"),

    ("h1", "7　Python API"),
    ("table", ["API", "用途"],
     [["Bridge(root, signer)", "打开/创建桥"],
      ["b.send(...) / b.deliver(...)", "发送请求/交付；交付支持 version、revises"],
      ["b.accept_delivery(actor, ref, version=..., decision=..., reason=...)", "写入验收/拒收记录"],
      ["b.rotate_key(new_signer, reason=...)", "轮换（旧钥授权新钥）"],
      ["b.revoke_key(kind=..., effective_at=..., suspected_leak_at=...)", "撤销（历史不改写）"],
      ["b.key_status()", "查看当前钥、轮换与撤销"],
      ["b.verify()", "桥内校验（账本/信封/工件/签名）"],
      ["evidence.export_pack(...)", "导出证据包"],
      ["evidence.verify_pack(pack, trust)", "离线核验，返回六轴结果与 exit_code"]]),
    ("h2", "7.1　验收记录内容"),
    ("p", "验收记录包含 protocol_version、acceptance_id、delivery_id、version、delivery_ref、"
          "artifacts_sha256、decision、reason、requires_anchoring、actor、signed_at 与签名。"),
    ("h2", "7.2　密钥轮换与撤销"),
    ("code", "from agentbridge import Bridge, signing\n"
             "old = signing.load_keyfile('keys/worker.key')\n"
             "new = signing.Signer('worker', new_seed)\n"
             "b = Bridge('shared', old)\n"
             "b.rotate_key(new, reason='routine')\n"
             "Bridge('shared', new).revoke_key('normal_retirement')\n"),

    ("h1", "8　证据包与离线核验"),
    ("h2", "8.1　导出"),
    ("code", "$ agentbridge --root shared --key keys/exporter.key \\\n"
             "    evidence export --delivery <v2 的 envelope id> --out ./pack \\\n"
             "    --status ./status.json --receipt ./receipt.json \\\n"
             "    --task-system jira --task-id ABC-123"),
    ("p", "manifest 记录账本切片、全部版本、验收、密钥历史、锚点回执与签名；originals/ 逐字节保留原始材料。"
          "证据包只带摘要，不带附件内容（hashes_only）。"),
    ("h2", "8.2　核验"),
    ("code", "$ agentbridge evidence verify --pack ./pack --trust ./trust.json\n"
             "{\n"
             "  \"axes\": {\n"
             "    \"integrity\": {\"status\": \"pass\"},\n"
             "    \"identity\": {\"status\": \"pass\"},\n"
             "    \"acceptance\": {\"status\": \"pass\"},\n"
             "    \"coverage\": {\"status\": \"pass\"},\n"
             "    \"anchoring\": {\"status\": \"pass\"},\n"
             "    \"content\": {\"status\": \"not_executed\"}\n"
             "  },\n"
             "  \"exit_code\": 2,\n"
             "  \"disclosure\": [\"content_mode=hashes_only：核验的是交付摘要与签署记录，未复核文件内容。\"]\n"
             "}"),
    ("h2", "8.3　六轴与状态"),
    ("table", ["轴", "含义"],
     [["integrity", "账本链、摘要、文件哈希、交付行与账本条目绑定、history 与账本一致"],
      ["identity", "外部信任匹配、逐记录选钥、轮换授权、撤销/泄露状态"],
      ["acceptance", "验收签名、版本/哈希绑定、旧版本 superseded、冲突"],
      ["coverage", "应记录/已记录事件与缺口"],
      ["anchoring", "回执签名、覆盖位置、最低检查点、精确检查点"],
      ["content", "hashes_only 下固定 not_executed"]]),
    ("p", "状态：pass / fail / unknown / not_applicable / not_evaluated / not_executed；"
          "退出码 0=全通过，1=有 fail，2=无 fail 但有 unknown/未执行，3=协议或 I/O 错误。"),
    ("h2", "8.4　接收方必须理解"),
    ("bullet", "不能确认文件内容已被复核（hashes_only）；"),
    ("bullet", "不能确认「最新全部历史」（取决于外部检查点与证据范围）；"),
    ("bullet", "不能判断业务交付质量；"),
    ("bullet", "身份、锚点、撤销状态依赖外部信任配置。"),

    ("h1", "9　密钥生命周期"),
    ("table", ["操作", "命令/API", "语义"],
     [["注册", "register / register_actor", "首次注册；外部信任必须匹配其指纹"],
      ["轮换", "rotate --new-key", "旧钥签名并携带新钥证明；旧钥之后不能写"],
      ["撤销", "revoke --kind ...", "normal_retirement / suspected_compromise / revoked；历史不改写"],
      ["状态", "key-status / key_status()", "当前钥、轮换、撤销、疑似泄露时间"],
      ["泄露边界", "verify", "可信时间只限定记录是否早于失效边界，不恢复密钥可信"],
      ["泄露后轮换", "—", "拒绝（E-ROTATE-AFTER-COMPROMISE）；恢复需 K3（未实现）"]]),
    ("muted", "K3 未实现时：停止用相关密钥签署，按试点准入的人工流程撤销、重新接入并保留历史。"),

    ("h1", "10　MCP 与网络部署"),
    ("h2", "10.1　MCP"),
    ("code", "$ agentbridge --root shared --key keys/planner.key mcp\n"
             "# 工具：send_request / deliver_result / poll_inbox / verify_bridge / read_ledger ..."),
    ("p", "默认只暴露只读与安全写入工具；破坏性工具（repair/recover_empty）需要 "
          "`--allow-destructive-tools` 且要求布尔 consent=true。"),
    ("h2", "10.2　HTTP 单写序列器"),
    ("code", "$ agentbridge serve --root shared --host 127.0.0.1 --port 8765\n"
             "$ agentbridge --remote http://127.0.0.1:8765 --key keys/planner.key actors"),
    ("p", "服务器不持有任何 actor 私钥，只校验客户端签名条目并排序；跨机部署建议放在 TLS 反向代理后。"),

    ("h1", "11　验证、退出码与已知限制"),
    ("h2", "11.1　桥内验证"),
    ("code", "$ agentbridge --root shared verify\n"
             "$ agentbridge --root shared verify --expect-head <seq>:<digest>"),
    ("h2", "11.2　已知限制"),
    ("bullet", "内容复核未实现：证据包只核验摘要与签署记录。"),
    ("bullet", "K3 紧急恢复未实现；泄露/丢失按人工流程。"),
    ("bullet", "多任务批量导出、项目隔离、保留、加密未实现。"),
    ("bullet", "导出对账本加共享锁阻塞写入；崩溃、磁盘满、跨机复制未覆盖。"),
    ("bullet", "验收暂未提供 CLI 子命令，使用 Python API。"),
    ("bullet", "远端 CI 未运行；当前证据为本地运行。"),

    ("h1", "12　故障排查"),
    ("table", ["现象", "处理"],
     [["refusing to append / head mismatch", "尾部可能被截断：先备份，再按需 repair --accept-head-loss"],
      ["envelope content changed", "信封字节被改：不要信任该记录，追查来源"],
      ["actor is not registered", "先 register，或检查是否用了错误密钥"],
      ["key rotated away / revocation", "使用当前钥；撤销后不能继续写"],
      ["E-DELIVERY-BINDING", "manifest 的版本/修订关系与账本不一致，重新导出"],
      ["E-HISTORY-MISMATCH", "manifest 密钥历史与账本不一致，重新导出"],
      ["verify 退出 2", "无 fail，但有 unknown/未执行；查看 axes 与 disclosure"]]),

    ("h1", "13　安全清单"),
    ("bullet", "私钥文件放在桥目录之外，权限 0600。"),
    ("bullet", "外部锚点抄到机器之外；定期核对检查点。"),
    ("bullet", "接收方自行确认信任输入（指纹/锚点/撤销发布者），不要信任包内文件。"),
    ("bullet", "证据包含交付摘要与身份信息，分享前确认范围。"),
    ("bullet", "导出前暂停写入或依赖共享锁，并记录前后检查点。"),
    ("bullet", "不把「核验通过」说成「内容合格」或「业务验收通过」。"),

    ("h1", "14　FAQ"),
    ("h2", "14.1　它能证明文件内容没被改吗？"),
    ("p", "能证明「当前内容与声明摘要不一致」，不能证明文件内容正确；默认也不复核内容（hashes_only）。"),
    ("h2", "14.2　能防住内部人改记录吗？"),
    ("p", "同权限下不能防改，只能发现；要发现「账本与 head 一起被重写」，必须持有外部锚点。"),
    ("h2", "14.3　对方需要安装什么？"),
    ("p", "一个开源验证器即可离线核验；不需要访问原平台，也不需要购买。"),
    ("h2", "14.4　能做多版本和拒收吗？"),
    ("p", "可以：deliver --version --revises，验收记录绑定版本；导出会保留全部版本与拒收理由。"),

    ("pagebreak",),
    ("h2", "附录 A　退出码与原因码"),
    ("table", ["退出码", "含义"],
     [["0", "所有适用轴 pass / not_applicable"],
      ["1", "任一轴 fail"],
      ["2", "无 fail，但有 unknown / not_evaluated / not_executed"],
      ["3", "协议或 I/O 错误（schema、解析、信任文件位置等）"]]),
    ("p", "常见原因码：E-CHAIN-GAP、E-SIG-INVALID、E-ENVELOPE-MISMATCH、E-DELIVERY-BINDING、"
          "E-HISTORY-MISMATCH、E-ROTATE-AFTER-COMPROMISE、E-DUPLICATE-VERSION、E-REVISION-CHAIN、"
          "E-ACC-DANGLING、E-ACC-CONFLICT、E-KEY-COMPROMISE-SUSPECTED、E-TRUST-NOT-ESTABLISHED。"),
    ("h2", "附录 B　路径与环境变量"),
    ("table", ["路径/变量", "说明"],
     [["ledger.jsonl", "账本（根目录）"],
      ["wire/inbox、wire/outbox", "交付/请求信封"],
      ["wire/artifacts", "内容寻址附件副本"],
      ["wire/acceptances", "验收/拒收原始记录"],
      ["wire/head.json", "head 锚点"],
      ["AGENTBRIDGE_ROOT", "CLI 默认桥目录"]],
     ),
]
