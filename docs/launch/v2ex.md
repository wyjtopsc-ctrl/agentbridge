# V2EX

**标题：** 多 Agent 协作出了争议，怎么证明“哪一版交给了谁”？

**正文：**

最近在做一个小工具 agentbridge，解决一个很具体的问题：两个 Agent（或两个团队）协作交付，
事后出现争议时，双方只有聊天记录和截图，说不清哪一版交付了、对方验收没有、记录有没有被改。

做法很窄：把“承诺—交付—验收”记进哈希链账本，每一步用 Ed25519 签名；支持交付版本、拒收理由、
修订关系和密钥轮换；最后可以导出一个证据包，接收方离线用开源验证器核验，不需要信任发送方，
也不需要购买。

它不做裁决、不判断交付质量；默认只核验摘要，不复核文件内容，报告里会明确写出来。

仓库（MIT）：https://github.com/wyjtopsc-ctrl/agentbridge
Demo video: https://github.com/wyjtopsc-ctrl/agentbridge/blob/main/demo/agentbridge-demo-zh.mp4
两分钟演示：`PYTHONPATH=src python3 demo/run_demo.py`

目前是 pre-1.0，只有本地 CI 证据，没有第三方审计。想听听大家：这种“交付证据”在哪些真实流程里
最需要？外包交付、平台第三方 Agent 准入、还是内部多 Agent 流水线？
