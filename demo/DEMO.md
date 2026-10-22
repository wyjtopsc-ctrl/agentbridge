# 2-minute demo storyboard

Recording: terminal at 120 columns, font 16+, light/dark theme consistent. Run from repo root:

```console
$ PYTHONPATH=src python3 demo/run_demo.py
```

| Time | On screen | Narration |
|---|---|---|
| 0:00 | repo + `agentbridge` README | “Agent 交付出了争议，怎么证明哪一版交给了谁？” |
| 0:10 | demo step 1–2 | “两个身份、一个共享桥；客户发送请求。” |
| 0:25 | step 3 | “执行方交付 v1；版本和附件摘要进入签名账本。” |
| 0:35 | step 4 | “客户拒收，理由绑定 v1；不是口头拒绝。” |
| 0:45 | step 5 | “修订 v2，previous_version 指向 v1。” |
| 0:55 | step 6 | “只验收 v2；验收 v1 不会自动变成验收 v2。” |
| 1:05 | step 7 | “导出证据包：账本、信封、验收、密钥历史、锚点回执。” |
| 1:20 | step 8 | “接收方离线核验：五轴通过，内容轴 not_executed。” |
| 1:35 | step 9 | “改一个字节，完整性立刻失败。” |
| 1:50 | step 10 | “它证明什么、不证明什么，报告里都写明。” |

Do not edit the output before recording. If a step fails, show the failure; the demo is about
verifiability, not a perfect run.
