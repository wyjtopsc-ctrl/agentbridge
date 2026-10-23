# Demo narration (Chinese)

| Step | 旁白（字幕） |
|---|---|
| Title | Agent 交付出了争议，怎么证明哪一版交给了谁？ |
| 1 Setup | 两个 Agent、一个共享账本：谁签了什么，都留下记录。 |
| 2 Request | 客户发送请求；版本与附件摘要进入签名账本。 |
| 3 Deliver v1 | 执行方交付 v1；这一版被固定下来。 |
| 4 Reject | 客户拒收 v1；理由绑定到这一版，而不是口头拒绝。 |
| 5 Revise v2 | 修订 v2；previous_version 指回 v1。 |
| 6 Accept v2 | 只验收 v2；验收 v1 不会自动变成验收 v2。 |
| 7 Export | 导出证据包：账本、信封、验收、密钥历史。 |
| 8 Verify | 接收方离线核验：五轴通过，内容轴未执行。 |
| 9 Tamper | 改一个字节，完整性立刻失败。 |
| 10 Boundary | 它证明版本与记录，不证明内容质量与最新历史。 |
| End | MIT 开源 · pre-1.0 · hashes_only 不复核文件内容 |

English version (for a later take):

| Step | Subtitle |
|---|---|
| Title | When agents disagree on a delivery, what can you actually prove? |
| 1 | Two identities, one shared ledger: who signed what is recorded. |
| 4 | The client rejects v1 — the reason is bound to that version, not a chat message. |
| 6 | Only v2 is accepted; accepting v1 never implies v2. |
| 8 | The receiver verifies offline: five axes pass, content is not executed. |
| 9 | Flip one byte and integrity fails immediately. |
| 10 | It proves versions and records, not quality or the latest history. |
