# Xbox MRS 规则

插件默认把规则发布到 `rules/<游戏或软件目录名>/`。域名和 IP 使用独立的 MRS 文件。

| 默认文件名 | Mihomo behavior | format |
| --- | --- | --- |
| `domain.mrs` | `domain` | `mrs` |
| `ip.mrs` | `ipcidr` | `mrs` |

在 LuCI 的 **GitHub 与 MRS** 登录后，可以从录制详情发布生成的 MRS，或选择已有文件上传。再次发布到同样的路径和文件名，插件会合并已有规则和这次的新条目。可在 GitHub 的提交记录查看每次更新。
