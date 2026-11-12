"""HarmonyProfile — HarmonyOS 操作系统的安全检测 Profile

HarmonyOS 使用 Toybox shell（类 Unix 工具集，aarch64，HongMeng Kernel）：
`rm`/`cat`/`chmod`/`curl`/`wget`/`ifconfig`/`ip` 等命令与 Linux 完全一致
（2026-09 实测 hdc shell）。因此**继承 LinuxProfile** 的通用规则，仅叠加
鸿蒙专属安全面。

鸿蒙有而 Linux 没有的安全面（见 `rules/l1_rules.json` 中 os=harmony 段）：

| 命令 | 危险用法 | 后果 |
|---|---|---|
| `bm` | `bm uninstall` / `bm install -p <包>` | 恶意卸载/安装应用（供应链） |
| `aa` | `aa force-stop` | 强制停止服务 |
| `param` | `param set` / `param dump` | 篡改/泄露系统参数 |
| `hdc` | `hdc shell` | 调试通道远程执行（提权） |
| `begetctl` | `begetctl set/write/param set` | 修改系统配置 |
| `hilog` | `hilog -c` | 清空系统日志（痕迹清除） |

敏感路径补充：`/data/app`（应用安装目录）、`/data/service/el1/public/param`
（系统参数持久化）、`/data/log`（系统日志）。
"""

from .linux import LinuxProfile


class HarmonyProfile(LinuxProfile):
    """HarmonyOS 操作系统安全检测 Profile（= Linux 通用规则 + 鸿蒙专属补充）"""

    os_type_value = "harmony"

    #: 接受 Linux 通用规则与鸿蒙专属规则（JSON 的 "os" 字段命中其一即加载）。
    #: 与 MacOSProfile 同理，继承 Linux 规则集，鸿蒙专属条目额外叠加。
    accepted_os = ("linux", "harmony")
