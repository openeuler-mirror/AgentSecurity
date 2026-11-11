"""MacOSProfile — macOS 操作系统的安全检测 Profile

macOS 与 Linux 同为 Unix 系，命令体系高度重合：`rm -rf`、`sudo`、`chmod`、
`.ssh/id_rsa`、`.aws/credentials`、`/etc/passwd` 等语义完全一致。因此**不复制**
一份 Linux 规则集（那会导致两处维护、必然漂移），而是：

- **继承** LinuxProfile 的全部规则加载逻辑与白名单
- 把 `accepted_os` 扩展为 `("linux", "macos")` —— 于是 JSON 里
  `os=macos` 的条目（macOS 专属安全面）与 Linux 通用条目**同时生效**

macOS 有而 Linux 没有的安全面（见 `rules/l1_rules.json` 中 os=macos 段）：

| 安全机制 | 相关命令 | 关闭/绕过的后果 |
|---|---|---|
| SIP 系统完整性保护 | `csrutil disable` | 可任意改系统文件 |
| Gatekeeper 应用校验 | `spctl --master-disable` | 可运行未签名应用 |
| launchd 持久化 | `launchctl load /Library/LaunchDaemons/...` | 开机自启后门 |
| 钥匙串凭据 | `security find-generic-password -w` | 窃取存储的密码 |
| 本地目录服务 | `dscl . -create` | 账户/组篡改 |
| NVRAM | `nvram <var>=` | 篡改启动参数 |
| 文件保护标志 | `chflags nouchg` | 绕过 SIP 前置步骤 |
"""

from .linux import LinuxProfile


class MacOSProfile(LinuxProfile):
    """macOS 操作系统安全检测 Profile（= Linux 通用规则 + macOS 专属补充）"""

    os_type_value = "macos"

    #: 接受 Linux 通用规则与 macOS 专属规则（JSON 的 "os" 字段命中其一即加载）。
    #: 这正是"继承而非复制"的实现点：改 Linux 规则时 macOS 自动跟随。
    accepted_os = ("linux", "macos")
