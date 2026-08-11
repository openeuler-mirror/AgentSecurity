# 默认沙箱策略

## 根文件系统布局

`pivot_root` 到 tmpfs 后创建的默认挂载和目录结构：

| 路径 | 类型 | 挂载源 | 选项 |
|------|------|--------|------|
| `/` | tmpfs | `tmpfs` | — |
| `/proc` | procfs | `proc` | `ro` |
| `/usr` | bind mount | `/oldroot/usr` | `ro,nodev,nosuid,noexec` |
| `/etc` | bind mount | `/oldroot/etc` | `ro,nodev,nosuid,noexec`（nsswitch.conf 覆盖为 `files dns`） |
| `/sys` | bind mount | `/oldroot/sys` | `ro,nodev,nosuid,noexec`（非 fatal，失败仅警告） |
| `/dev` | tmpfs（根已为 tmpfs，/dev 直接建目录） | — | — |
| `/dev/shm` | tmpfs | `tmpfs` | — |
| `/tmp` | tmpfs | `tmpfs` | `mode=0777,size=256M`（默认） |
| `/bin` | symlink | → `usr/bin` | — |
| `/sbin` | symlink | → `usr/sbin` | — |
| `/lib` | symlink | → `usr/lib` | — |
| `/lib64` | symlink | → `usr/lib64` | — |
| `/dev/null` | mknod | `1:3` | — |
| `/dev/zero` | mknod | `1:5` | — |
| `/dev/full` | mknod | `1:7` | — |
| `/dev/random` | mknod | `1:8` | — |
| `/dev/urandom` | mknod | `1:9` | — |
| `/dev/tty` | mknod | `5:0` | — |

> `/oldroot` 是 `pivot_root` 后原根文件系统的挂载点，用于 bind mount 宿主机路径。

## Landlock 权限集

默认添加的 Landlock 规则（`setup_landlock_base()`，`sandbox-run.c:577-603`）：

## 规则表

| 路径 | 权限 | 类型 | 理由 |
|------|------|------|------|
| `/usr/bin` | `read+execute` | 目录级 | 所有二进制执行 + 路径遍历 |
| `/usr/lib` | `read+execute` | 目录级 | 共享库，运行时加载必需 |
| `/usr/lib64` | `read+execute` | 目录级 | 同上。内核 6.6 不检查 mmap(PROT_EXEC)，但语义上 so 是代码，加 execute 兼容未来 |
| `/usr/share` | `read` | 目录级 | locale、zoneinfo、doc 等只读数据文件，无风险 |
| `/etc` | `read` | 目录级 | ld.so.cache、passwd、group、nsswitch.conf、hostname，均 world-readable |
| `/proc/self` | `read` | 目录级 | 进程自身信息（maps、environ、fd、net 等）。通过 O_PATH open + landlock_add_rule 实现 |
| `/proc/filesystems` | `read` | 文件级 | libselinux 初始化读取内核支持的文件系统列表 |
| `/proc/1/mounts` | `read` | 文件级 | libselinux 初始化读取挂载表，ns 内只有沙箱自身挂载 |
| `/proc/loadavg` | `read` | 文件级 | 系统负载 |
| `/proc/uptime` | `read` | 文件级 | 系统启动时间 |
| `/proc/stat` | `read` | 文件级 | CPU 统计 |
| `/proc/cpuinfo` | `read` | 文件级 | CPU 型号和核数 |
| `/proc/meminfo` | `read` | 文件级 | 内存使用量 |
| `/proc/version` | `read` | 文件级 | 内核版本 |
| `/proc/devices` | `read` | 文件级 | 设备号列表 |
| `/sys` | `read` | 目录级 | 暴露硬件/内核信息但有兼容性需求（lscpu 等），优先兼容 |
| `/dev/null` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/zero` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/full` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/random` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/urandom` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/tty` | `read+write+truncate` | 文件级 | 标准设备，沙箱自建 |
| `/dev/shm` | `read+write+truncate` | 目录级 | 沙箱自建 tmpfs，共享内存用 |
| `/dev/pts` | `read+write+truncate` | 目录级 | 伪终端 |
| `/tmp` | `read+write+truncate` | 目录级 | 沙箱自建 tmpfs，进程工作目录 |

