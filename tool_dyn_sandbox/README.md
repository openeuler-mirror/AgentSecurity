# Agent Tool 动态沙箱

基于 Linux 内核隔离机制（Landlock + seccomp + mount namespace + network namespace）的沙箱执行工具，为 AI agent 的 tool 执行提供细粒度隔离和运行时权限动态放宽。

## 功能特性

- **文件系统隔离** — mount namespace + pivot_root 到独立 tmpfs，沙箱间完全隔离
- **文件访问控制** — Landlock LSM 提供读/写/执行/删除/截断的路径级权限
- **网络隔离与管控** — network namespace + nftables，支持 CIDR 和域名白名单
- **系统调用过滤** — seccomp-bpf 白名单，预置 default/file_access/script 三档 profile
- **非 root 执行** — user namespace 获取内部权限，无需 sudo/setuid
- **运行时提权** — 捕获文件landlock拦截事件，动态决策后放行或拒绝，业务无感重试

## 架构

```
                   dyn-sandbox
          ┌──────────────────────────────┐
          │  父进程 (monitor)             │
          │    ├── poll 循环             │
          │    ├── 转发 stdio            │
          │    └── 动态授权决策          │
          ├── 子进程 (exec) ─────────────┤
          │    ├── netns / pivot_root    │
          │    ├── Landlock / seccomp    │
          │    └── execve tool           │
          └──────────┬───────────────────┘
                     │ ioctl
               dyn_sandbox.ko (内核模块)
          ┌──────────────────────────────┐
          │  网络: veth + nftables       │
          │  文件: kprobe + 动态放权    │
          └──────────────────────────────┘
```

## 快速开始

```bash
# 加载内核模块
sudo insmod driver/dyn_sandbox.ko

# 基本命令
dyn-sandbox --mount /usr:ro --seccomp default -- echo hello

# 脚本执行
dyn-sandbox --mount /usr:ro --mount-tmpfs /tmp:64 \
  --seccomp script -- bash -c "echo hello > /tmp/greet && cat /tmp/greet"

# 网络访问
dyn-sandbox --mount /usr:ro --seccomp script \
  --domain github.com -- curl -s https://github.com
```

## 编译

```bash
# 内核模块 (需在目标内核版本上编译)
make -C driver

# dyn-sandbox 二进制
make -C dyn-sandbox

# 全部
make
```

## 系统要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Linux 内核 | >= 5.13 | Landlock ABI 1 |
| `CONFIG_USER_NS=y` | | user namespace |
| `CONFIG_NET_NS=y` | | network namespace |
| `CONFIG_SECCOMP_FILTER=y` | | seccomp-bpf |
| `CONFIG_SECURITY_LANDLOCK=y` | | Landlock LSM |
| `CONFIG_KPROBES=y` | | 运行时提权 |
| `CONFIG_NF_TABLES=m` | | nftables 规则 |
| nsenter (util-linux) | | netns 命令执行 |
| nft (nftables) | | nftables 规则配置 |

## 项目结构

```
├── dyn-sandbox/          # 沙箱用户态二进制
│   ├── dyn-sandbox.c     # 主逻辑
│   ├── seccomp_profiles.c # seccomp BPF profile
│   ├── landlock.c        # Landlock 规则管理
│   ├── policy_parser.c   # YAML 策略解析
│   └── param_parse.c     # CLI 参数解析
├── driver/               # 内核模块 dyn_sandbox.ko
│   ├── sandbox_main.c    # 字符设备 /dev/dyn-sandbox
│   ├── sandbox_net.c     # 网络管理 (veth/nftables)
│   ├── sandbox_file.c    # 文件动态授权 (kprobe)
│   └── sandbox_landlock.c # Landlock 内核辅助
├── dyn-sandbox-dns/        # DNS 代理 (域名白名单)
├── test/                 # 集成测试
└── docs/                 # 设计文档
    ├── dyn-sandbox-design.md  # 详细设计
    └── usage-guide.md         # 使用指南
```

## 详细文档

- [使用指南](docs/usage-guide.md) — CLI 参数、YAML 策略、使用示例
- [设计文档](docs/dyn-sandbox-design.md) — 架构、流程、接口、依赖

## 附录

- [使用指南](docs/usage-guide.md) — CLI 参数参考、YAML 策略格式、场景示例
- [默认沙箱策略](docs/default-landlock-permissions.md) — 根文件系统布局、Landlock 默认权限集
