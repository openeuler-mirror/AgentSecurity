# dyn-sandbox 使用文档

## 1. 概览

`dyn-sandbox` 是一个基于 Linux 内核隔离机制（Landlock + seccomp + mount namespace + network namespace）的沙箱执行工具。它在执行目标命令前，按配置策略限制其对文件系统、系统调用和网络的访问。

基本用法：

```
dyn-sandbox [选项...] -- command [参数...]
```

`--` 后的部分作为目标命令及其参数，之前的部分为沙箱配置选项。

## 2. 快速开始

最小用例（仅 seccomp default profile）：

```
dyn-sandbox --seccomp default -- echo hello
```

Bind mount + seccomp profile：

```
dyn-sandbox --mount /usr:ro --seccomp default -- ls /
```

YAML 策略文件：

```
dyn-sandbox --policy mypolicy.yaml -- echo hello
```

调试输出（打印配置后退出，不启动沙箱）：

```
dyn-sandbox --mount /usr -D
```

## 3. CLI 参数参考

| 选项 | 短选项 | 参数格式 | 默认值 | 约束 | 说明 |
|------|--------|---------|--------|------|------|
| `--mount` | 无 | `/src[:ro\|rw]` | ro | 最多 32 个（含 `--mount-tmpfs`） | Bind mount 主机目录到沙箱; 默认只读，指定 `:rw` 可读; 支持逗号分隔多值 |
| `--mount-tmpfs` | 无 | `/path[:MB]` | 256 MB | 最多 32 个（含 `--mount`） | 挂载 tmpfs。size 省略或 `:0` = 默认 256 支持逗号分隔多值 |
| `--tmpfs-size` | 无 | MB | 256 | — | 单独指定 `/tmp` tmpfs 大小；`0` 亦为默认 256（解析物化为 256） |
| `--landlock` | 无 | `/path:perm1+perm2` | 仅路径，无权限 | 最多 64 条 | Landlock 路径访问规则。不支持 `~` 或环境变量展开 |
| `--seccomp` | 无 | profile | — | 与 `--seccomp-syscalls` 互斥；只能设置一次 | 使用预置 seccomp profile。可选值：`default` / `file_access` / `script` |
| `--seccomp-syscalls` | 无 | syscall1,syscall2,... | — | 与 `--seccomp` 互斥；累计 ≤511 字符 | 自定义 syscall 白名单，逗号分隔。重复 = 追加合并（union，对齐 YAML `syscalls` 追加语义），超长报 `too long` |
| `--domain` | 无 | domain | — | 最多 16 个，单个最长 127 字符 | DNS 域名白名单，可重复或逗号分隔多值（空段一律拒绝，同 `--mount` 多值形式） |
| `--cidr` | 无 | x.x.x.x/prefix | — | 最多 16 个，prefix 1-32（`/0` 拒绝：会放行全部流量） | IP CIDR 白名单，可重复或逗号分隔多值（空段一律拒绝，同 `--mount` 多值形式）；地址须标准点分十进制（`inet_pton` 校验，拒绝简写 `10/8`、八进制、越界段如 `10.0.0.999`，畸形一律报 `invalid CIDR address`） |
| `--policy` | 无 | file | — | 与所有 CLI 参数互斥 | 从 YAML 策略文件加载完整配置 |
| _（工作目录）_ | `-c` | /path | `/` | 只能设置一次 | 设置命令工作目录（重复报 `conflicting -c workdir`） |
| `--dump-config` | `-D` | — | — | 豁免互斥检查 | 打印 `sandbox_config` 所有字段后退出，不启动沙箱 |

### 互斥规则

- `--policy` 不能与任何其他 CLI 选项混用（`-D` 豁免）
- `--seccomp` 和 `--seccomp-syscalls` 互斥
- 互斥检查在参数解析阶段进行，早于文件读取

## 4. YAML 策略参考

### 完整格式

```yaml
name: write_file           # 工具名
version: 1                 # 策略版本

mount:                     # 挂载策略（可见集）
  - type: bind             # bind | tmpfs
    src: /usr              # bind 只收 src；沙箱内目标恒 = src
    readonly: true         # bind 时是否只读
  - type: tmpfs
    dest: /tmp             # tmpfs 只收 dest（无 src）
    size: "100MB"          # tmpfs 大小

landlock:                  # 文件访问策略（精确路径，不存在则跳过）
  - path: /usr/bin
    access: [execute, read]
  - path: /usr/lib
    access: [read]
  - path: /tmp
    access: [read, write, remove, truncate]

network:                   # 网络策略（mode: filter 默认 reject 未匹配地址）
  mode: filter             # filter | isolate | share（缺省按列表推导）
  domains:                 # DNS 域名白名单（仅 mode: filter 使用）
    - example.com
    - github.com
  cidrs:                   # IP CIDR 白名单（仅 mode: filter 使用）
    - 10.0.0.0/8

seccomp:                   # seccomp 策略（profile 和 syscalls 互斥）
  # profile: script        # default | file_access | script
  syscalls: [read, write, open, close, mmap, exit_group]  # 自定义白名单
```

### mount 条目

| 字段 | 适用类型 | 必须 | 类型 | 默认值 | 说明 |
|------|---------|------|------|--------|------|
| `type` | 两者 | 推荐 | 字符串 | bind | `bind` 或 `tmpfs` |
| `src` | bind | 是 | 字符串 | — | 主机路径（bind 的沙箱内目标） |
| `dest` | tmpfs | 是 | 字符串 | — | tmpfs 挂载目标路径 |
| `readonly` | bind | 否 | 布尔 | true | `false` = 可读写 |
| `size` | tmpfs | 否 | 整数 | 256 | tmpfs 大小（MB） |

- bind `src` / tmpfs `dest` 必须以 `/` 开头，不含 `..`、`.`、`//`、尾部 `/`，且不得命中内部停泊根 `/oldroot`（防止经沙箱内部停泊根叠层逃逸）
- tmpfs 条目不应设置 `readonly` 字段（默认可读写）
- `/tmp` 的 tmpfs 由程序内部自动创建，`--mount-tmpfs /tmp:xxx` 仅修改其大小
- 未识别键（字段拼错、或旧版设计文档遗留的 `network.enabled`——网络开关现由 `mode` 表达）一律报 `policy: unknown key`；策略文件只接受上表与下列各节的键
- 同一 dest 只能挂载一次
- CLI `--mount` / `--mount-tmpfs` / `--domain` / `--cidr` 都支持单参数逗号分隔多值（`--mount "/a:ro,/b:rw"`、`--mount-tmpfs "/d1:100,/d2:200"`、`--domain "a.com,b.com"`、`--cidr "10.0.0.0/8,192.168.0.0/16"`）；逗号是保留分隔符，值内不得含 `,`；空段（前导/中间连续/尾逗号）一律拒绝，逗号必须严格分隔非空条目

### landlock 条目

| 字段 | 必须 | 类型 | 说明 |
|------|------|------|------|
| `path` | 是 | 字符串 | 路径，支持目录前缀匹配 |
| `access` | 否 | 列表 | 权限列表，不指定时仅绑定路径无额外权限 |

权限用列表格式 `[read, execute]`，对应 CLI 的 `read+execute` 语法。

### network 配置

| 字段 | 必须 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `mode` | 否 | 字符串 | 推导 | `filter` / `isolate` / `share`，见下 |
| `domains` | 否 | 字符串列表 | — | DNS 域名白名单，dyn-sandbox-dns 仅放行匹配域名 |
| `cidrs` | 否 | 字符串列表 | — | IP CIDR 白名单，直接加入 nftables 放行集合。地址须标准点分十进制、prefix 1-32，畸形（越界段/非数字/简写）一律报 `invalid CIDR` |

`mode` 取值：

| mode | 语义 | domains/cidrs |
|------|------|---------------|
| `filter` | 建 veth + nftables 白名单过滤 | 需要（未匹配流量被 reject） |
| `isolate` | 完全无网络（空 netns，无 veth、无 DNS） | 禁止，同时配置会报错 |
| `share` | 共享宿主网络命名空间与 DNS | 禁止，同时配置会报错 |

- 未写 `mode` 时自动推导：有 domains/cidrs → `filter`；否则 `isolate`
- 未匹配任何 domain/cidr 的流量被 nftables reject（ICMP unreachable）

### seccomp 配置

`profile` 和 `syscalls` 互斥，只能选其一。

| 字段 | 类型 | 说明 |
|------|------|------|
| `profile` | 字符串 | 预置 profile 名：`default` / `file_access` / `script` |
| `syscalls` | 字符串列表 | 自定义 syscall 白名单，如 `[read, write, openat]` |

## 5. CLI ↔ YAML 等价性说明

以下两组配置产生相同的 `sandbox_config`：

| CLI | YAML |
|-----|------|
| `--mount /usr:ro` | `mount: [{type: bind, src: /usr}]`（readonly 默认 true） |
| `--mount /data:rw` | `mount: [{type: bind, src: /data, readonly: false}]` |
| `--mount-tmpfs /data:128` | `mount: [{type: tmpfs, dest: /data, size: 128}]` |
| `--landlock /usr:read+execute` | `landlock: [{path: /usr, access: [read, execute]}]` |
| `--domain a.com,b.com` | `network: {domains: [a.com, b.com]}` |
| `--cidr 10.0.0.0/8,192.168.0.0/16` | `network: {cidrs: [10.0.0.0/8, 192.168.0.0/16]}` |
| `--share-net` | `network: {mode: share}` |
| `--seccomp default` | `seccomp: {profile: default}` |
| `--seccomp-syscalls read,write` | `seccomp: {syscalls: [read, write]}` |

**互斥规则**：`--policy` 不能与任何 CL 选项混用（`-D` 豁免）。如果已有 CLI 参数，再指定 `--policy` 会报错退出；反之亦然。


## 6. 使用示例

### 运行基本命令

```
dyn-sandbox --mount /usr:ro --mount /etc:ro --seccomp default -- cat /etc/hostname
```

### 执行脚本

需要 read+execute 权限访问二进制和动态库，使用 `script` profile：

```
dyn-sandbox --mount /usr:ro --mount-tmpfs /tmp:64 \
  --seccomp script -- bash -c "echo hello > /tmp/greet && cat /tmp/greet"
```

### 自定义 syscall 白名单

只放行必要的 syscall，其余全部 deny（返回 EPERM）：

```
dyn-sandbox --seccomp-syscalls write,exit_group -- /bin/echo hello
```

### 文件读写 + Landlock 精确权限

`--mount /tmp:rw` 让 tmpfs 可读写，`--landlock` 精确定义 `/tmp` 内允许写：

```
dyn-sandbox --mount /usr:ro --mount /tmp:rw \
  --landlock '/tmp/**:read+write' --seccomp file_access \
  -- touch /tmp/testfile
```

### 网络访问 + 域名白名单

使用 `script` profile（含 socket/connect 等网络 syscall）：

```
dyn-sandbox --mount /usr:ro --seccomp script \
  --domain github.com -- curl -s https://github.com
```

### CIDR 白名单

只允许访问特定网段：

```
dyn-sandbox --mount /usr:ro --seccomp script \
  --cidr 10.0.0.0/8 -- ping -c 1 10.0.0.1
```

### 运行时提权（Landlock 动态放宽）

工具试图写入未授权的路径时，父进程输出 `AUTH_REQ` 并等待 stdin 决策：

```
dyn-sandbox --mount /usr:ro --mount /tmp:rw \
  --landlock '/tmp/**:read+write' --seccomp script \
  -- bash -c "echo 'try write' > /tmp/allowed.txt"
```

### 工作目录

```
dyn-sandbox --mount /usr:ro --mount-tmpfs /tmp:64 \
  -c /tmp --seccomp script -- pwd
```

### 完全隔离（无网络）

```
dyn-sandbox --mount /usr:ro --seccomp script -- ip link
```

### 组合：网络 + 文件 + 自定义 syscall

```
dyn-sandbox --mount /usr:ro --mount /tmp:rw \
  --landlock '/tmp/**:read+write' \
  --domain example.com --cidr 93.184.216.0/24 \
  --seccomp-syscalls read,write,openat,close,mmap,brk,exit_group,socket,connect,sendto,recvfrom \
  -- curl -s http://example.com
```


## 7. 附录

### Landlock 权限表

`ll_add_rule_str()` 对**非目录路径**自动屏蔽目录专用位（`READ_DIR` / `MAKE_REG` / `MAKE_DIR` / `REMOVE_FILE` / `REMOVE_DIR`）。

| 权限名 | 作用于目录的 flag | 作用于文件的 flag |
|--------|-----------------|-----------------|
| read | `READ_FILE \| READ_DIR` | `READ_FILE` |
| write | `WRITE_FILE \| MAKE_REG \| MAKE_DIR` | `WRITE_FILE` |
| execute | `EXECUTE` | `EXECUTE` |
| remove | `REMOVE_FILE \| REMOVE_DIR` | （无，内核不接受文件级 remove） |
| truncate | `TRUNCATE` | `TRUNCATE` |

目录规则是路径前缀匹配，权限向下作用于子树中的所有文件。

### Seccomp profile 说明

| Profile | Syscall 数量 | 说明 | 典型用途 |
|---------|-------------|------|---------|
| default | ~31 | 保守白名单，含 glibc 启动必需 + 基本文件 IO + 信号 | 运行基本命令（`ls`, `echo`, `cat`） |
| file_access | ~28 | 含 execve + mprotect + access，可运行动态链接的文件工具 | 文件读写工具 |
| script | ~75 | 含进程管理 + 网络 socket + 文件系统查询 + 时间，支持 shell/Python | 脚本执行（bash, python3） |

自定义 syscall 白名单通过 `--seccomp-syscalls` 或 `seccomp.syscalls` 指定，支持的 syscall 名称见 `seccomp_profiles.c` 的 `syscall_names` 映射表（约 80 个常见 syscall）。

### 约束汇总

| 资源 | 最大值 | 说明 |
|------|--------|------|
| mount 条目 | 32 | 含 bind 和 tmpfs 合计 |
| landlock 规则 | 64 | — |
| 域名白名单 | 16 | 每个不超过 127 字符 |
| CIDR 白名单 | 16 | prefix 范围 0-32 |
| 自定义 syscall | 128 | — |
| seccomp profile | 3 种预置 | default / file_access / script |
| YAML 嵌套深度 | 32 层 | 超出报错 |
