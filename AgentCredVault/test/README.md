# 系统级测试用例

本目录放需要真实环境（root、libvirt 客户机、外网）的用例。`crates/*/tests/` 是 Rust 集成测试，
随 `cargo test` 运行；这里的用例不在 `cargo test` 中执行。

| 用例 | 形态 | 断言的目标 |
|---|---|---|
| `e2e-vm-transparent.sh` | libvirt guest 经 `nat PREROUTING` DNAT 到宿主机非 loopback 监听；真实公网 HTTPS；真实 CA 信任链 | VM 内只持有 fakecred 的客户端完成 HTTPS 请求，宿主机侧替换为真实值；未绑定域名原样透传；`SO_ORIGINAL_DST`、内层 Host≠目标、直连监听、非 443、审计不含真实值 |
| 同上，git over HTTPS 段 | guest 内 `git clone` 公开仓库后本地提交，再用 fakecred 作 Basic 密码推送新分支 | clone 走匿名透传；push 的 Basic 密码被替换；有真实凭据时 push 成功、无凭据时上游 401；审计分别记录 `substitute`；真实凭据不出现在 daemon 日志 |

捕获规则由 `credproxyd` 启动时安装：只创建 `CREDSVAULT_PREROUTING` 链和一条 443 DNAT，
转发、宿主访问和 SNAT 保持由 libvirt/CNI/运维现有配置负责。安装失败则拒绝启动；停止或崩溃
保留规则，只有 `credproxyd uninstall-capture` 显式删除。用例的 cleanup 会执行该命令。

## 前置条件

- root（宿主机 netfilter、客户端信任库安装）。
- 已存在的 libvirt 网络与 guest，默认 `virbr-cpb` / `192.168.56.0/24` / `root@192.168.56.26`，
  SSH 私钥 `~/.ssh/id_ed25519`；guest 有 `curl` 与 `update-ca-trust`。
- 宿主机与 guest 都能访问外网。
- 二进制用 `--features credproxyd/test-hooks` 构建：用例用 `--state-file` / `--lock-file` 把
  daemon 自身配置（CA）与实例锁隔离到临时目录，不读写 `/var/lib/credsvault`；透明监听地址、
  捕获参数都经 bootstrap 配置交给 daemon（`listen_transparent` / `capture` 段），
  端口自动选空闲端口。

## 运行

```sh
cargo build --release --features credproxyd/test-hooks --workspace
sudo test/e2e-vm-transparent.sh
```

环境变量：`BRIDGE`、`SUBNET`、`GW`、`VM_LISTEN`、`GUEST`、`GUEST_KEY`、`BOUND_HOST`、
`UNBOUND_HOST`、`BIN_DIR`、`RUN_DIR`。

git 段默认用 `GIT_HOST=atomgit.com`、`GIT_PATH=/yinxyww/itrustee_tzdriver.git`、
`GIT_USER=yinxyww`，推到 `GIT_BRANCH=credproxy-e2e/<UTC 时间戳>` 并保留。`GIT_CRED_FILE`
指向 `GIT_USER` 的访问令牌或密码文件时，push 预期成功；不设置时该凭据写入随机无效值，
push 预期被上游拒绝（401），只验证替换路径。凭据只经 `--value-file` 进入 vault，guest
只拿 fakecred。

脚本内置了一个测试用的 DeepSeek key（`DS_API_KEY`，按部署者要求硬编码，随仓库分发；
仓库共享时应在提交前移除并轮换）。该 key 会被写入工作目录下的
0600 文件、经 `--value-file` 进入临时 vault，跑完在 cleanup 中删除。脚本因此在
`api.deepseek.com` 上跑：有效凭据 → 200（替换）、无效凭据 → 401（替换后由上游拒绝）、
未注册 token → 401（原样透传）、真实 key 经捕获 → 200（透传）、真实 key 直连 → 200，以及
guest 内一次 `curl` chat completion（真实模型输出）；`DS_CHAT_MODEL` 选择聊天用例的模型。
脚本不打印 key，guest 侧真实 key 用例经 ssh stdin 写入 0600 头文件并在请求后删除。

`CREDPROXY_TEST_KEEP=1` 在成功时保留工作目录；失败时总是保留。
