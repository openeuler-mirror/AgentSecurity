# 按用户选择性接入透明捕获的方案分析

> 分析对象：conch 沙箱透明捕获（见 `docs/conch-transparent-capture.md`）在多用户场景下的门控。
> 问题：一个沙箱由一个用户使用，只让“已配置用户”的沙箱进入透明捕获，未配置用户的流量不能经过代理。
> 证据口径：【实测】本次命令输出；【代码】当前仓库代码；【文档】本目录既有分析；【推断】由前两者推出，未实测；【未验证】没有证据。

## 0. 结论摘要

1. **数据面没有“用户”。** IP/TCP 头只有五元组，TLS ClientHello 只有 SNI，HTTP 里的 fakecred 是凭据句柄，都不是用户身份。按用户选择必须在控制面完成，再映射成网络位置或逐连接策略。
2. **当前系统没有可信的“用户→沙箱”绑定。** `user_id` 是客户端自报（【文档】`agentos-auth-identity-analysis.md:20-23, 526`）；conch 沙箱对象没有 user 字段（【实测】`conch sandbox create --help`、`conch sandbox ls` 表头）；jiuwenbox 只提供沙箱对象（`id` / `ip_address` / `pid`，【文档】同文件 `:529`）。
3. **策略键是用户，执行形态是 IP。** 捕获配置以 `user_id` 为键；credproxy 把“已配置用户”当前持有的宿主可见源地址映射成 `/32` DNAT 规则。未配置用户的地址没有规则，流量直接出网。数据面（iptables）只认地址，用户身份只存在于控制面的用户↔IP 租约里。
4. **“按用户”需要平台先补身份链**：开启 IAM、把认证结果写回连接（【文档】`:20-23`，当前无调用方）、并在创建沙箱时把认证身份写入用户↔沙箱绑定。在此之前只能由操作员维护“已配置用户”集合，无法可信地判断某个沙箱属于谁。
5. **捕获门控不是授权边界。** 捕获只决定“是否经过 daemon”；某个沙箱能否获得替换仍由 credproxyd 的 credential→binding 决定。若要防 fakecred 跨用户冒用，凭据绑定也应使用与策略键一致的维度（用户），并用沙箱身份/源地址做归属校验；这是独立于捕获门控的一层。

## 1. 问题定义

### 1.1 两个必须分开的问题

**问题 A：免打扰。** 未配置用户的沙箱如果被 DNAT 到 credproxyd，daemon 会用私有 CA 终止 TLS（`crates/credproxyd/src/proxy.rs:354-380` 对所有被接受的连接调用 `serve_mitm`）。客户端不信任该 CA 时 TLS 校验失败，表现为 HTTPS 全断（【推断】私有 CA 不在客户端信任库时必然失败，本次实验未做“不装 CA”的对照）。所以“未配置用户不受影响”等价于“不要把他们的连接 DNAT 过去”。

**问题 B：防冒用。** 即使只捕获已配置用户，fakecred 仍是 bearer 值：任何拿到 fakecred 的进程都能让 daemon 替换。当前 `credential add --agent conch-agent` 的 agent 名由操作员声明，不来自沙箱身份，因此不能区分沙箱。问题 B 不能靠捕获门控解决。

### 1.2 为什么“用户”不在数据面

- iptables 能匹配的字段是接口、源/目的地址、端口、协议、mark 等；没有“用户”字段。
- TLS 的 SNI 是目的主机名，不是发起者身份。
- 请求里的 fakecred 是 daemon 签发的凭据句柄，不是用户身份；它回答“替换成哪个真值”，不回答“这是谁”。
- 因此任何按用户的方案都必须先把用户身份落到一个数据面可判定的属性上（源 IP、mark、连接级策略），而这个映射必须由控制面写入。

### 1.3 当前身份链的事实

| 身份锚点 | 是否可信 | 能否区分用户 | 依据 |
|---|---|---|---|
| `user_id`（query / `X-User-Id`） | 否 | 名义上可以，实际任意声明 | 【文档】`agentos-auth-identity-analysis.md:20-23, 526` |
| IAM 认证结果 | 认证本身可信；但默认关闭，且结果未写回连接 | 不能（当前） | 【文档】同上 `:13-18, 20-23` |
| `instance_id` | 否，是可枚举的 bearer capability | 不能单独作归属 | 【文档】同上 `:25-27, 537-538` |
| conch `sandbox_id` | 是（对象存在性由 conchd 维护） | 区分沙箱，不区分用户 | 【实测】`conch sandbox ls` 列：ID/TEMPLATE_NAME/TEMPLATE_ID/CPU/MEMORY_MB/STARTED_AT；create 选项无 user |
| jiuwenbox `id` / `ip_address` / `pid` | 是（jiuwenbox-server 以 root 管理沙箱） | 区分沙箱，不区分用户 | 【文档】`:49, 529` |
| slot IP（`10.12.1.x`） | 是（网络位置） | 区分 slot；与沙箱对象关联后区分沙箱 | 【实测】slot netns 地址表；LOG `SRC=10.12.1.55` |
| guest 内 uid 1001 | 是（进程属性） | 所有沙箱同一 uid，不能区分用户 | 【文档】`:52, 532` |

**结论**：当前可用的可信锚点是“沙箱对象 + slot IP”；“用户”不是可信属性。按用户做门控的前提是把这个属性补出来。

## 2. 约束

1. **DNAT 必须在宿主 netns。** credproxyd 在宿主 netns 用 `SO_ORIGINAL_DST` 取 DNAT 前的目的（`crates/credproxyd/src/ingress.rs:71-109`，调用点 `proxy.rs:359-380`）。若在 slot netns 内做 DNAT，宿主 conntrack 里没有那条原始目的，daemon 无法恢复公网目标。
2. **规则只能匹配 TCP 443。** UDP/443（QUIC）和 IPv6 不在当前规则覆盖内（见 `docs/conch-transparent-capture.md` 第 6 节）。
3. **捕获点对源地址的信任来自 slot netns 的 NAT。** 宿主看到的是 slot netns 地址，不是 guest 地址；若 guest 能伪造 `10.12.1.x` 源地址绕过 slot 的 SNAT，按 IP 门控就会被绕过——这一点未验证。
4. **规则生命周期与沙箱生命周期不一致会错捕。** slot IP 在 slot 上复用；沙箱 A 的遗留规则会捕获之后调度到同一 slot 的沙箱 B（【推断】依据：slot netns 与地址持久存在，当前无沙箱时 100 个 slot 仍有地址）。
5. **未配置用户不能经过 daemon。** 一旦经过，就必须解决 CA 分发，否则断网。

## 3. 方案空间

### 3.1 方案 A：按 slot IP `/32` 门控（推荐）

**机制**：把当前的 `-s 10.12.0.0/20` 收窄为已配置用户当前租约地址的 `-s <slot-ip>/32`：

```sh
iptables -t nat -I PREROUTING 1 -i cni-conch0 -s 10.12.1.51/32 -p tcp --dport 443 \
  -j DNAT --to-destination 10.12.0.1:<port>
```

不在规则集合里的地址没有匹配规则，流量按原路由直接出网，不经过 daemon，也不需要 CA。

**决策源**：credproxy 管理面维护已配置用户集合 `C`；用户↔IP 租约集合 `B` 由 AgentOS 的 `created` / `deleted` 事件维护（第 6 节）。实际下发的规则集合是 `{b.source_ip | b ∈ B 且 b.user_id ∈ C}`。规则与 IP 一一对应，用户身份不进入 iptables。

**时序**（决定成败）：

1. 创建路径以认证用户身份创建沙箱，拿到宿主可见的 slot IP。
2. AgentOS 发出 `created(user_id, source_ip, binding_id)`；credproxy 记录租约；若 `user_id ∈ C`，插入该 IP 的 `/32` 规则。
3. 规则就绪后，才允许该用户的 `exec` / 业务流量。未配置用户不插入规则，也不需要这个 gate。

第 2 步必须在第 3 步之前完成，否则沙箱启动后到规则生效前的连接会直连（nat 表只对连接首包生效，事后补规则不会改写已建立连接）。可行的接入点：AgentOS 在创建返回前同步调用 credproxy；credproxy 返回规则已就绪后，AgentOS 再向用户开放。

**删除与 IP 复用**：`deleted(user_id, source_ip, binding_id)` 删除该租约；若删除后没有其它存活租约使用这个 IP，撤掉该 IP 的规则。若同一个 IP 被新的 `created` 租约接管（旧租约的 `deleted` 丢失或晚到），以新租约的归属为准：先撤旧用户对该 IP 的规则，再按新用户是否在 `C` 中决定是否插入。每条规则用 `-m comment --comment "credproxy:user=<uid>:binding=<id>"` 标记，便于精确删除和审计关联。无快照时的恢复语义见 6.3。

**失败模式**：

- 规则插入失败：已配置用户的流量直连，fakecred 不会被替换，表现为 401/凭据无效。`created` 应返回错误，AgentOS 重试或阻止该沙箱使用需要替换的凭据，不能静默。
- 规则删除失败：后续复用同一 IP 的未配置用户被错误捕获，TLS 失败。下一次该 IP 的 `created` 接管会清除它（前提是事件覆盖所有沙箱，见 6.2）。
- 事件源不可用：不再新增捕获；持久化的已有规则保留。对新沙箱表现为“未捕获”。

**优点**：未配置用户完全不受影响；策略按用户表达，一个用户的多个沙箱自动覆盖；不需要改 daemon；规则可审计。
**缺点**：规则随租约增删；依赖事件时序与投递；同一 IP 复用带来遗留规则风险；捕获粒度是源 IP，共享沙箱内无法区分不同用户。

### 3.2 方案 B：全量捕获 + daemon 连接级策略

**机制**：保留 `/20` 规则，daemon 按源 IP 查“已配置用户的当前租约地址集合”：集合内走 `serve_mitm`，集合外做原始 TCP 转发（`copy_bidirectional`，不终止 TLS）。

**现状差距**：`handle_transparent_conn` 取到 `original_dst` 后无条件调用 `serve_mitm`（`proxy.rs:354-380`），没有原始转发分支；需要新增代码和租约地址集合查询。

**优点**：宿主规则静态；策略可在线变更；不用管沙箱创建时序。
**缺点**：未配置沙箱的流量仍然经过 daemon——不满足“不要都用代理”的字面要求，且 daemon 故障会波及所有人；daemon 需要信任源 IP→沙箱映射；实现量大于方案 A。

### 3.3 方案 C：全量捕获 + daemon 拒绝租约集合外的源

不可接受：未配置用户的 HTTPS 直接断，且 daemon 成为所有沙箱的单点。

### 3.4 方案 D：slot 内 MARK + 宿主静态规则（变体）

**机制**：在所选 slot 的 netns 里给 443 流量打 mark（`-t mangle -A OUTPUT ... -j MARK --set-mark`），宿主只保留一条静态规则 `-m mark --mark <值> -p tcp --dport 443 -j DNAT ...`。DNAT 仍在宿主 netns，`SO_ORIGINAL_DST` 不受影响。

**优点**：宿主规则集固定，增删捕获对象只改 slot netns 的一条 mark 规则；规则数量不随沙箱数增长。
**缺点/未验证**：skb mark 跨 netns 是否保持未实测；mark 值可能与 CNI/其它工具的 mark 冲突；slot netns 的规则同样随 slot 复用，生命周期问题与方案 A 相同；仍需改一个 root 组件去写 slot netns。

### 3.5 方案 E：按用户/租户做网络分段

**机制**：每个用户（或租户）一个网桥/子网/slot 组，宿主按 `-i` 或 `-s <段>` 匹配。

**优点**：网络层隔离最干净；规则数量与用户数成正比，不与沙箱数成正比；天然支持按用户审计。
**缺点**：需要改 conch/CNI 的地址分配与网桥布局，改动最大；当前一个 `cni-conch0` + `10.12.0.0/20` 承载所有 slot（【实测】）。

### 3.6 方案 F：显式代理（opt-in）

**机制**：只给已配置沙箱注入 `HTTPS_PROXY` / git `http.proxy`，指向一个普通 CONNECT 代理；不做 DNAT。未配置沙箱没有代理配置，直连。

**优点**：完全没有 iptables 与 CA 分发问题；未配置用户零影响；把代理变量注入该用户的沙箱即可。
**缺点**：不透明，依赖应用遵守代理变量（git/curl 遵守，部分程序不遵守）；用户可在沙箱内取消变量绕过；代理必须做鉴权（源 IP 白名单或每沙箱 token），否则任何能连到代理的进程都能用。

### 3.7 方案 G：只靠凭据层，不做捕获门控

**机制**：所有沙箱都捕获，只有已配置的沙箱有凭据；未配置的没有 fakecred，请求原样透传。

**问题**：未配置沙箱仍会被 MITM，客户端不信任 CA 就断网；“原样透传”发生在 TLS 终止之后，不是连接级直通。不满足问题 A。

### 3.8 对比

| 方案 | 作用层 | 未配置沙箱是否经过 daemon | 需要改 daemon | 主要成本 | 主要风险 |
|---|---|---|---|---|---|
| A | 宿主 nat | 否 | 否 | 规则生命周期 + 事件时序 | 遗留规则错捕复用同一 IP 的其它用户 |
| B | daemon | 是（原始转发） | 是 | 新增 relay + 租约地址集合查询 | 单点、源 IP 信任 |
| C | daemon | 是（拒绝） | 否 | 无 | 未配置用户断网 |
| D | slot mangle + 宿主 nat | 否 | 否 | slot 规则管理 | mark 跨 netns 未验证 |
| E | conch/CNI | 否 | 否 | 网络架构改造 | 改动面最大 |
| F | 应用/代理 | 否 | 否（新代理） | 应用配合 + 代理鉴权 | 非透明、可绕过 |

## 4. “某个用户”的决策权

捕获的**策略**按用户配置，**执行**按 IP 下发规则。这是两个不同的问题：谁决定某个用户是否被捕获；谁证明某个 IP 现在属于该用户。

| 决策/证据 | 可信性 | 现状 | 结论 |
|---|---|---|---|
| 操作员在 credproxy 管理面维护已配置用户集合 `C` | 可信（admin 角色，SO_PEERCRED） | 需新增命令/配置 | v1 的策略来源 |
| 创建路径断言 `(user_id, sandbox_id, source_ip)` | 取决于创建路径上的身份认证 | 沙箱对象无 user 字段；创建请求无 user 字段 | 必须补；这是绑定可信性的来源 |
| jiuwenbox 沙箱策略 | 进程可信，但 UDS `0666`，任何本地进程可调用；且策略没有 user 字段 | 策略只有文件系统/网络 allow/deny（【实测】`/var/lib/jiuwenbox/jiuwenbox-policy.yaml:211-245`） | 可作为“是否捕获”的开关，但不能证明用户 |
| IAM + 网关写回 + 创建时绑定 | 认证可信 | IAM 默认关闭；认证结果未写回连接（【文档】`:20-23`） | 需要平台改动，长期方案 |

**因此**：

- v1 的捕获集合是“操作员配置的用户集合 `C`”与“事件维护的用户↔IP 租约”的交集：只有 `C` 中用户的地址被下发规则。
- `user_id` 不能来自 query/header；必须来自创建路径上的认证结果，并由可信进程写入事件。仅从 query/header 取 `user_id` 不构成绑定（【文档】`:526`）。
- 如果“一个沙箱由一个用户使用”这个前提不成立（工具沙箱可能被多个会话共用），按用户门控只能按归属用户决定整个沙箱是否被捕获，不能在同一沙箱内区分用户；需要先确认沙箱的分配粒度。

## 5. 推荐的 v1 取舍

1. **策略键用 `user_id`**：credproxy 管理面维护已配置用户集合 `C`，不维护“沙箱名单”。
2. **执行用 `/32`**：规则集合是 `C` 中用户当前存活租约的源地址并集；每个地址一条 DNAT 规则；不在集合里的地址不经过 daemon。
3. **绑定来源用 AgentOS 的两个事件**：`created(user_id, source_ip, binding_id)` / `deleted(user_id, source_ip, binding_id)`；`user_id` 必须是认证身份；`sandbox_id` 可作为 `binding_id`，同时用于审计和归属校验。
4. **事件覆盖所有沙箱，不只 `C` 中的用户**：IP 复用时，新租约的 `created` 是清除旧用户遗留规则的唯一依据（见 6.2）。
5. **同步插规则**：对 `C` 中的用户，`created` 处理完成（规则已插）后才放行其流量；未配置用户无需等待。`deleted` 立即撤租约和规则。事件处理失败要返回错误并告警，不能静默。
6. **无快照时持久化本地状态**：`C` 和 `B` 落盘；credproxy 重启后按持久化状态重建规则；建议 AgentOS 在事件流重连后重放所有存活租约的 `created`，修正断开期间的偏差（见 6.3）。
7. **凭据层单独决策**：捕获按用户，不等于凭据自动按用户。fakecred 的归属维度需要另行确定；若要防跨用户冒用，应使用与策略键一致的维度（用户），沙箱身份/源 IP 用于二次校验。这一层是防冒用，不是免打扰。
8. **不做方案 B 的“全量捕获 + 原始转发”作为 v1**：它把未配置用户也放进 daemon 路径，和需求相反；只有在“规则生命周期不可控”成为主要矛盾时再考虑。

## 6. AgentOS 需要提供的信息

捕获配置按用户维护，因此这两个接口的语义不是“沙箱生命周期通知”，而是**用户 ↔ IP 租约的建立与撤销**：

- `user_id` 是策略键，必须是认证结果，不是客户端自报值。
- `source_ip` 是宿主 netns 看到的源地址（slot netns 的 `10.12.1.x`），是数据面选择器。
- `binding_id` 标识一条租约，用于幂等和精确撤销；可以直接用 `sandbox_id`，也可以另给。
- `sandbox_id` 是归属证据和审计关联，不是策略键。

一个用户可同时持有多条租约（多个沙箱/IP）；同一 IP 在一个租约结束后可被另一个用户的租约复用；任一时刻同一 `source_ip` 至多属于一条存活租约，新的 `created` 接管该 IP 时旧租约被视为结束。`recreate` 如果用同一个 `sandbox_id` 重新绑定新 IP，必须让旧租约结束、新租约建立（同一个 `binding_id` 的新 `created` 覆盖旧绑定，或先 `deleted` 再 `created`，二者选一并写进契约）。

### 6.1 事件

| 事件 | 语义 | 必需字段 | credproxy 的处理 |
|---|---|---|---|
| `created` | 用户 U 现在通过源地址 X 使用沙箱 S | `user_id`（认证）、`source_ip`、`binding_id`、序号/时间、提供方身份 | 按 `binding_id` 覆盖旧绑定；若 X 已被另一条存活租约占用，结束旧租约（takeover）；U ∈ C 则确保 X 的 `/32` 规则存在；U ∉ C 则撤掉 X 上属于旧用户的规则（如果有） |
| `deleted` | 用户 U 不再通过 X 使用 S | `user_id`、`source_ip`、`binding_id`、序号/时间、提供方身份 | 删除该绑定；若 X 不再有存活租约，或剩余租约的用户都不在 C 中，撤 X 的规则；`binding_id` 未知时按 `(user_id, source_ip)` 匹配；不得撤掉由另一条存活租约支撑的规则 |

规则以 IP 为键；takeover 时如果该 IP 的规则保留，comment 里的 `user`/`binding` 要改成新租约的值，保证审计归属正确。

字段要求：

- `user_id`：由创建路径上的认证结果给出，附签发方/认证时间；不能从沙箱内请求、query 或 `X-User-Id` 取（【文档】`agentos-auth-identity-analysis.md:20-23, 526`）。
- `source_ip`：宿主可见地址；必须是沙箱网络就绪后的值。guest 地址（`192.168.100.21`）不可用。
- 序号：按 `binding_id` 单调；credproxy 丢弃比已见序号旧的重复/乱序事件。
- 就绪：对 `C` 中的用户，`created` 的响应表示规则已就绪；AgentOS 收到成功响应后才向用户放行流量。
- 投递语义：至少一次；credproxy 按 `binding_id` 幂等。

### 6.2 事件必须覆盖所有沙箱

不只发 `C` 中用户的事件。原因在 IP 复用：假设用户 A 在 IP X 上的 `deleted` 丢失，之后 X 被分配给未配置用户 B。如果 B 的 `created` 不发，credproxy 会一直保留 A 在 X 上的规则，B 的流量被错误地 DNAT 到 daemon（TLS 失败）。如果所有沙箱都发事件，B 的 `created` 会接管 X，credproxy 撤掉 A 的规则，B 不被捕获。

覆盖所有沙箱也让 credproxy 的绑定表完整，便于审计“某个 IP 当时属于谁”。没有归属用户的沙箱（例如系统任务）也要发 `created`，`user_id` 为空或使用专用标记；它的作用是接管 IP、清除该 IP 上的旧规则，因为空用户不在 `C` 中。

### 6.3 用户配置变更、持久化与恢复

- 把用户加入 `C`：为其所有存活租约插入 `/32` 规则。
- 把用户移出 `C`：删除其所有租约对应的规则，租约本身保留（用户可能稍后重新启用）。该用户存活沙箱的流量随即直连，fakecred 不再被替换——这是策略生效的直接表现，应通知用户。
- `C` 和绑定表必须持久化；credproxy 重启后先恢复状态，再重建规则。
- **不做快照接口**（已确认）。没有快照就没有权威对账源；恢复依赖两件事：本地持久化，以及 AgentOS 在事件流重连/credproxy 重启后**重放全部存活租约的 `created`**。重放复用的是同一个 `created` 事件，不是第三个接口。若不提供重放，断连期间漏掉的 `created/deleted` 只能等该 IP 下一次 `created` 接管时才被纠正，这是接受的残留风险。

### 6.4 当前 AgentOS 的缺口（证据）

- jiuwenbox 的 `SandboxRef` 没有用户字段：`id / phase / runtime / pid / created_at / started_at / last_active_at / error_message / env / ip_address`（【代码】`jiuwenbox/models/sandbox.py:87-106`）。
- `CreateSandboxRequest` 没有用户或标签字段：`command / env / policy / policy_mode / sandbox_id / sandbox_runtime`（【代码】`jiuwenbox/server/routes/sandbox.py:39-50`）。
- conch CLI 没有用户字段；`sandbox create` 的选项只有模板/资源/ID（【实测】`conch sandbox create --help`）。
- jiuwenbox 对 conch 沙箱的 `ip_address` 来自 conch record 的 `domain`（【代码】`conch/sandbox.py:791`）。`domain` 是否等于宿主看到的 slot IP **未验证**；这是契约里必须确认的一项。
- 网关的 `user_id` 是客户端自报，IAM 默认关闭，认证结果未写回连接（【文档】`:20-23`）。
- jiuwenbox 当前没有沙箱生命周期事件订阅/外发设施。检索：`grep -rniE "webhook|subscribe|event_bus|eventbus|callback_url|notify_url" /usr/local/lib/python3.11/dist-packages/jiuwenbox --include='*.py'` 在 46 个 `.py` 文件中只命中 `server/runtime/process.py` 的 “oversubscribed” 注释；`grep -rniE "sandbox\.created|sandbox\.deleted|on_event|emit\("` 只命中 `server/etcd_sync/client.py` 的配置同步 watcher（同步策略配置，不是沙箱生命周期）。两个事件需要新增。

### 6.5 交付渠道

- 走 credproxy 已有的 management plane（AF_UNIX + `SO_PEERCRED`）；把 AgentOS 的 root 进程映射为 operator 角色，沙箱进程不应能连到该 socket。
- 事件里的 `user_id` 只有在事件发送方可信时才有意义；如果沙箱内进程能调用事件接口，它可以伪造用户↔IP 绑定。发送方认证与 `user_id` 的认证是两件事，都要做。
- 如果 AgentOS 与 credproxy 不在同一台机器，需要 mTLS 或签名事件；不要用“源 IP 是管理网”作为认证。

## 7. 未验证与待确认

1. **认证用户如何进入创建路径**：需要看 YuanRong/jiuwenbox 创建 conch 沙箱时由哪一层认证用户、把身份写到哪里；当前证据只到“沙箱对象 + slot IP”。
2. **工具沙箱是否跨用户共享**：若共享，按用户门控只能按归属用户决定整个沙箱是否被捕获，不能在同一沙箱内区分用户。
3. **源 IP 可伪造性**：guest 是否能发出源地址为其它 `10.12.1.x` 的包并绕过 slot netns 的 SNAT；未实测。
4. **skb mark 跨 netns 保持**：方案 D 的前提，未实测。
5. **`/32` 规则端到端**：本次实验只验证了 `/20`；`/32` 是同一条规则收窄匹配，机制上成立，但未跑过完整 E2E。
6. **CA 分发**：被捕获沙箱如何信任 daemon 的 CA（镜像烘焙、volume、还是每次 `--cacert`）；未验证。
7. **IPv6 / UDP 443**：当前规则不覆盖；若沙箱有 IPv6 出口，按 IP 门控可能被绕过。
8. **jiuwenbox `ip_address` 与宿主可见 slot IP 是否同一值**：`conch/sandbox.py:791` 取的是 conch record 的 `domain`；需要实测比对 `domain` 与 `10.12.1.x`。
9. **事件流的重放与顺序能力**：AgentOS 能否在重连后重放全部存活租约的 `created`、能否保证同一 `binding_id`/同一 IP 的事件顺序；未验证。

## 附录 A 复核命令

```sh
# 沙箱对象（无 user 字段）
sudo conch sandbox ls
sudo conch sandbox create --help

# jiuwenbox 沙箱对象字段（无 user 字段）
sudo jiuwenbox --base-url unix:///run/jiuwenbox/jiuwenbox.sock sandbox ls
grep -n "class SandboxRef" -A 25 /usr/local/lib/python3.11/dist-packages/jiuwenbox/models/sandbox.py

# jiuwenbox 是否存在沙箱生命周期事件外发设施
grep -rniE "webhook|subscribe|event_bus|eventbus|callback_url|notify_url" \
  /usr/local/lib/python3.11/dist-packages/jiuwenbox --include='*.py'
grep -rniE "sandbox\.created|sandbox\.deleted|on_event|emit\(" \
  /usr/local/lib/python3.11/dist-packages/jiuwenbox --include='*.py'

# 身份分析中的关键结论
grep -n "user_id\|可信归属\|sandbox_id" docs/agentos-auth-identity-analysis.md

# 当前捕获规则形态
sudo iptables -t nat -S PREROUTING | grep 10.12
```
