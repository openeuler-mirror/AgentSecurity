# git over HTTPS：承载凭据的报文实际内容

本文记录 git（Smart HTTP）在 HTTPS 上传输用户名/口令时，凭据在报文中的确切位置与编码形式，
以及同一条消息在凭据代理两侧的差异。内容来自 2026-11-01 在 VM 形态上的实测抓取，不是推断。

## 1. 抓取条件与证据范围

| 项 | 值 |
|---|---|
| 客户端 | VM `credproxy-b-vm`（openEuler 24.03），git 2.54.0 |
| 远端 | `https://gitcode.com/yinxyww/itrustee_tzdriver.git` |
| 入口 | 透明捕获：guest 443 → 宿主 `nat PREROUTING` DNAT → `192.168.56.1:4111` |
| 抓取方式 | `GIT_TRACE_CURL=<file> GIT_TRACE_REDACT=0`（默认会隐去 `Authorization`，必须置 0） |
| 抓到的是 | 客户端 `http.c` 层的明文，即 TLS 加密前的字节；代理终止 TLS 后看到的是同一份内容 |

两条限制，避免误读：

- 追踪器把非可打印字节渲染成 `.`，**字节计数保持精确**（正文 396 字节与 `Content-Length` 对得上），
  但 pack 部分的实际字节值无法从这份抓取里还原。
- 本文不包含真实 PAT。客户端到代理这一段永远不含它，只有代理到上游那一段才有；那一段不在本文范围内。

## 2. 凭据出现在哪一层

TLS 隧道内是 HTTP/1.1（该入口 ALPN 只提供 `http/1.1`）。git 的 Smart HTTP 只定义两组 URL：

- `GET .../info/refs?service=git-receive-pack`（或 `git-upload-pack`）——取 ref 广告；
- `POST .../git-receive-pack`（或 `git-upload-pack`）——传包。

认证完全在 HTTP 层完成。pkt-line 与 packfile 载荷不携带任何认证材料。

```mermaid
sequenceDiagram
    participant G as git（VM 内）
    participant D as credproxyd（4111）
    participant U as gitcode.com:443

    G->>D: GET info/refs（无 Authorization）
    D->>U: GET info/refs（无 Authorization，TLS）
    U-->>D: 401 + WWW-Authenticate
    D-->>G: 401 原样透传
    G->>G: 调用 credential.helper，得到 username/password
    G->>D: GET info/refs（Authorization: Basic base64(user:placeholder)）
    D->>D: 解码 Basic → 口令位置精确查表 → 绑定校验 → 取 cred → 重编码
    D->>U: GET info/refs（Authorization: Basic base64(user:real)）
    U-->>D: 200（ref 广告）
    D-->>G: 200 流式回传
    G->>D: POST git-receive-pack（Authorization 同上，正文为命令 + pack）
    D->>U: POST git-receive-pack（Authorization 换为 cred，正文按字节透传）
    U-->>D: 200（report-status）
    D-->>G: 200 流式回传
```

## 3. 只有一个字段承载口令

凭据只出现在 `Authorization` 请求头，取值是 `Basic ` 后接
`Base64(username ":" password)`（RFC 7617 §2）。解码后按**第一个** `:` 切分：
之前是用户名，之后是口令（因此口令本身可以包含 `:`）。

本次实测值（VM 内 `git config` 注入的 fakecred，见 §7 的说明）。抓取于 2026-11-01，当时 fakecred 的
前缀是 `cred-`；2026-11-05 起统一为 `fcred-`，下文保留原始抓取值：

```text
Authorization: Basic dGVzdHVzZXI6Y3JlZC0wMWExOTVmNjk4YjE3MGU4YjJjODI2MjFiNmVhNmZhYQ==
```

解码：

```text
$ printf '%s' 'dGVzdHVzZXI6Y3JlZC0wMWExOTVmNjk4YjE3MGU4YjJjODI2MjFiNmVhNmZhYQ==' | base64 -d
testuser:cred-01a195f698b170e8b2c82621b6ea6faa
```

| 组成 | 位置 | 本例长度 |
|---|---|---|
| 方案名 | 头值开头 `Basic `（方案名大小写不敏感） | 6 字节 |
| Base64 载荷 | 头值其余部分 | 64 字符（46 字节原文，`==` 填充） |
| 用户名 | 解码后第一个 `:` 之前 | 8 字节（`testuser`） |
| 口令 | 解码后第一个 `:` 之后 | 37 字节（`cred-…`） |

用户名与 URL 路径里的账号名是两回事：本次路径是 `/yinxyww/itrustee_tzdriver.git`，而认证用户名
分别用过 `git`、`yinxyww`、`testuser` 三种取值，三次推送都被服务端接受（返回 200 并推进 ref）。
可见该远端只校验口令位，不把用户名与账号比对。

## 4. 完整报文（实测，四帧）

报文位于 TLS 隧道内；下表按线序给出，`CRLF` 省略。

### 4.1 第一帧：匿名 GET

```http
GET /yinxyww/itrustee_tzdriver.git/info/refs?service=git-receive-pack HTTP/1.1
Host: gitcode.com
User-Agent: git/2.54.0
Accept: */*
Accept-Encoding: deflate, gzip, br
Accept-Language: zh-CN, *;q=0.9

```

- 没有 `Authorization`，也没有消息体。
- 上游回 `401 Unauthorized`；git 追踪器把挑战头按长度隐去，内容未落在这次抓取里。

同一 URL 的匿名请求另用 curl 从宿主直连取过头（2026-11-02），挑战是：

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Auth-Version: 2.0
WWW-Authenticate: Basic realm="GitCode"

```

代理把这一帧原样透传给客户端；git 收到 401 后才去调 `credential.helper`。

### 4.2 第二帧：带凭据的 GET

```http
GET /yinxyww/itrustee_tzdriver.git/info/refs?service=git-receive-pack HTTP/1.1
Host: gitcode.com
Authorization: Basic dGVzdHVzZXI6Y3JlZC0wMWExOTVmNjk4YjE3MGU4YjJjODI2MjFiNmVhNmZhYQ==
User-Agent: git/2.54.0
Accept: */*
Accept-Encoding: deflate, gzip, br
Accept-Language: zh-CN, *;q=0.9
Pragma: no-cache

```

与第一帧相比只多了 `Authorization` 和 `Pragma: no-cache`（后者是客户端关闭缓存时加的）。
请求行、`Host`、其余头完全相同——凭据不在 URL、不在查询串、不在消息体。

### 4.3 第二帧的响应：ref 广告

```http
HTTP/1.1 200 OK
date: Sun, 01 Nov 2026 07:33:42 GMT
content-type: application/x-git-receive-pack-advertisement
set-cookie: HWWAFSESID=<实测值隐去>; path=/
set-cookie: HWWAFSESTIME=<实测值隐去>; path=/
set-cookie: gitcode_wechat_from=; Max-Age=10; Path=/; Secure; HttpOnly; domain=.gitcode.com
cache-control: no-cache
cache-control: no-cache, no-store, must-revalidate
cache-control: no-store
x-correlation-id: fp9Es9AoZI
strict-transport-security: max-age=31536000; includeSubdomains;
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-content-type-options: nosniff
x-download-options: noopen
x-xss-protection: 1; mode=block
x-xss-protection: 1; mode=block
pragma: no-cache
server: elb
transfer-encoding: chunked

```

`transfer-encoding: chunked` 表示没有 `Content-Length`，正文是分块流；代理按流转发，不缓冲。

### 4.4 第三帧：POST（正文即命令 + pack）

```http
POST /yinxyww/itrustee_tzdriver.git/git-receive-pack HTTP/1.1
Host: gitcode.com
Authorization: Basic dGVzdHVzZXI6Y3JlZC0wMWExOTVmNjk4YjE3MGU4YjJjODI2MjFiNmVhNmZhYQ==
User-Agent: git/2.54.0
Accept-Encoding: deflate, gzip, br
Content-Type: application/x-git-receive-pack-request
Accept: application/x-git-receive-pack-result
Accept-Language: zh-CN, *;q=0.9
Content-Length: 396

```

头部块实测 386 字节，正文 396 字节。凭据同样只在 `Authorization` 里；正文按字节原样转发。

### 4.5 第三帧的响应

```http
HTTP/1.1 200 OK
date: Sun, 01 Nov 2026 07:54:51 GMT
content-type: application/x-git-receive-pack-result
set-cookie: HWWAFSESID=<实测值隐去>; path=/
set-cookie: HWWAFSESTIME=<实测值隐去>; path=/
set-cookie: gitcode_wechat_from=; Max-Age=10; Path=/; Secure; HttpOnly; domain=.gitcode.com
cache-control: no-cache
cache-control: no-cache, no-store, must-revalidate
cache-control: no-store
x-correlation-id: vHcQL1acNS
strict-transport-security: max-age=31536000; includeSubdomains;
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-content-type-options: nosniff
x-download-options: noopen
x-xss-protection: 1; mode=block
x-xss-protection: 1; mode=block
pragma: no-cache
server: elb
transfer-encoding: chunked

```

响应体是 pkt-line 的 `report-status` 与 side-band 进度流；git 打印的
`remote: Start Git Hooks Checking [PASSED]` 就来自这里。

## 5. 请求正文的结构（不含凭据）

396 字节正文的分解（pkt-line 长度是 4 位十六进制，含这 4 字节本身）：

```text
00b7                                                           ← 183 字节（头 4 + 载荷 179）
578f160c32adde4ed656d6739648da1dd8010d34                       ← 旧 OID，40 字节
84d73e91b34575cea73dbd0204f1867f6259293a                       ← 新 OID，40 字节
refs/heads/master                                              ← 引用名，17 字节
␀                                                              ← NUL，之后是能力列表
report-status-v2 side-band-64k quiet object-format=sha1 agent=git/2.54.0-Linux   ← 79 字节
0000                                                           ← flush-pkt
PACK                                                           ← pack 流，209 字节
```

长度自洽：183 + 4 + 209 = 396。载荷 179 = 40 + 1 + 40 + 1 + 17 + 1 + 79。

pack 部分逐字段的定位方式（用另一次现场生成的 269 字节 pack 实测）：

```text
magic b'PACK' version 2 objects 5
obj1: offset= 12 type=commit    size=118 inflated=118 zbytes=93
obj2: offset=107 type=blob      size=  6 inflated=  6 zbytes=14
obj3: offset=122 type=blob      size=  2 inflated=  2 zbytes=10
obj4: offset=133 type=tree      size= 61 inflated= 61 zbytes=70
obj5: offset=205 type=tree      size= 33 inflated= 33 zbytes=42
trailer 7a63ac3814d5234f817aedd437305a4b9d0851af at 249 file_len 269
```

- 只有 0–11（`PACK` + 版本 + 对象数）与末尾 20 字节校验和是固定 offset；
- 对象之间是顺序自定界：变长类型/大小头（首字节 bit7 续位、bit6–4 类型、bit3–0 大小低位，
  后续每字节 7 位左移 4、11、18…）+ zlib 流，zlib 长度没有字段，必须 inflate 完才知道边界；
- `ofs-delta` 的基对象是相对当前对象起点的负偏移（变长编码），`ref-delta` 是 20 字节 OID；
- 推送允许 thin pack，`ref-delta` 的基对象可能不在本包里。

因此正文里的 pack 不能按偏移表读取，也不需要读：凭据根本不在其中。

## 6. 同一条消息在代理两侧

| 位置 | `Authorization` 的值 | 说明 |
|---|---|---|
| 客户端 → 代理 | `Basic base64(user:<fakecred>)` | 客户端只持有 fakecred |
| 代理 → 上游 | `Basic base64(user:<真实值>)` | 解码后在口令位替换，再重新编码 |

处理顺序（`crates/credproxyd/src/proxy.rs`）：

1. `transparent_dispatch`（:452）内层 `Host` 必须等于 SNI（`host_header_matches`，:929）；
2. 头字段发现：`discovery_views`（:719）为 `Authorization` 额外提供解码后的用户名与口令两个视图；
   `basic_credentials`（:734）按 RFC 7617 解码，接受大小写不同的方案名与带/不带 padding 的 Base64；
3. 完整 fakecred 在 registry 精确查表，且该凭据的 `allowed_hosts` 命中当前 `host:port`，才取值替换；
   未登记、未绑定的一律原样透传；
4. `rewrite_value`（:682）在解码后的口令里替换、由 `basic_header`（:751）重新编码；
5. `forward_transparent`（:564）重建 `Host`、去掉 hop-by-hop 头，正文按字节流透传。

守护进程日志（`/run/credproxy/credproxyd.log`）对应记录：

```text
vm: placeholder_hit credential=itrustee-push host=gitcode.com:443
vm: substituted credentials=itrustee-push host=gitcode.com:443
audit ts=1793519691 ingress=vm agent=vm-git credential=itrustee-push host=gitcode.com:443 method=POST path=/yinxyww/itrustee_tzdriver.git/git-receive-pack status=200 decision=substitute
```

## 7. 其它可能承载凭据的入口

| 入口 | 最终形态 | 备注 |
|---|---|---|
| `https://user:pass@host/...` 的 URL userinfo | 被客户端转成同一个 `Authorization` 头 | 请求行里不保留 |
| `http.extraHeader` 预置 `Authorization: Basic …` | 原样出现在该头 | 可跳过 401 与 helper |
| `credential.helper` 的 stdio | `username=` / `password=` 两行，只在本机进程间 | 不上线，不经过代理 |
| cookie、查询串、正文 | 不含认证材料 | 实测四帧中均无 |

本文出现的 `cred-01a195f698b170e8b2c82621b6ea6faa` 是 agent 侧 fakecred，不是真实口令；但它本身是一条
可用凭据（持有它即可让代理对 `gitcode.com:443` 替换 cred）。对外分享本文前，应先用
`credclient authority remove` 删除该凭据，或轮换绑定。
