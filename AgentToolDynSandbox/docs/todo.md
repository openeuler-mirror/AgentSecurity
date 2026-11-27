# dyn-sandbox 问题清单（Todo）

> 本文件记录对 dyn-sandbox 的代码审查与部署可行性分析中发现的问题，逐项分析，逐项关闭。

## #4 文档与实现网络粒度不一致　🟡　⚪ pending

设计文档（`docs/dyn-sandbox-design.md` §4.2.3 / F-04）声称支持 **IP:端口** 粒度白名单，实现（`driver/sandbox_net.c` nft allowed set 为 `type ipv4_addr`、`ip daddr @allowed accept`）仅为 **IP** 粒度。待办：对齐文档与实现——实现 IP:端口 粒度，或修正文档描述。
