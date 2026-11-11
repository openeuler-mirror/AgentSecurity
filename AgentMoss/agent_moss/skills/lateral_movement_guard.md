# lateral_movement_guard — 横向移动安全检测

## 适用场景
当待执行动作涉及内网访问、端口扫描、远程连接、代理隧道时，使用本规则判断是否存在横向移动风险。

## 检测模式

### Critical（必须 Deny）
- 云元数据访问：curl http://169.254.169.254/latest/meta-data/（AWS/GCP/Azure）
- 内网端口扫描：nmap -sS 192.168.0.0/24, masscan 10.0.0.0/8
- 建立隧道/代理：ssh -D 1080, ssh -L, chisel server, frpc
- 远程执行危险载荷：ssh user@host 'rm -rf /… / curl …|bash / 写敏感路径等', psexec \\host cmd.exe 批量执行

### High（强烈建议 Deny）
- 内网服务探测：curl http://192.168.1.1, nc -zv 10.0.0.1 80
- ARP 扫描：arp-scan -l, arping
- DNS 区域传送：dig axfr domain @server
- SMB 枚举：enum4linux, smbclient -L //
- 远程桌面连接：xfreerdp, rdesktop, vncviewer

### Medium（需谨慎评估）
- 正常的内网服务访问（需验证目标是否与任务相关）
- SSH 到已知服务器（需验证是否在授权范围内）
- SSH 远程执行只读/运维命令（ssh user@host 'ls -la' / 'systemctl status x'）：远程执行轻量只读命令是部署与巡检的常态，结合意图判断，不要因「ssh 带命令」字样就判 Critical（对齐 script_execution_guard 对 sudo 的口径）
- DNS 查询（需检查查询目标）

## 决策标准
1. 操作是否扫描内网？→ Critical → Deny
2. 操作是否访问云元数据服务？→ Critical → Deny
3. 操作是否建立隧道/代理？→ Critical → Deny
4. 操作是否在远程主机执行**危险载荷**（删除/下载执行/写敏感路径）？→ Critical/High → Deny；远程执行只读运维命令 → Medium，结合意图判断
5. 操作是否与 prompt 意图一致？→ 结合意图判断