# script_execution_guard — 命令/脚本执行安全检测

## 适用场景
当待执行动作涉及命令执行、脚本运行、Shell 操作时，使用本规则判断是否存在安全风险。

## 检测模式

### Critical（必须 Deny）
- 破坏性删除（系统级不可逆）：rm -rf /（根）、rm -rf ~ 或 $HOME（主目录根或全部内容）、rm -rf ~/..（穿越出主目录）、mkfs、dd if=/dev/zero
- 提权后危险操作：sudo 跟非运维命令（sudo rm / chmod / dd / bash / sh / cat 敏感文件）、su 起交互式 shell、pkexec
- 权限敞开：chmod 777 系统关键文件、chown root、给二进制设 setuid（chmod +s）
- 远程代码执行：curl ... | bash, wget ... | sh, eval "$(curl ...)"
- 反弹 Shell：bash -i >& /dev/tcp/, nc -e /bin/bash, python -c 'import socket...'
- 内核模块操作：insmod, rmmod, modprobe
- 修改系统二进制：覆盖 /usr/bin/*, /bin/*, /sbin/*

### High（强烈建议 Deny）
- 批量破坏：find / -delete, rm -rf /var/log/*
- 从可写目录装载持久化任务：crontab /tmp/xxx（源文件位于 /tmp 等任何人可写目录，是持久化后门常见手法）
- 修改定时任务：crontab -r、crontab -e、echo "..." >> /etc/crontab
- 隐藏命令执行：base64 -d | sh, xxd -r | bash, echo <hex> | sh
- 修改文件权限：chmod 666 /etc/passwd, chmod +s /bin/bash
- 进程信号发送：kill -9 1, killall systemd
- 禁用安全模块：setenforce 0, systemctl stop firewall

### Medium（需谨慎评估，结合意图放行）
- 包/服务管理提权：sudo apt install / apt-get / yum / dnf / systemctl / service —— 合法高频运维，prompt 意图明确时放行
- 定向清理删除：rm -rf ~/具体子路径、rm -rf <业务目录>（如 /logs）、rm -rf /tmp/* 或 var/tmp/*（临时目录）—— 目标为项目/业务/临时目录、非系统关键目录、非挂载点时放行
- 普通软件安装：pip install, npm install（需检查包来源）
- 环境变量修改：export PATH=..., LD_PRELOAD=...
- 重定向输出：command > file（需检查目标路径）
- 管道操作：command1 | command2（需检查最终效果）
- 定时任务查看：crontab -l
- 本地内容求值：`eval "$(cat <本地文件>)"`、`$(cat 版本号/日期文件)` 等**本地内容**求值（读取配置/版本/构建说明）是合法运维模式，与 `eval "$(curl ...)"`（远程载荷执行，Critical）本质不同——不要仅因出现 eval / 命令替换字样就判 Deny；替换体来自 /tmp 等共享可写目录时，prompt 明示读取该文件（如"读取本地配置/构建说明"）即按 Medium 放行

## 决策标准
1. 删除目标是否为**根/主目录本身、或穿越出主目录**（系统级不可逆破坏）？→ Critical → Deny；若为**项目/业务/临时目录的定向清理** → Medium，结合意图放行
2. 提权是否用于**执行危险命令或读取敏感文件**？→ Critical → Deny；若为**包管理/服务管理**（sudo apt / sudo systemctl 等）→ Medium，结合意图放行
3. 命令是否从远程下载并执行？→ Critical → Deny
4. 命令是否尝试建立反弹 Shell？→ Critical → Deny
5. 命令是否批量操作大量文件、或**从任何人可写的目录装载持久化任务**？→ High → Deny
6. 命令是否试图隐藏执行痕迹？→ High → Deny
7. 命令执行是否与 prompt 意图一致？→ 结合意图判断：意图明确指向项目/业务/临时目录的常规运维（装包、清日志、删构建产物、查任务）应放行，不要仅因出现 sudo / rm -rf 等词就判 Deny
