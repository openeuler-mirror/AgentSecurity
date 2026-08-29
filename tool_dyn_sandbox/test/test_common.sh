# test_common.sh — 测试环境公共函数
# 被 test_all.sh 和各独立测试脚本 source
# 要求调用前已定义: DIR, sudo_run (KO_DIR 已不再使用: 模块走 /lib/modules 系统路径)
#
# 说明: 驱动在 open /dev/dyn-sandbox 时校验调用方 exe 路径, 仅允许
#   /usr/bin/dyn-sandbox 与 /usr/bin/dyn-sandbox-dns. 因此测试必须走
#   安装后的可信路径, test_setup 负责把当前构建产物安装到系统路径
#   (若已修改源码, 请先 make clean && make, 再运行测试).

_SANDBOX_SYSTEMD=${_SANDBOX_SYSTEMD:-0}

test_setup() {
    # 把当前构建的二进制与内核模块安装到系统路径 (/usr/bin, /lib/modules/.../extra)
    # 顶层 make 默认 LANDLOCK_ENABLE=0, 而测试套件依赖 landlock 特性, 必须显式传 1
    # (install 依赖 all, 否则会用无 Landlock 变体覆盖安装导致 landlock 用例全挂)
    sudo_run make -C ${DIR}/.. install LANDLOCK_ENABLE=1
    sudo_run depmod -a

    if [ -d /run/systemd/system ]; then
        _SANDBOX_SYSTEMD=1
        sudo_run systemctl daemon-reload
        # restart 触发 ExecStopPost rmmod + ExecStartPre modprobe, 重新加载最新模块
        sudo_run systemctl restart dyn-sandbox.service
    else
        _SANDBOX_SYSTEMD=0
        sudo_run modprobe dyn_sandbox 2>/dev/null \
            || sudo_run insmod /lib/modules/$(uname -r)/extra/dyn_sandbox.ko 2>/dev/null || true
        /usr/bin/dyn-sandbox-dns >> /tmp/dyn-sandbox-dns-test.log 2>&1 &
        sleep 1
    fi
}

test_cleanup() {
    sudo_run systemctl stop dyn-sandbox.service 2>/dev/null || true
    pkill dyn-sandbox-dns 2>/dev/null || true
    sudo_run rmmod dyn_sandbox 2>/dev/null || true
}
