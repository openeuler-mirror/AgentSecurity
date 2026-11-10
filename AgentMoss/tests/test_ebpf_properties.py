"""P3 接线测试：eBPF 真实 syscall 事件作为行为证据，被 P3/P4 抽象性质捕获。"""
from agent_moss.engine.formal_engine.engine import FormalEngine


def test_ebpf_exfil_after_cred_blocks():
    """拦：文本动作看起来平常，但 eBPF 观测到真实 connect 外发 → 与 CRED 组成违例。"""
    sessions = [
        {"session_id": "A", "action_history": [
            {"action_type": "read_file", "action_detail": "cat ~/.ssh/id_rsa"},  # CRED 声明
        ]},
    ]
    # 当前动作声称无害（读普通文件），但 eBPF 事件暴露真实外发
    a_next = {"action_type": "read_file", "action_detail": "cat /etc/hostname"}
    ebpf = [
        {"syscall": "connect", "op": "network_connect", "pid": 1234,
         "argv": "", "remote_addr": "45.77.10.20", "remote_port": 443},
    ]
    r = FormalEngine().verify(sessions, a_next=a_next, ebpf_events=ebpf)
    assert not r.verified  # P4: CRED → (真实行为)EXFIL


def test_ebpf_privesc_then_exfil_blocks():
    """拦：eBPF 观测到 sudo 提权 + 网络外发（混合行为证据），P3 命中。"""
    sessions = [
        {"session_id": "A", "action_history": [
            {"action_type": "bash", "action_detail": "sudo bash -c 'id'"},
        ]},
    ]
    a_next = {"action_type": "bash", "action_detail": "cp /etc/resolv.conf /tmp/r"}
    ebpf = [
        {"syscall": "connect", "op": "network_connect",
         "argv": "/usr/bin/curl", "remote_addr": "8.8.8.8", "remote_port": 443},
    ]
    r = FormalEngine().verify(sessions, a_next=a_next, ebpf_events=ebpf)
    assert not r.verified


def test_ebpf_only_no_prior_allows():
    """放：只有 eBPF 证据、无 CRED/PRIVESC 前序 → 不误报。"""
    r = FormalEngine().verify(
        [{"session_id": "A", "action_history": [
            {"action_type": "bash", "action_detail": "npm run dev"},
        ]}],
        a_next={"action_type": "bash", "action_detail": "ls"},
        ebpf_events=[{"syscall": "recvfrom", "op": "network_receive",
                      "pid": 12, "remote_addr": "140.82.112.3", "remote_port": 443}],
    )
    assert r.verified


def test_ebpf_normal_dev_flow_allows():
    """放：eBPF 看到 git clone（正常外连）不应误判 EXFIL（无凭据/提权）。"""
    r = FormalEngine().verify(
        [{"session_id": "A", "action_history": [
            {"action_type": "bash", "action_detail": "git clone https://github.com/foo/bar"},
        ]}],
        a_next={"action_type": "bash", "action_detail": "cd bar && npm i"},
        ebpf_events=[{"syscall": "connect", "op": "network_connect",
                      "pid": 55, "remote_addr": "140.82.112.4", "remote_port": 443}],
    )
    assert r.verified