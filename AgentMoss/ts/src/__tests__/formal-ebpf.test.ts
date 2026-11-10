/**
 * P3 eBPF 接线测试（TS 镜像 Python test_ebpf_properties.py）：
 * 真实 syscall 事件作为行为证据被 P3/P4 捕获。
 */
import { describe, expect, it } from 'vitest';
import { FormalEngine } from '../engine/formal-engine';

describe('P3 eBPF evidence (TS)', () => {
  it('ebpf exfil after cred blocks', () => {
    const r = new FormalEngine().verify(
      [{ sessionId: 'A', actionHistory: [
        { actionType: 'read_file', actionDetail: 'cat ~/.ssh/id_rsa' },
      ]}],
      { actionType: 'read_file', actionDetail: 'cat /etc/hostname' },
      [{ syscall: 'connect', op: 'network_connect', pid: 1234, remote_addr: '45.77.10.20', remote_port: 443 }],
    );
    expect(r.verified).toBe(false);
  });

  it('ebpf privesc then exfil blocks', () => {
    const r = new FormalEngine().verify(
      [{ sessionId: 'A', actionHistory: [
        { actionType: 'bash', actionDetail: 'sudo bash -c id' },
      ]}],
      { actionType: 'bash', actionDetail: 'cp /etc/resolv.conf /tmp/r' },
      [{ syscall: 'connect', op: 'network_connect', argv: '/usr/bin/curl', remote_addr: '8.8.8.8', remote_port: 443 }],
    );
    expect(r.verified).toBe(false);
  });

  it('ebpf only with no prior allows', () => {
    const r = new FormalEngine().verify(
      [{ sessionId: 'A', actionHistory: [{ actionType: 'bash', actionDetail: 'npm run dev' }] }],
      { actionType: 'bash', actionDetail: 'ls' },
      [{ syscall: 'recvfrom', op: 'network_receive', pid: 12, remote_addr: '140.82.112.3', remote_port: 443 }],
    );
    expect(r.verified).toBe(true);
  });

  it('ebpf git clone allows (no cred/privesc)', () => {
    const r = new FormalEngine().verify(
      [{ sessionId: 'A', actionHistory: [{ actionType: 'bash', actionDetail: 'git clone https://github.com/foo/bar' }] }],
      { actionType: 'bash', actionDetail: 'cd bar && npm i' },
      [{ syscall: 'connect', op: 'network_connect', pid: 55, remote_addr: '140.82.112.4', remote_port: 443 }],
    );
    expect(r.verified).toBe(true);
  });
});