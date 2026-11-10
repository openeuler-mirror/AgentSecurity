"""Brain 规则/Skill 贡献器 — 把本地沉淀的安全知识提交为远端 PR/MR

设计目标：让 Brain 自学习的成果能回流到共享仓库（默认 AtomGit/GitCode 的
kenhkl/AgentMoss），供维护者审核合并，其他人通过现有 import_rules /
import_skills 接收（origin_node='central'）。

流程（favor 平台的 merge-request 流程，实测 gitcode.com 的 git push 会提示
MR 创建链接）：
1. 导出本地 active + source=llm_extracted 规则，以及 active + origin_node=local 的 skill
2. 组装成 agent_moss/rules/*.json 或 skills/*.md 的补丁内容
3. 探测目标仓 push 权限：git ls-remote 失败 → 引导申请权限（邮件）
4. 有权限：push 临时分支 brain-contrib/<ts>
   - 有 API token（env AGENT_MOSS_CONTRIBUTE_TOKEN）→ 走 GitLab 风格 MergeRequest API
   - 无 token → 输出平台提示的 MR 网页链接，用户手点
5. 默认不自动 merge，一切交维护者审核

中心化预留：本模块不做中心服务器（那是后续中心化部署的活儿）。但导出格式
（ring buffer rules JSON + skill MD）与 import_rules/import_skills 兼容，
未来接中心服务器时，只需把第 4 步的"push 分支"替换成"POST 到中心 API"。
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# 默认目标仓库：AtomGit/GitCode 上的 AgentMoss 共享仓（供 owner/协作者直接 push 探测）
DEFAULT_TARGET_REPO = "ssh://git@atomgit.com/kenhkl/AgentMoss.git"
# 权限申请邮箱（私仓无权限时引导用户邮件申请）
CONTACT_EMAIL = "kenhkl11@hotmail.com"
# API token env（GitLab 风格 PRIVATE-TOKEN；无 token 时仅输出 MR 网页链接）
TOKEN_ENV = "AGENT_MOSS_CONTRIBUTE_TOKEN"
# 平台 SSH 主机（fork 的 SSH URL 用它拼：ssh://git@<HOST>/<user>/AgentMoss.git）
PLATFORM_SSH_HOST = "atomgit.com"

# 规则导出时排除这些 source（贡献的应是"本地 LLM 提取且审核通过"的沉淀，不含中心下发）
EXPORT_RULE_SOURCES = ("llm_extracted", "user")


class ContributionError(Exception):
    """贡献流程异常（可向用户展示的消息）"""


def collect_rules(brain_store) -> list[dict]:
    """导出本地可贡献的 brain 规则（active + llm_extracted/user）。"""
    from .rule_store import STATUS_ACTIVE
    rules = []
    for r in brain_store.get_active_rules():
        if r.source not in EXPORT_RULE_SOURCES:
            continue
        rules.append({
            "layer": r.layer,
            "rule_type": r.rule_type,
            "pattern": r.pattern,
            "scope": r.scope,
            "confidence": r.confidence,
            "explanation": r.explanation,
            "source_event_count": len(r.source_event_ids),
            "trigger_count": r.trigger_count,
        })
    return rules


def collect_skills(skill_mgr) -> list[dict]:
    """导出本地可贡献的 brain skill（active + origin_node=local）。"""
    skills = skill_mgr.export_skills()
    return skills or []


def write_export_files(out_dir: Path, rules: list[dict], skills: list[dict]) -> list[Path]:
    """把导出内容写入指定目录，返回写出的文件路径列表。"""
    out_dir = Path(out_dir)
    written = []
    # 规则 → rules/ 下按 layer 分文件（对齐 agent_moss/rules/*.json 事实源格式）
    rules_dir = out_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    by_layer: dict[int, list[dict]] = {}
    for r in rules:
        by_layer.setdefault(r["layer"], []).append(r)
    for layer, items in sorted(by_layer.items()):
        path = rules_dir / f"l{layer}_brain_rules.json"
        path.write_text(
            json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8",
        )
        written.append(path)
    # 空规则时写空文件（表示本次贡献无规则）
    if not rules:
        path = rules_dir / "empty.txt"
        path.write_text("(no brain rules to contribute)", encoding="utf-8")
        written.append(path)

    # skill → skills/ 下
    skills_dir = out_dir / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    for sk in skills:
        path = skills_dir / f"{sk['name']}.md"
        path.write_text(sk.get("content", ""), encoding="utf-8")
        written.append(path)
    if not skills:
        path = skills_dir / "empty.txt"
        path.write_text("(no brain skills to contribute)", encoding="utf-8")
        written.append(path)

    return written


def _run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """执行 git 命令（捕获输出，不打印 token）。"""
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=60,
    )


def probe_access(target_repo: str) -> bool:
    """探测目标仓是否可 push（git ls-remote 成功 = 至少有读权限，再试 push 探测）。

    私仓无权限时 ls-remote 会 403/401 → 返回 False，引导用户申请权限。
    """
    res = _run_git(["ls-remote", "--heads", target_repo])
    if res.returncode != 0:
        logger.debug("ls-remote 失败: %s", res.stderr.strip())
        return False
    return True


def build_commit_message(rules: list[dict], skills: list[dict]) -> str:
    """生成 MR commit message（描述贡献内容）。"""
    lines = [
        "feat(brain): 贡献本地 LLM 自学习沉淀的规则与 Skill",
        "",
        f"本次贡献由 AgentMoss Brain 从 {len(rules)} 条规则与 {len(skills)} 个 Skill 组成，",
        "均为本地 LLM 提取 + 审核通过的 active 项。",
    ]
    if rules:
        lines.append("")
        lines.append("## 规则")
        by_layer: dict[int, int] = {}
        for r in rules:
            by_layer[r["layer"]] = by_layer.get(r["layer"], 0) + 1
        for layer, cnt in sorted(by_layer.items()):
            lines.append(f"- Layer {layer}: {cnt} 条")
        # 附规则描述（取前几条的 explanation，便于审阅）
        for r in rules[:5]:
            lines.append(f"  - [{r['rule_type']}] {r['pattern'][:80]} — {r['explanation'][:60]}")
    if skills:
        lines.append("")
        lines.append("## Skill")
        for sk in skills[:5]:
            lines.append(f"- {sk['name']}: {sk.get('category', '')}")
    lines.append("")
    lines.append("Co-Authored-By: AgentMoss Brain <brain@agentmoss.local>")
    return "\n".join(lines)


def git_commit_and_push(
    workdir: Path,
    target_repo: str,
    branch: str,
    rules: list[dict],
    skills: list[dict],
) -> str:
    """在 workdir 组装提交并 push 到目标仓分支，返回 MR 网页链接（或 None 需 API）"""
    # 组装 git 仓库（fetch 远端 master 作为 base，避免本地历史污染远端）
    _run_git(["init", "-q"], cwd=workdir)
    _run_git(["remote", "add", "origin", target_repo], cwd=workdir)
    _run_git(["fetch", "--depth", "1", "origin", "master"], cwd=workdir)
    _run_git(["checkout", "-q", "-b", branch, "FETCH_HEAD"], cwd=workdir)
    _run_git(["add", "-A"], cwd=workdir)
    _run_git(["commit", "-q", "-m", build_commit_message(rules, skills)], cwd=workdir)

    # push
    push = _run_git(["push", "origin", branch], cwd=workdir)
    if push.returncode != 0:
        logger.debug("push 失败: %s", push.stderr.strip())
        raise ContributionError(
            f"push 到 {target_repo} 失败：{push.stderr.strip()[:300]}"
        )
    return push.stdout + push.stderr


def extract_mr_url(push_output: str, target_repo: str, branch: str) -> str:
    """从 push 输出提取平台提示的 MR 链接（gitcode 的 push hook 会打印）。"""
    # 平台格式: https://gitcode.com/.../merge_requests/new?source_branch=...
    for line in push_output.splitlines():
        line = line.strip()
        if "merge_requests/new" in line or "pull/new" in line or "new?source_branch" in line:
            return line
    # 回退：无 MR 链接时构建仓库首页的 branches 链接（用户手点 create PR）
    if "gitcode.com" in target_repo or "atomgit.com" in target_repo:
        repo_path = _extract_repo_path(target_repo)
        return f"https://gitcode.com/{repo_path}/branches"
    return ""


def _extract_repo_path(repo_url: str) -> str:
    """从 SSH/HTTPS URL 提取 owner/repo 路径。

    - ssh://git@atomgit.com/kenhkl/AgentMoss.git → kenhkl/AgentMoss
    - git@gitcode.com:kenhkl/AgentMoss.git       → kenhkl/AgentMoss
    - https://gitcode.com/kenhkl/AgentMoss.git   → kenhkl/AgentMoss
    """
    url = repo_url
    # ssh:// 或 scp-like (git@host:path)
    if url.startswith("ssh://"):
        url = url.split("://", 1)[1]
        # git@atomgit.com/kenhkl/AgentMoss.git → 去掉 host 部分
        if "/" in url.split("/", 1)[0] and "@" in url.split("/", 1)[0]:
            url = url.split("/", 1)[1]
        elif "@" in url.split("/", 1)[0]:
            url = url.split("/", 1)[1] if "/" in url else url
    elif ":" in url and "@" in url and url.startswith("git@"):
        url = url.split(":", 1)[1]
    elif url.startswith("http"):
        url = url.split("://", 1)[1]
    return url.removesuffix(".git").strip("/")


def create_mr_via_api(
    target_repo: str, branch: str, title: str, desc: str,
) -> bool:
    """尝试通过 GitLab 风格 API 创建 MR（需要 token）。

    Returns:
        True = MR 创建成功；False = 无 token 或 API 失败（调用方回退网页链接）
    """
    from urllib.request import Request, urlopen

    token = os.getenv(TOKEN_ENV, "")
    if not token:
        return False
    # gitcode 是 GitLab 兼容 API，仓库 id 用 URL-encode 的 path
    import urllib.parse
    repo_path = target_repo.split(":")[-1].removesuffix(".git")  # kenhkl/AgentMoss
    if repo_path.startswith("/"):
        repo_path = repo_path.lstrip("/")
    api_url = f"https://gitcode.com/api/v4/projects/{urllib.parse.quote(repo_path, safe='')}/merge_requests"
    payload = json.dumps({
        "source_branch": branch,
        "target_branch": "master",
        "title": title,
        "description": desc,
    }).encode("utf-8")
    req = Request(
        api_url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "PRIVATE-TOKEN": token,
        },
    )
    try:
        with urlopen(req, timeout=20) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        logger.debug("API 建 MR 失败（回退网页）: %s", e)
        return False


def get_current_username() -> str:
    """从 git 全局配置取当前用户名（用于拼 fork 的 SSH URL）。

    用户 fork `kenhkl/AgentMoss` 后，自己的 fork 路径是
    `ssh://git@<host>/<username>/AgentMoss.git`。
    返回空串表示取不到（引导用户显式 --fork-user 指定）。
    """
    res = _run_git(["config", "--get", "user.name"])
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    return ""


def build_fork_ssh_url(username: str) -> str:
    """拼当前用户 fork 的 SSH URL：ssh://git@<host>/<username>/AgentMoss.git"""
    return f"ssh://git@{PLATFORM_SSH_HOST}/{username}/AgentMoss.git"


def resolve_push_target(args) -> str:
    """决定 push 分支推到哪个仓。

    优先级（其他用户贡献场景，push 目标必须是"自己有写权限的仓"）：
      1. 显式 --target：用户给了一个自己有权限的仓（fork 或直接）
      2. --fork-user <用户名>：用户显式指定自己的 gitcode 用户名，拼 fork URL
      3. 默认：查 git config user.name 拼 `ssh://git@atomgit.com/<user>/AgentMoss.git`
         —— 即用户自己的 fork。若用户尚未 fork，后续探测会提示先网页 fork。
      4. 都取不到 → 报错引导。
    """
    if args.target:
        return args.target
    if getattr(args, "fork_user", None):
        return build_fork_ssh_url(args.fork_user)
    username = get_current_username()
    if username:
        return build_fork_ssh_url(username)
    raise ContributionError(
        "无法确定 push 目标：请在网页端 fork 目标仓库后使用 --fork-user <用户名> "
        "（或直接 --target <你的 fork SSH URL>）"
    )


def contribute(args) -> int:
    """CLI 入口：导出 → 提交 → 引导。

    设计：默认 push 到"当前用户自己的 fork"，MR 指向共享仓 kenhkl/AgentMoss。
    因为共享仓是私仓（其他用户无 push 权限），push 到 fork 是唯一可行路径；MR
    由用户在网页端从 fork 的分支指向 shared 仓发起。
    """
    from .rule_store import BrainRuleStore
    from .skill_manager import BrainSkillManager

    # 工具链检查
    if _run_git(["version"]).returncode != 0:
        print("错误：未检测到 git，贡献功能需要 git CLI。")
        return 2

    # 目标 = 用户的 fork（或显式 --target）
    try:
        push_target = resolve_push_target(args)
    except ContributionError as e:
        print(f"[Brain] {e}")
        return 2
    print(f"[Brain] push 目标: {push_target}")
    print(f"[Brain] MR 指向: {DEFAULT_TARGET_REPO}")

    # 1. 收集
    store = BrainRuleStore()
    skill_mgr = BrainSkillManager(skills_dir=Path(__file__).parent.parent / "skills")
    try:
        rules = collect_rules(store)
        skills = collect_skills(skill_mgr)
    finally:
        store.close()
        skill_mgr.close()

    if not rules and not skills:
        print("[Brain] 本地没有 active 的 brain 规则或 skill，无可贡献内容。")
        return 0

    print(f"[Brain] 导出: {len(rules)} 条规则, {len(skills)} 个 Skill")

    # 2. 写入临时目录（干净快照）
    import tempfile
    tmpdir = Path(tempfile.mkdtemp(prefix="agentmoss-contrib-"))
    try:
        write_export_files(tmpdir / "agent_moss" / "brain_contrib", rules, skills)

        # 3. 权限探测：目标仓（用户 fork）必须可 push
        print(f"[Brain] 探测 {push_target} 访问权限 ...")
        if not probe_access(push_target):
            username = get_current_username()
            print(f"[Brain] 无法访问 {push_target}")
            print()
            if username:
                print(f"  当前 git 用户: {username}")
                print(f"  可能原因：你还没有 fork 目标仓库，或 fork 名不匹配。")
                print(f"  请先在网页端 fork: {DEFAULT_TARGET_REPO}")
                fork_url = build_fork_ssh_url(username)
                print(f"    （fork 后你的仓应该是: {fork_url}）")
            print()
            print(f"  如果你确认已 fork 但对私仓访问受限：")
            print(f"    收件人: {CONTACT_EMAIL}")
            print(f"    邮件注明: 你的 gitcode 账号 + 申请理由（访问 AgentMoss 仓库以提交 PR）")
            print("    fork 后重试本命令，或用 --target <你的 fork URL> 显式指定。")
            return 1

        branch = args.branch or f"brain-contrib/{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        print(f"[Brain] 推送分支 {branch} → {push_target}")
        push_output = git_commit_and_push(tmpdir, push_target, branch, rules, skills)
        print(f"[Brain] 推送成功。")

        # 4. MR（优先 API，无 token 给网页链接）
        title = f"[Brain] 贡献 {len(rules)} 条规则 + {len(skills)} 个 Skill"
        desc = build_commit_message(rules, skills)
        if create_mr_via_api(push_target, branch, title, desc):
            print(f"[Brain] 已通过 API 创建 Merge Request：")
            print(f"  {branch} → master (MR 指向 {DEFAULT_TARGET_REPO})")
        else:
            mr_url = extract_mr_url(push_output, push_target, branch)
            print()
            print(f"[Brain] 请在网页端创建 Merge Request（from 你的 fork → shared 仓 master）：")
            if mr_url:
                print(f"  {mr_url}")
            print(f"  分支: {branch}  →  master (目标仓: {DEFAULT_TARGET_REPO})")
            if not os.getenv(TOKEN_ENV):
                print(f"  （提示：设置 env {TOKEN_ENV} 可让本命令自动创建 MR）")
        return 0
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def add_contribute_parser(subparsers):
    """注册 `agentmoss brain contribute` 子命令。"""
    brain_parser = subparsers.add_parser(
        "brain", help="Brain 自学习管理（贡献/查看本地沉淀）"
    )
    brain_sub = brain_parser.add_subparsers(dest="brain_command", help="Brain 子命令")
    contrib = brain_sub.add_parser(
        "contribute", help="把本地 brain 规则/skill 提交为远端 MR"
    )
    contrib.add_argument(
        "--target", "-t", default=None,
        help="push 目标仓库 SSH URL（默认按当前 git 用户拼 fork："
             f"ssh://git@atomgit.com/<user>/AgentMoss.git）",
    )
    contrib.add_argument(
        "--fork-user", default=None,
        help="你的 gitcode 用户名（用于拼 fork URL，当 git config user.name 不符时）",
    )
    contrib.add_argument(
        "--branch", default=None,
        help="推送分支名（默认 brain-contrib/<时间戳>）",
    )
    return brain_parser