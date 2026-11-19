"""Manual prefilter publishing and read-only disk inspection; no worker startup."""
import json
import os
from pathlib import Path
import sys


def _configured_rules(profile):
    from .engine.heuristic import CommandPatternScanner
    from .engine.prefilter_contract import RuleSpec
    from .profiles import get_profile
    from .scenarios import get_scenario_extensions_multi
    from .infra.runtime_config import is_layer_enabled
    from .rules_contract import enforce_rules_contract

    enforce_rules_contract()
    # Same deployment scenario enablement as coordinator; request-specific agent
    # and SDK in-memory extensions must instead supply an exported full snapshot.
    scenario = os.environ.get('AGENT_MOSS_SCENARIO', '')
    try:
        enabled = is_layer_enabled('scenario_rules_enabled')
    except Exception:
        enabled = True
    extension = get_scenario_extensions_multi(scenario) if enabled else None
    scanner = CommandPatternScanner(get_profile(profile), agent_ext=extension)
    rules = tuple(RuleSpec(p['pattern'], p['regex'].flags) for p in scanner._get_active_rules())
    return rules, scenario if enabled else ''


def _disk_status(args):
    from .engine import prefilter_manifest as manifest

    entry = args.db or os.environ.get('AGENT_MOSS_ACCEL_DB')
    if not entry:
        raise ValueError('请设置 --db 或 AGENT_MOSS_ACCEL_DB')
    from .engine.prefilter_disk import read_package
    from .engine.prefilter_storage import PackageBusy, PackageLock, read_status, LOCK_FILE
    try:
        directory = Path(entry).resolve(strict=True)
        if (directory / LOCK_FILE).exists():
            with PackageLock(directory):
                state = read_status(directory)
                if state is not None and state['state'] != 'ready':
                    return dict(state, scope='disk_only', worker_state='not_checked',
                                notice='磁盘包尚不可加载；不代表进程中的旧数据库已停用。')
        with read_package(entry) as disk:
            metadata, packaged = disk.metadata, disk.rules
            directory, identity = disk.directory, disk.identity
    except PackageBusy:
        return {'scope': 'disk_only', 'worker_state': 'not_checked', 'state': 'busy',
                'notice': '正在生成或加载，请稍后重试'}
    descriptor = metadata['database']
    return {
        'scope': 'disk_only', 'worker_state': 'not_checked',
        'notice': '仅检查本进程可见的磁盘包；不表示任何服务 worker 已加载。',
        'entry': str(Path(entry).absolute()), 'version_dir': str(directory),
        'identity': identity, 'state': 'ready',
        'generation': metadata.get('generation'),
        'rules_fingerprint': metadata.get('rules_fingerprint'),
        'configured_entry': os.environ.get('AGENT_MOSS_ACCEL_DB') or None,
        'enabled_by_config': (os.environ.get('AGENT_MOSS_ACCEL', '0') == '1'
                              and bool(os.environ.get('AGENT_MOSS_ACCEL_DB'))),
        'package': {'rules_total': len(packaged),
                    'rules_accelerated': sum(r.expression_id is not None for r in packaged),
                    'expressions_total': len(metadata['expressions'])},
        'native': {'state': 'not_checked', 'required': descriptor is not None,
                   'backend': descriptor['backend'] if descriptor else None,
                   'notice': '磁盘覆盖不代表原生库可用；此命令不加载原生库或启动监测线程。'},
    }


def cmd_accel(args):
    try:
        if args.accel_command == 'build-db':
            from .engine.prefilter_build import build_package, read_rules_snapshot
            if args.rules_file:
                rules = read_rules_snapshot(Path(args.rules_file))
                source = f'rules_file={Path(args.rules_file).absolute()}'
            else:
                rules, scenario = _configured_rules(args.profile)
                source = f'profile={args.profile};scenario={scenario}'
            result = build_package(rules, Path(args.out),
                                   disabled_rules=args.disable_rule, source=source)
        elif args.accel_command == 'status':
            result = _disk_status(args)
        else:
            raise ValueError('请选择 build-db 或 status 子命令')
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except Exception as exc:
        print(f'预筛操作失败: {exc}', file=sys.stderr)
        return 2
