"""平台特征（PlatformTraits）Python 端测试 — 验证不同平台的写/读命令识别。"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent_moss.engine.logic_rules import _is_write_operation
from agent_moss.profiles import get_profile


def _check(cmd, osn):
    p = get_profile(osn)
    return _is_write_operation('bash', cmd, p.write_keywords, p)


def test_linux_commands():
    assert _check('rm -rf /tmp/x', 'linux')
    assert _check('cp a b', 'linux')
    assert not _check('cat a b', 'linux')
    assert not _check('del /q C:\\tmp', 'linux')  # del 不是 Linux 命令


def test_windows_commands():
    assert _check('del /q C:\\tmp\\x', 'windows')
    assert _check('copy a b', 'windows')
    assert _check('icacls C:\\tmp /grant Everyone:F', 'windows')
    assert _check('reg delete HKLM\\Software /f', 'windows')
    assert not _check('type C:\\tmp\\x', 'windows')  # type 是读


def test_platform_isolation():
    # 同一命令在不同平台判定不同（隔离）
    assert not _check('del /q C:\\tmp', 'linux')
    assert _check('del /q C:\\tmp', 'windows')
    assert _check('rm -rf /', 'linux')
    assert not _check('rm -rf /', 'windows')  # rm 不是 Windows 命令


def test_macos_inherits_linux():
    assert _check('rm -rf /', 'macos')
    assert not _check('del /q C:\\tmp', 'macos')


def test_read_only_commands():
    l = get_profile('linux').read_only_commands
    w = get_profile('windows').read_only_commands
    assert 'cat' in l and 'type' in w
    assert 'type' not in l  # type 是 Linux 命令但语义不同（查看类型）
    assert 'cat' not in w  # cat 不是 Windows 命令


def test_write_command_res():
    l = {rx.pattern for rx in get_profile('linux').write_command_res}
    w = {rx.pattern for rx in get_profile('windows').write_command_res}
    assert any('rm' in p for p in l)
    assert any('del' in p for p in w)
    assert not any('del' in p for p in l)
