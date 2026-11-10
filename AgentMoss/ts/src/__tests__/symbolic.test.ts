/**
 * LiteSE symbolic executor tests — TS side.
 * Mirrors the four scenario categories verified in Python symbolic.py.
 */

import { describe, it, expect } from 'vitest';
import { symbolicProcess, evalCondition, matchGlob, evalExpr, evalNumericCompare } from '../engine/script-engine/symbolic';

describe('LiteSE: variable concatenation (P2)', () => {
  it('case selector prefix${1}suffix resolves', () => {
    const src = '#!/bin/bash\ncase "prefix${1}suffix" in\n  prefixcleansuffix) rm -rf ~/.ssh/id_rsa ;;\n  prefixbacksuffix) echo safe ;;\nesac\n';
    const out = symbolicProcess(src, ['clean']);
    expect(out).not.toBeNull();
    expect(out).toContain('id_rsa');
    expect(out).not.toContain('safe branch');
  });
});

describe('LiteSE: internal named variables (P3)', () => {
  it('MODE=clean picks clean branch', () => {
    const src = '#!/bin/bash\nMODE=clean\ncase $MODE in\n  clean) rm -rf ~/.ssh/id_rsa ;;\n  dev) echo safe ;;\nesac\n';
    const out = symbolicProcess(src, []);
    expect(out).not.toBeNull();
    expect(out).toContain('id_rsa');
  });
  it('global var + if equality', () => {
    const src = '#!/bin/bash\nENV=prod\nif [ "$ENV" = "prod" ]; then\n  echo inprod\nelse\n  echo other\nfi\n';
    const out = symbolicProcess(src, []);
    expect(out).not.toBeNull();
    expect(out).toContain('inprod');
  });
});

describe('LiteSE: glob wildcard (P4)', () => {
  it('bak* matches bakery, dev falls to *', () => {
    const src = '#!/bin/bash\ncase $1 in\n  bak*) echo dangerous ;;\n  *) echo safe ;;\nesac\n';
    const out = symbolicProcess(src, ['bakery']);
    expect(out).not.toBeNull();
    expect(out).toContain('dangerous');
    expect(out).not.toContain('safe');
    const out2 = symbolicProcess(src, ['dev']);
    expect(out2).not.toBeNull();
    expect(out2).not.toContain('dangerous');
    expect(out2).toContain('safe');
  });
  it('matchGlob primitive', () => {
    expect(matchGlob('bak*', 'bakery')).toBe(true);
    expect(matchGlob('bak*', 'dev')).toBe(false);
    expect(matchGlob('a?c', 'abc')).toBe(true);
  });
});

describe('LiteSE: numeric compare (P4)', () => {
  it('evalNumericCompare', () => {
    expect(evalNumericCompare('-gt', '10', '5')).toBe(true);
    expect(evalNumericCompare('-lt', '3', '5')).toBe(true);
    expect(evalNumericCompare('-gt', 'a', '5')).toBeNull();
  });
  it('if [ $1 -gt 5 ]', () => {
    const src = '#!/bin/bash\nif [ "$1" -gt 5 ]; then\n  echo big\nelse\n  echo small\nfi\n';
    const out = symbolicProcess(src, ['10']);
    expect(out).toContain('big');
    const out2 = symbolicProcess(src, ['3']);
    expect(out2).toContain('small');
  });
});

describe('LiteSE: nested matching (depth-paired, safe)', () => {
  it('nested case in case: outer clean retained but unbound inner fails closed', () => {
    const src = [
      '#!/bin/bash',
      'case $1 in',
      '  clean)',
      '    case $2 in',
      '      hard) rm -rf ~/.ssh/id_rsa ;;',
      '      soft) echo safe ;;',
      '    esac',
      '    ;;',
      '  backup) echo safe ;;',
      'esac',
    ].join('\n');
    const out = symbolicProcess(src, ['clean', 'hard']);
    // 安全关键：危险命令不得在剪枝结果中消失
    if (out !== null) {
      expect(out).toContain('rm -rf');
    }
  });
  it('nested clean branch released when backup', () => {
    const src = [
      '#!/bin/bash',
      'case $1 in',
      '  clean)',
      '    case $2 in',
      '      hard) rm -rf ~/.ssh/id_rsa ;;',
      '      soft) echo safe ;;',
      '    esac',
      '    ;;',
      '  backup) echo safe ;;',
      'esac',
    ].join('\n');
    const out = symbolicProcess(src, ['backup']);
    expect(out).not.toBeNull();
    expect(out).not.toContain('rm -rf');
    expect(out).toContain('safe');
  });
  it('if in case: danger preserved on clean branch', () => {
    const src = [
      '#!/bin/bash',
      'case $1 in',
      '  clean)',
      '    if [ "$2" = "all" ]; then',
      '      rm -rf ~/.ssh/id_rsa',
      '    fi',
      '    ;;',
      '  *) echo safe ;;',
      'esac',
    ].join('\n');
    const out = symbolicProcess(src, ['clean', 'all']);
    // 安全关键：危险命令不得消失
    expect(out).not.toBeNull();
    expect(out).toContain('rm -rf');
  });
});

describe('LiteSE: fail-closed', () => {
  it('unknown named selector returns null', () => {
    const src = '#!/bin/bash\nMODE=$1\ncase $MODE in\n  prod) rm -rf ~/.ssh/id_rsa ;;\nesac\n';
    expect(symbolicProcess(src, [])).toBeNull();
  });
  it('non-modelable syntax returns null', () => {
    const src = '#!/bin/bash\ncase $1 in\n  clean) rm -rf ~/.ssh/id_rsa ;;\nesac\n$(echo evil)\n';
    expect(symbolicProcess(src, ['clean'])).toBeNull();
  });
});