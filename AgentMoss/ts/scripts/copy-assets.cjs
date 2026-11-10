/**
 * Copy shared prompt templates and skill files into dist/ so the published
 * npm package is self-contained.
 *
 * template-loader.ts / skill-loader.ts resolve these at runtime relative to
 * __dirname. After tsup bundles into dist/cli.js, __dirname is dist/, so the
 * files must live at dist/templates and dist/skills.
 *
 * In dev (tsx src/cli.ts), __dirname is src/engine/ and the loaders fall back
 * to ../../agent_moss/{templates,skills} (the repo root Python dirs), so no
 * copy is needed there.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..');
const distDir = path.resolve(__dirname, '..', 'dist');

function copyDir(src, dest) {
    if (!fs.existsSync(src)) {
        console.warn(`[copy-assets] source not found, skipping: ${src}`);
        return 0;
    }
    let count = 0;
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
        const s = path.join(src, entry);
        const d = path.join(dest, entry);
        const stat = fs.statSync(s);
        if (stat.isDirectory()) {
            count += copyDir(s, d);
        } else if (stat.isFile()) {
            fs.copyFileSync(s, d);
            count++;
        }
    }
    return count;
}

const assets = [
    { src: path.join(repoRoot, 'agent_moss', 'templates'), dest: path.join(distDir, 'templates') },
    { src: path.join(repoRoot, 'agent_moss', 'skills'), dest: path.join(distDir, 'skills') },
    // 三方 agent 定制化规则（rules.json 单一事实源，py+ts 共用）
    { src: path.join(repoRoot, 'agent_moss', 'agents'), dest: path.join(distDir, 'agents') },
    // 场景定制化规则（scenarios/<id>/rules.json 单一事实源，py+ts 共用；
    // ts/src/scenarios/index.ts 的 resolveScenariosDir 优先 dist/scenarios）
    { src: path.join(repoRoot, 'agent_moss', 'scenarios'), dest: path.join(distDir, 'scenarios') },
    // 用户敏感动作通配符规则（py+ts 共用单一事实源；config.ts loadCustomRules 读取，
    // 含 crontab -e / iptables - / * | crontab 等规则，TS 端需此文件避免 L1 漏检）
    { src: path.join(repoRoot, 'agent_moss', 'rules'), dest: path.join(distDir, 'rules') },
    // Policy Console SPA。console/router.ts 的 STATIC_DIR = join(__dirname, 'static')，
    // tsup 把 router 内联进 dist/*.js，__dirname 解析为 dist/，故落到 dist/static。
    { src: path.join(repoRoot, 'agent_moss', 'console', 'static'), dest: path.join(distDir, 'static') },
    // systemd service 模板（agent-moss install 命令用）
    { src: path.join(__dirname, '..', 'src', 'data'), dest: path.join(distDir, 'data') }
];

let total = 0;
for (const { src, dest } of assets) {
    const n = copyDir(src, dest);
    total += n;
    console.log(`[copy-assets] ${path.relative(repoRoot, src)} -> ${path.relative(distDir, dest)} (${n} files)`);
}
console.log(`[copy-assets] done, ${total} files copied to dist/`);
