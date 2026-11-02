/**
 * dsh-mcpaudit 扫描器：扫描文件/目录中的 skill 与 MCP 配置
 * v1.0.0：保护目录改为配置化（guard-rules.yaml），并输出「被保护跳过的目录」
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadGuardConfig } from './config.js';
const SKILL_EXTS = new Set([
    '.md', '.txt', '.json', '.jsonl', '.yaml', '.yml',
    '.py', '.js', '.ts', '.toml', '.xml', '.html',
]);
/** 始终跳过的公共目录（代码库/虚拟环境，与敏感凭据无关） */
const HARD_SKIP_DIRS = new Set([
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'dist', 'build', 'models', '.idea', '.vscode',
]);
function resolveSensitivePatterns(alwaysProtect) {
    const config = loadGuardConfig();
    const dirs = new Set(config.protectedDirs.protectedDirs ?? []);
    if (alwaysProtect) {
        dirs.add('.ssh');
        dirs.add('.aws');
        dirs.add('.gnupg');
    }
    return Array.from(dirs).map((d) => d.replace(/\\/g, '/'));
}
function isProtectedPath(p, patterns) {
    const normalized = p.replace(/\\/g, '/');
    for (const pat of patterns) {
        const pn = pat.replace(/\/+$/, '');
        if (normalized === pn || normalized.startsWith(pn + '/')) {
            return { protected: true, reason: `protected directory: ${pat}` };
        }
    }
    if (/(^|\/)\.git[/\\](config|credentials)($|[/\\])/.test(normalized)) {
        return { protected: true, reason: 'protected: .git/config or .git/credentials' };
    }
    return { protected: false, reason: '' };
}
function walk(dir, targets, depth, sensitive, skipped) {
    if (depth > 8)
        return;
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const e of entries) {
        const full = path.join(dir, e.name);
        if (HARD_SKIP_DIRS.has(e.name))
            continue;
        if (e.isDirectory()) {
            const { protected: isProt, reason } = isProtectedPath(full, sensitive);
            if (isProt) {
                skipped.push({ path: full, reason });
                continue;
            }
            walk(full, targets, depth + 1, sensitive, skipped);
        }
        else if (e.isFile()) {
            const ext = path.extname(e.name).toLowerCase();
            if (!SKILL_EXTS.has(ext))
                continue;
            try {
                const st = fs.statSync(full);
                if (st.size > 256 * 1024)
                    continue; // 256KB 上限
                const content = fs.readFileSync(full, 'utf-8');
                targets.push({ kind: 'file', name: e.name, filePath: full, content });
            }
            catch {
                // 竞态/权限错误跳过
            }
        }
    }
}
function scanFile(p, targets, sensitive, skipped) {
    const ext = path.extname(p).toLowerCase();
    if (!SKILL_EXTS.has(ext))
        return;
    const { protected: isProt, reason } = isProtectedPath(p, sensitive);
    if (isProt) {
        skipped.push({ path: p, reason });
        return;
    }
    try {
        const st = fs.statSync(p);
        if (st.size > 256 * 1024)
            return;
        const content = fs.readFileSync(p, 'utf-8');
        targets.push({ kind: 'file', name: path.basename(p), filePath: p, content });
    }
    catch {
        // 跳过
    }
}
/** 默认扫描位置（常见 MCP 配置 + skill 目录） */
export function defaultPaths() {
    const home = process.env.USERPROFILE ?? process.env.HOME ?? '';
    if (!home)
        return [];
    const isWin = process.platform === 'win32';
    const paths = [];
    if (isWin) {
        paths.push(path.join(home, '.claude', 'claude_desktop_config.json'), path.join(home, '.cursor', 'mcp.json'), path.join(home, '.mcp.json'), path.join(home, '.claude', 'skills'), path.join(home, '.config', 'claude', 'skills'));
    }
    else {
        paths.push(path.join(home, '.claude', 'claude_desktop_config.json'), path.join(home, '.config', 'claude', 'claude_desktop_config.json'), path.join(home, '.mcp.json'), path.join(home, '.claude', 'skills'), path.join(home, '.config', 'claude', 'skills'));
    }
    return paths;
}
/** 扫描全部目标（只返回目标） */
export function scanAll(extraPaths = []) {
    return scanAllWithInfo(extraPaths).targets;
}
/** 扫描全部目标，附带被保护跳过目录信息 */
export function scanAllWithInfo(extraPaths = []) {
    const targets = [];
    const skipped = [];
    const paths = extraPaths.length > 0 ? extraPaths : defaultPaths();
    const alwaysProtect = loadGuardConfig().protectedDirs.alwaysProtectSensitiveDirs;
    const sensitive = resolveSensitivePatterns(alwaysProtect);
    for (const p of paths) {
        let st;
        try {
            st = fs.statSync(p);
        }
        catch {
            continue;
        }
        if (st.isDirectory())
            walk(p, targets, 0, sensitive, skipped);
        else
            scanFile(p, targets, sensitive, skipped);
    }
    return { targets, skipped };
}