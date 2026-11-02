/**
 * dsh-mcpaudit - DeepSeek Harness 安全审计插件 (v1.0.0)
 *
 * 提供工具：
 * - mcpaudit_scan         扫描本机默认位置，输出多格式报告
 * - mcpaudit_scan_path    扫描指定路径
 * - mcpaudit_observe      运行时观察摘要（只记录不拦截）
 *
 * v1.0.0（由 dsh-mcpguard v0.3 更名升级而来）：
 * - 17 条规则（新增 INJ-004/005、NET-001、REG-001、FILE-001、CMD-002、ENV-001）
 * - 外置 guard-rules.yaml 配置（规则覆盖、白名单、生命周期钩子）
 * - 多格式报告：JSON / Markdown / SARIF
 * - 增量扫描（文件哈希跟踪）
 * - Cordis 生命周期钩子：skill/MCP 加载前自动扫描（可选拦截模式）
 * - 审计日志持久化（JSONL / SQLite）
 *
 * 兼容 DeepSeek Harness 0.1.0-rc.5：tools.register + execute + output。
 */
import * as path from 'node:path';
import { ToolObserver, makePreExecuteHook } from './runtime/observer.js';
import { loadGuardConfig, matchPath, matchHash, sha256Of } from './config.js';
import { buildDefaultEngine, scanText, redact, severityScore } from './rules.js';
import { scanAll, scanAllWithInfo } from './scanner.js';
import { buildEnhancedFindings, buildReportOutput } from './reporter.js';
import { registerLifecycleHooks } from './hooks.js';
import { loadHashStore, saveHashStore, diffAgainstStore, applyChangesToStore } from './hashstore.js';
import { createAuditLogger, buildAuditRecords } from './audit.js';
export const name = 'mcpaudit';
export const inject = ['tools'];
export const PLUGIN_VERSION = '1.0.0';
/** Shared observer (runtime watch mode — never blocks) */
export const observer = new ToolObserver();
/** Re-export for tests */
export { buildDefaultEngine, scanText, redact, severityScore };
function getProtectedDirs() {
    const config = loadGuardConfig();
    return new Set(config.protectedDirs.protectedDirs);
}
function getAlwaysProtect() {
    return loadGuardConfig().protectedDirs.alwaysProtectSensitiveDirs;
}
function isWhitelisted(filePath, hash) {
    const config = loadGuardConfig();
    if (config.whitelist.paths.length > 0 && matchPath(filePath, config.whitelist.paths))
        return true;
    if (config.whitelist.hashes.length > 0 && matchHash(hash, config.whitelist.hashes))
        return true;
    return false;
}
function buildConfiguredRules() {
    const config = loadGuardConfig();
    const base = buildDefaultEngine();
    return base
        .map(r => {
        const ov = config.rules[r.id];
        if (!ov)
            return r;
        return {
            ...r,
            severity: (ov.severity ?? r.severity),
        };
    })
        .filter(r => {
        const ov = config.rules[r.id];
        return ov?.enabled === undefined || ov.enabled !== false;
    });
}
function buildFileReports(targets, options) {
    const config = loadGuardConfig();
    const rules = buildConfiguredRules();
    const contextLines = options.contextLines ?? 5;
    const redactEnabled = options.redactInReport ?? config.protectedDirs.redactInReport;
    const minSev = options.minSeverity ?? config.protectedDirs.minReportSeverity;
    const alwaysProtect = getAlwaysProtect();
    const protectedDirs = getProtectedDirs();
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const files = [];
    const protectedDirsSkipped = [];
    const allHashes = {};
    const profile = options.profile ?? process.env.DSH_PROFILE ?? 'default';
    for (const t of targets) {
        const normalizedPath = t.filePath.replace(/\\/g, '/').toLowerCase();
        const hash = sha256Of(t.content);
        allHashes[normalizedPath] = hash;
        if (alwaysProtect) {
            for (const dir of ['.ssh', '.aws', '.gnupg']) {
                if (normalizedPath.includes(`/${dir}/`) || normalizedPath.endsWith(`/${dir}`)) {
                    protectedDirsSkipped.push({ path: t.filePath, reason: `protected directory: .${dir}` });
                    continue;
                }
            }
            if (/[/\\]\.git[/\\](config|credentials)($|[/\\])/.test(normalizedPath)) {
                protectedDirsSkipped.push({ path: t.filePath, reason: 'protected: .git/config or .git/credentials' });
                continue;
            }
        }
        for (const dir of protectedDirs) {
            const dirNorm = dir.replace(/\\/g, '/').toLowerCase();
            if (normalizedPath.includes(`/${dirNorm}/`) || normalizedPath.endsWith(`/${dirNorm}`)) {
                protectedDirsSkipped.push({ path: t.filePath, reason: `protected by config: ${dir}` });
                continue;
            }
        }
        if (isWhitelisted(t.filePath, hash)) {
            files.push({
                name: t.name,
                path: redact(t.filePath),
                score: 100,
                totalFindings: 0,
                findings: [],
                skippedProtected: false,
            });
            continue;
        }
        const rawFindings = scanText(t.content, `${t.name} (${t.filePath})`, rules);
        const enhanced = buildEnhancedFindings(t.filePath, t.content, rawFindings, contextLines, redactEnabled);
        const minSevLevel = sevOrder[minSev] ?? 4;
        const filtered = enhanced.filter(f => (sevOrder[f.severity] ?? 4) <= minSevLevel);
        const contextFiltered = filtered.filter(f => {
            if (f.severity === 'high' && f.ruleId === 'B64-001') {
                const allCtx = [...f.contextBefore, ...f.contextAfter].map(c => c.content).join('\n');
                if (/example|docs?|sample|test/i.test(allCtx))
                    return false;
            }
            return true;
        });
        const score = severityScore(contextFiltered.map(f => ({ severity: f.severity })));
        files.push({
            name: t.name,
            path: redact(t.filePath),
            score,
            totalFindings: contextFiltered.length,
            findings: contextFiltered,
            skippedProtected: false,
        });
        if (options.auditLogger && config.audit.enabled) {
            const action = contextFiltered.some(f => f.severity === 'critical')
                ? (config.lifecycle.blockMode ? 'blocked' : 'alert')
                : contextFiltered.length > 0 ? 'alert' : 'logged';
            const records = buildAuditRecords('scan', profile, redact(t.filePath), contextFiltered.map(f => ({ ruleId: f.ruleId, severity: f.severity, title: f.title, fingerprint: f.fingerprint })), action, hash, config.lifecycle.blockMode, score);
            for (const r of records)
                options.auditLogger.log(r);
        }
    }
    return { files, protectedDirsSkipped, allHashes };
}
function runScan(paths, opts = {}) {
    const config = loadGuardConfig();
    const fmt = opts.format ?? config.report.defaultFormat;
    const profile = process.env.DSH_PROFILE ?? 'default';
    let auditLogger = null;
    if (config.audit.enabled) {
        const fp = config.audit.format === 'sqlite'
            ? (config.audit.dbPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.db'))
            : (config.audit.jsonlPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.jsonl'));
        auditLogger = createAuditLogger(config.audit.format, fp, config.audit.maxSizeMB);
    }
    const storePath = config.protectedDirs.hashStorePath ||
        path.join(process.env.HOME ?? '.', '.mcpaudit', 'hash-store.json');
    const store = config.protectedDirs.incremental ? loadHashStore(storePath) : null;
    const { targets: allTargets, skipped: scannerSkipped } = scanAllWithInfo(paths);
    const filePaths = allTargets.map(t => t.filePath);
    let targetsToScan = allTargets;
    let scanChanged = true;
    if (store && config.protectedDirs.incremental) {
        const diff = diffAgainstStore(filePaths, store);
        if (diff.added.length === 0 && diff.modified.length === 0) {
            targetsToScan = [];
            scanChanged = false;
        }
        else {
            const changedPaths = new Set([...diff.added, ...diff.modified]);
            targetsToScan = allTargets.filter(t => changedPaths.has(t.filePath));
        }
    }
    const { files, protectedDirsSkipped, allHashes } = buildFileReports(targetsToScan, {
        contextLines: config.report.showContextLines ? 5 : 0,
        redactInReport: config.protectedDirs.redactInReport,
        incremental: config.protectedDirs.incremental,
        auditLogger,
        profile,
        incrementalMode: !!store,
    });
    const mergedSkipped = [...protectedDirsSkipped, ...scannerSkipped];
    if (store && config.protectedDirs.incremental) {
        const diff = diffAgainstStore(filePaths, store);
        for (const unchangedPath of diff.unchanged) {
            const t = allTargets.find(tgt => tgt.filePath === unchangedPath);
            if (!t)
                continue;
            files.push({
                name: t.name,
                path: redact(t.filePath),
                score: 100,
                totalFindings: 0,
                findings: [],
                skippedProtected: false,
            });
        }
    }
    const totalTargets = allTargets.length;
    const output = buildReportOutput(files, totalTargets, PLUGIN_VERSION, fmt, config.report.showContextLines);
    if (config.audit.showSkippedDirs && mergedSkipped.length > 0) {
        output.json.protectedDirsSkipped = mergedSkipped;
    }
    if (store && config.protectedDirs.incremental && scanChanged) {
        const updated = applyChangesToStore(store, targetsToScan.map(t => t.filePath));
        saveHashStore(storePath, updated);
    }
    if (auditLogger)
        auditLogger.close();
    return output;
}
export function apply(ctx) {
    const tools = ctx.tools;
    const config = loadGuardConfig();
    const jsonOutput = {
        schema: { type: 'object' },
        render: (_args, value) => [
            { type: 'text', text: JSON.stringify(value, null, 2) },
        ],
    };
    tools.register({
        name: 'mcpaudit_scan',
        description: '明棱 mcpaudit（v1.0）：扫描本机 MCP 配置与 skill 目录，检测 17 种风险（提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露、路径穿越、危险网络 I/O 等）。返回 JSON/Markdown/SARIF 多格式报告。',
        parameters: {
            type: 'object',
            properties: {
                format: {
                    type: 'string',
                    enum: ['json', 'markdown', 'sarif', 'all'],
                    default: 'json',
                    description: '报告格式：json | markdown（人类可读）| sarif（代码安全标准格式）| all（一次性返回所有格式）',
                },
            },
        },
        output: jsonOutput,
        async execute(args) {
            return runScan([], { format: (args?.format ?? 'json') });
        },
    });
    tools.register({
        name: 'mcpaudit_scan_path',
        description: '明棱 mcpaudit（v1.0）：扫描指定目录或文件，支持增量扫描。多格式报告输出（JSON/Markdown/SARIF）。',
        parameters: {
            type: 'object',
            properties: {
                path: { type: 'string', description: '要扫描的目录或文件路径' },
                format: {
                    type: 'string',
                    enum: ['json', 'markdown', 'sarif', 'all'],
                    default: 'json',
                    description: '报告格式',
                },
                incremental: {
                    type: 'boolean',
                    default: true,
                    description: '启用增量扫描（只扫描改动过的文件）',
                },
            },
            required: ['path'],
        },
        output: jsonOutput,
        async execute(args) {
            return runScan([args.path], { format: (args?.format ?? 'json') });
        },
    });
    tools.register({
        name: 'mcpaudit_observe',
        description: '明棱 mcpaudit（v1.0）：运行时观察摘要。查看工具调用投毒检测记录，只观察不拦截。返回统计 + 最近 10 条记录。',
        parameters: { type: 'object', properties: {} },
        output: jsonOutput,
        async execute() {
            return observer.summary();
        },
    });
    try {
        const lifecycleHandler = registerLifecycleHooks(ctx);
        if (lifecycleHandler) {
            console.log('[mcpaudit] Lifecycle hooks registered (autoScan=%s, blockMode=%s)', config.lifecycle.autoScan, config.lifecycle.blockMode);
        }
    }
    catch (e) {
        console.warn('[mcpaudit] Lifecycle hook registration failed (不影响扫描功能):', e instanceof Error ? e.message : String(e));
    }
    try {
        const toolsCtx = ctx;
        if (typeof toolsCtx?.tools?.preExecute === 'function') {
            toolsCtx.tools.preExecute(makePreExecuteHook(observer));
        }
        else if (typeof toolsCtx.on === 'function') {
            toolsCtx.on('tools/pre-execute', makePreExecuteHook(observer));
        }
        else {
            console.warn('[mcpaudit] tools/pre-execute seam unavailable, observe mode not attached (scanning still works)');
        }
    }
    catch (e) {
        console.warn('[mcpaudit] Observe mode hook failed (不影响扫描功能):', e instanceof Error ? e.message : String(e));
    }
}
export default { name, inject, apply };