/**
 * dsh-mcpaudit — Cordis 生命周期钩子
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildDefaultEngine, scanText, redact } from './rules.js';
import { loadGuardConfig, matchHash, matchPath, sha256Of } from './config.js';
import { buildEnhancedFindings, buildReportOutput } from './reporter.js';
import { createAuditLogger, buildAuditRecords } from './audit.js';
export function scanForLifecycle(content, target, profile) {
    const config = loadGuardConfig();
    if (config.whitelist.paths.length > 0 && matchPath(target, config.whitelist.paths)) {
        return { findings: [], allowed: true };
    }
    const hash = sha256Of(content);
    if (config.whitelist.hashes.length > 0 && matchHash(hash, config.whitelist.hashes)) {
        return { findings: [], allowed: true };
    }
    const baseRules = buildDefaultEngine();
    const rules = baseRules
        .map(r => {
        const override = config.rules[r.id];
        if (!override)
            return r;
        return {
            ...r,
            severity: (override.severity ?? r.severity),
        };
    })
        .filter(r => {
        const override = config.rules[r.id];
        return override?.enabled === undefined || override.enabled !== false;
    });
    const rawFindings = scanText(content, target, rules);
    const enhanced = buildEnhancedFindings(target, content, rawFindings, 5, config.protectedDirs.redactInReport);
    const filtered = enhanced.filter(f => {
        if (f.severity === 'info') {
            const inComment = f.contextBefore.some(l => /^\s*(?:\/\/|#|\/\*|\*)/.test(l.content) ||
                /\bexample\b/i.test(l.content) ||
                /\bdocs?\b/i.test(l.content));
            if (inComment)
                return false;
        }
        return true;
    });
    let allowed = true;
    let reason;
    if (config.lifecycle.blockMode && config.lifecycle.autoScan) {
        const blockSevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const minBlock = blockSevOrder[config.lifecycle.blockMinSeverity] ?? 0;
        for (const f of filtered) {
            const fSev = blockSevOrder[f.severity] ?? 4;
            if (fSev <= minBlock) {
                allowed = false;
                reason = `[mcpaudit] Blocked: ${f.ruleId} (${f.severity}) — ${f.title} at ${target}:${f.line}:${f.column}`;
                break;
            }
        }
    }
    return { findings: filtered, allowed, reason };
}
function makeAuditLogger() {
    const config = loadGuardConfig();
    if (!config.audit.enabled)
        return null;
    const fp = config.audit.format === 'sqlite'
        ? (config.audit.dbPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.db'))
        : (config.audit.jsonlPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.jsonl'));
    return createAuditLogger(config.audit.format, fp, config.audit.maxSizeMB);
}
export function makeLifecycleHandler() {
    const config = loadGuardConfig();
    const auditLogger = makeAuditLogger();
    const profile = process.env.DSH_PROFILE ?? 'default';
    return function handleLifecycleEvent(event) {
        if (!config.lifecycle.autoScan) {
            return { allowed: true };
        }
        if (!event.content) {
            try {
                if (fs.existsSync(event.target)) {
                    event.content = fs.readFileSync(event.target, 'utf-8');
                    event.contentHash = sha256Of(event.content);
                }
            }
            catch {
                return { allowed: true, reason: `[mcpaudit] could not read file: ${event.target}` };
            }
        }
        const { findings, allowed, reason } = scanForLifecycle(event.content, event.target, profile);
        if (auditLogger) {
            const action = !allowed
                ? 'blocked'
                : (config.lifecycle.alertOnly || findings.length > 0) ? 'alert' : 'logged';
            const records = buildAuditRecords(event.kind === 'skill' ? 'lifecycle_load' : 'lifecycle_register', profile, redact(event.target), findings.map(f => ({ ruleId: f.ruleId, severity: f.severity, title: f.title, fingerprint: f.fingerprint })), action, event.contentHash, config.lifecycle.blockMode);
            for (const r of records)
                auditLogger.log(r);
        }
        if (!allowed) {
            return {
                allowed: false,
                reason,
                severity: findings[0]?.severity,
                report: buildReportOutput([{
                        name: path.basename(event.target),
                        path: redact(event.target),
                        score: Math.max(0, 100 - findings.filter(f => f.severity === 'critical').length * 40),
                        totalFindings: findings.length,
                        findings,
                        skippedProtected: false,
                    }], 1, '1.0.0', 'json', false).json,
            };
        }
        if (config.lifecycle.alertOnly && findings.length > 0 && auditLogger) {
            console.warn(`[mcpaudit] Alert: ${findings.length} finding(s) in ${event.target}`);
        }
        return { allowed: true };
    };
}
export function registerLifecycleHooks(ctx) {
    const handler = makeLifecycleHandler();
    if (typeof ctx.on === 'function') {
        ctx.on('skill:loaded', (target, meta) => {
            const result = handler({
                kind: 'skill',
                target,
                content: meta?.content,
                profile: process.env.DSH_PROFILE ?? 'default',
            });
            if (!result.allowed) {
                throw new Error(result.reason);
            }
        });
        ctx.on('mcp:server:registered', (name, meta) => {
            const config = loadGuardConfig();
            if (!config.lifecycle.autoScan)
                return;
            const configPath = path.join(process.env.HOME ?? '.', '.mcp.json');
            try {
                if (fs.existsSync(configPath)) {
                    const content = fs.readFileSync(configPath, 'utf-8');
                    const result = handler({
                        kind: 'mcp',
                        target: configPath,
                        content,
                        profile: process.env.DSH_PROFILE ?? 'default',
                    });
                    if (!result.allowed) {
                        throw new Error(result.reason);
                    }
                }
            }
            catch {
                // MCP config scan is best-effort
            }
        });
        return handler;
    }
    return null;
}