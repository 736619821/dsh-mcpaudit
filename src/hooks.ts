/**
 * dsh-mcpaudit — Cordis 生命周期钩子
 *
 * 监听以下事件（来自 Cordis 插件系统）：
 *  - skill:loaded     — skill 文件刚加载到 Agent 上下文
 *  - mcp:server:registered — MCP server 注册完成
 *
 * 两种模式：
 *  - alertOnly=true / blockMode=false → 只告警，不阻止
 *  - blockMode=true  → 扫描到 >= blockMinSeverity 风险时抛出错误，阻止加载
 *
 * 挂接方式：Cordis 的事件总线（ctx.on / ctx.emit）
 * 文档：https://github.com/deepseek-ai/dsh-cordis (Cordis API)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildDefaultEngine, scanText, redact } from './rules.js';
import { loadGuardConfig, matchHash, matchPath } from './config.js';
import { buildEnhancedFindings, buildReportOutput } from './reporter.js';
import { createAuditLogger, buildAuditRecords, type AuditSeverity } from './audit.js';
import { sha256Of } from './config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LifecycleBlockResult {
  allowed: boolean;
  reason?: string;
  report?: object;
  severity?: string;
}

export interface LifecycleEvent {
  /** 'skill' | 'mcp' */
  kind: 'skill' | 'mcp';
  /** Resolved file path or MCP server name */
  target: string;
  /** Raw content of the skill file (if available) */
  content?: string;
  /** SHA-256 of content */
  contentHash?: string;
  /** Profile name (from DSH_PROFILE env) */
  profile: string;
  /** Source of the event */
  source?: string;
}

// ---------------------------------------------------------------------------
// Core scan logic (used by hooks)
// ---------------------------------------------------------------------------

export function scanForLifecycle(
  content: string,
  target: string,
  profile: string,
): { findings: ReturnType<typeof buildEnhancedFindings>; allowed: boolean; reason?: string } {
  const config = loadGuardConfig();

  // Whitelist check: path
  if (config.whitelist.paths.length > 0 && matchPath(target, config.whitelist.paths)) {
    return { findings: [], allowed: true };
  }

  // Whitelist check: hash
  const hash = sha256Of(content);
  if (config.whitelist.hashes.length > 0 && matchHash(hash, config.whitelist.hashes)) {
    return { findings: [], allowed: true };
  }

  // Build rules (with config overrides)
  const baseRules = buildDefaultEngine();
  const rules = baseRules
    .map(r => {
      const override = config.rules[r.id];
      if (!override) return r;
      return {
        ...r,
        severity: (override.severity ?? r.severity) as typeof r.severity,
      };
    })
    .filter(r => {
      const override = config.rules[r.id];
      return override?.enabled === undefined || override.enabled !== false;
    });

  const rawFindings = scanText(content, target, rules);
  const enhanced = buildEnhancedFindings(target, content, rawFindings, 5, config.protectedDirs.redactInReport);

  // Criticality filter: suppress info-level in comments/examples
  const filtered = enhanced.filter(f => {
    if (f.severity === 'info') {
      // Auto-demote 'sk-' in comments
      const inComment = f.contextBefore.some(l =>
        /^\s*(?:\/\/|#|\/\*|\*)/.test(l.content) ||
        /\bexample\b/i.test(l.content) ||
        /\bdocs?\b/i.test(l.content)
      );
      if (inComment) return false;
    }
    return true;
  });

  // Block decision
  let allowed = true;
  let reason: string | undefined;
  if (config.lifecycle.blockMode && config.lifecycle.autoScan) {
    const blockSevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
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

// ---------------------------------------------------------------------------
// Event handler factory
// ---------------------------------------------------------------------------

function makeAuditLogger() {
  const config = loadGuardConfig();
  if (!config.audit.enabled) return null;
  const fp = config.audit.format === 'sqlite'
    ? (config.audit.dbPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.db'))
    : (config.audit.jsonlPath || path.join(process.env.HOME ?? '.', '.mcpaudit', 'audit.jsonl'));
  return createAuditLogger(config.audit.format, fp, config.audit.maxSizeMB);
}

export function makeLifecycleHandler() {
  const config = loadGuardConfig();
  const auditLogger = makeAuditLogger();
  const profile = process.env.DSH_PROFILE ?? 'default';

  return function handleLifecycleEvent(event: LifecycleEvent): LifecycleBlockResult {
    if (!config.lifecycle.autoScan) {
      return { allowed: true };
    }

    if (!event.content) {
      // Try to read file directly
      try {
        if (fs.existsSync(event.target)) {
          event.content = fs.readFileSync(event.target, 'utf-8');
          event.contentHash = sha256Of(event.content);
        }
      } catch {
        return { allowed: true, reason: `[mcpaudit] could not read file: ${event.target}` };
      }
    }

    const { findings, allowed, reason } = scanForLifecycle(
      event.content,
      event.target,
      profile,
    );

    // Write audit log
    if (auditLogger) {
      const action: 'blocked' | 'alert' | 'logged' = !allowed
        ? 'blocked'
        : (config.lifecycle.alertOnly || findings.length > 0) ? 'alert' : 'logged';
      const records = buildAuditRecords(
        event.kind === 'skill' ? 'lifecycle_load' : 'lifecycle_register',
        profile,
        redact(event.target),
        findings.map(f => ({ ruleId: f.ruleId, severity: f.severity as AuditSeverity, title: f.title, fingerprint: f.fingerprint })),
        action,
        event.contentHash,
        config.lifecycle.blockMode,
      );
      for (const r of records) auditLogger.log(r);
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
      // Just log the alert — not blocking
      console.warn(`[mcpaudit] Alert: ${findings.length} finding(s) in ${event.target}`);
    }

    return { allowed: true };
  };
}

// ---------------------------------------------------------------------------
// Cordis hook registration helper
// ---------------------------------------------------------------------------

export interface CordisContext {
  on?: (event: string, handler: (...args: unknown[]) => void) => void;
  emit?: (event: string, ...args: unknown[]) => boolean;
  /** tools.preExecute for runtime observation */
  tools?: {
    preExecute?: (hook: (call: unknown, next: () => unknown) => unknown) => void;
  };
}

/**
 * Attempt to register lifecycle hooks on a Cordis context.
 * Returns the handler function for manual invocation.
 */
export function registerLifecycleHooks(ctx: CordisContext): ((event: LifecycleEvent) => LifecycleBlockResult) | null {
  const handler = makeLifecycleHandler();

  if (typeof ctx.on === 'function') {
    ctx.on('skill:loaded', (target: string, meta?: { content?: string }) => {
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

    ctx.on('mcp:server:registered', (name: string, meta?: { config?: unknown }) => {
      const config = loadGuardConfig();
      if (!config.lifecycle.autoScan) return;

      // For MCP servers, scan the config file
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
      } catch {
        // MCP config scan is best-effort
      }
    });

    return handler;
  }

  return null;
}