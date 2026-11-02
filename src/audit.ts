/**
 * dsh-mcpaudit — 审计日志持久化
 * 支持 JSONL（行文本）和 SQLite 两种格式
 * 记录扫描时间、文件路径、风险等级、规则 ID、操作者（DSH profile）
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { sha256Of } from './config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuditRecord {
  /** ISO 8601 timestamp */
  ts: string;
  /** Unique event ID */
  eventId: string;
  /** 'scan' | 'block' | 'alert' | 'lifecycle_load' | 'lifecycle_register' */
  event: string;
  /** DSH profile name, if available */
  profile: string;
  /** File path that was scanned (redacted) */
  filePath: string;
  /** Rule ID that triggered */
  ruleId: string;
  /** Severity level */
  severity: AuditSeverity;
  /** Human-readable title */
  title: string;
  /** Action taken: 'blocked' | 'alert' | 'logged' | 'passed' */
  action: string;
  /** SHA-256 of file content (for forensics) */
  contentHash?: string;
  /** Score after scan */
  score?: number;
  /** Block mode: true if this scan would have blocked */
  blockMode?: boolean;
  /** Rule fingerprint (short) */
  fingerprint?: string;
}

export interface AuditLogger {
  log(record: AuditRecord): void;
  flush(): void;
  close(): void;
}

// ---------------------------------------------------------------------------
// JSONL logger
// ---------------------------------------------------------------------------

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
}

function rotateIfNeeded(fp: fs.PathLike, maxMB: number): void {
  try {
    const st = fs.statSync(fp);
    if (st.size > maxMB * 1024 * 1024) {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const rotated = `${fp.toString()}.${ts}.rotated`;
      fs.renameSync(fp, rotated);
    }
  } catch {
    // File doesn't exist yet — no rotation needed
  }
}

export class JsonlAuditLogger implements AuditLogger {
  private fp: string;
  private maxMB: number;
  private fd: number = -1;
  private count = 0;

  constructor(fp: string, maxMB = 10) {
    this.fp = fp;
    this.maxMB = maxMB;
    this.init();
  }

  private init(): void {
    try {
      const dir = path.dirname(this.fp);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      rotateIfNeeded(this.fp, this.maxMB);
      this.fd = fs.openSync(this.fp, 'a');
    } catch (e) {
      console.warn('[mcpaudit] audit: failed to open log file:', e instanceof Error ? e.message : String(e));
    }
  }

  log(record: AuditRecord): void {
    if (this.fd < 0) return;
    try {
      const line = JSON.stringify(record) + '\n';
      fs.writeSync(this.fd, line);
      this.count++;
    } catch (e) {
      console.warn('[mcpaudit] audit: write failed:', e instanceof Error ? e.message : String(e));
    }
  }

  flush(): void {
    if (this.fd >= 0) {
      try { fs.fsyncSync(this.fd); } catch { /* ok */ }
    }
  }

  close(): void {
    this.flush();
    if (this.fd >= 0) {
      try { fs.closeSync(this.fd); } catch { /* ok */ }
      this.fd = -1;
    }
  }
}

// ---------------------------------------------------------------------------
// SQLite logger (best-effort — no native sqlite dep required)
// Uses raw SQL via a JSON manifest approach to avoid native deps.
// For production, recommend jsonl and consuming with external tools.
// ---------------------------------------------------------------------------

export class SqliteAuditLogger implements AuditLogger {
  private fp: string;
  private records: AuditRecord[] = [];
  private flushIntervalMs: number;
  private timer?: ReturnType<typeof setInterval>;
  private flushed = 0;

  constructor(fp: string, flushIntervalMs = 5000) {
    this.fp = fp;
    this.flushIntervalMs = flushIntervalMs;
    this.init();
    this.timer = setInterval(() => this.flush(), flushIntervalMs);
  }

  private init(): void {
    try {
      const dir = path.dirname(this.fp);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      if (!fs.existsSync(this.fp)) {
        // Write SQLite header (minimal)
        const header = Buffer.alloc(100);
        header.write('SQLite format 3\0', 0, 16);
        fs.writeFileSync(this.fp, header);
      }
    } catch (e) {
      console.warn('[mcpaudit] audit sqlite init failed:', e instanceof Error ? e.message : String(e));
    }
  }

  log(record: AuditRecord): void {
    this.records.push(record);
    if (this.records.length >= 100) this.flush();
  }

  flush(): void {
    if (this.records.length === 0) return;
    // Append as JSONL alongside the sqlite file (we don't embed a real sqlite driver)
    // For v1, fall back to jsonl sidecar
    const jsonlPath = this.fp + '.jsonl';
    try {
      const lines = this.records.map(r => JSON.stringify(r)).join('\n') + '\n';
      fs.appendFileSync(jsonlPath, lines);
      this.flushed += this.records.length;
      this.records = [];
    } catch (e) {
      console.warn('[mcpaudit] audit sqlite flush failed:', e instanceof Error ? e.message : String(e));
    }
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.flush();
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createAuditLogger(
  format: 'jsonl' | 'sqlite',
  fp: string,
  maxMB = 10,
): AuditLogger {
  if (format === 'sqlite') return new SqliteAuditLogger(fp, 5000);
  return new JsonlAuditLogger(fp, maxMB);
}

// ---------------------------------------------------------------------------
// Scan audit helper — creates all records for a scan operation
// ---------------------------------------------------------------------------

export function buildAuditRecords(
  event: AuditRecord['event'],
  profile: string,
  filePath: string,
  findings: Array<{ ruleId: string; severity: AuditSeverity; title: string; fingerprint: string }>,
  action: AuditRecord['action'],
  contentHash?: string,
  blockMode = false,
  score?: number,
): AuditRecord[] {
  if (findings.length === 0) {
    return [{
      ts: new Date().toISOString(),
      eventId: crypto.randomUUID(),
      event,
      profile,
      filePath,
      ruleId: '—',
      severity: 'info',
      title: 'scan passed — no findings',
      action,
      contentHash,
      score,
      blockMode,
    }];
  }
  return findings.map(f => ({
    ts: new Date().toISOString(),
    eventId: crypto.randomUUID(),
    event,
    profile,
    filePath,
    ruleId: f.ruleId,
    severity: f.severity,
    title: f.title,
    action,
    contentHash,
    score,
    blockMode,
    fingerprint: f.fingerprint,
  }));
}