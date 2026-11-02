/**
 * dsh-mcpaudit — 审计日志持久化
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
function rotateIfNeeded(fp, maxMB) {
    try {
        const st = fs.statSync(fp);
        if (st.size > maxMB * 1024 * 1024) {
            const ts = new Date().toISOString().replace(/[:.]/g, '-');
            const rotated = `${fp.toString()}.${ts}.rotated`;
            fs.renameSync(fp, rotated);
        }
    }
    catch {
        // no rotation needed
    }
}
class JsonlAuditLogger {
    constructor(fp, maxMB = 10) {
        this.fp = fp;
        this.maxMB = maxMB;
        this.fd = -1;
        this.count = 0;
        this.init();
    }
    init() {
        try {
            const dir = path.dirname(this.fp);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            rotateIfNeeded(this.fp, this.maxMB);
            this.fd = fs.openSync(this.fp, 'a');
        }
        catch (e) {
            console.warn('[mcpaudit] audit: failed to open log file:', e instanceof Error ? e.message : String(e));
        }
    }
    log(record) {
        if (this.fd < 0) return;
        try {
            const line = JSON.stringify(record) + '\n';
            fs.writeSync(this.fd, line);
            this.count++;
        }
        catch (e) {
            console.warn('[mcpaudit] audit: write failed:', e instanceof Error ? e.message : String(e));
        }
    }
    flush() {
        if (this.fd >= 0) {
            try { fs.fsyncSync(this.fd); }
            catch { /* ok */ }
        }
    }
    close() {
        this.flush();
        if (this.fd >= 0) {
            try { fs.closeSync(this.fd); }
            catch { /* ok */ }
            this.fd = -1;
        }
    }
}
class SqliteAuditLogger {
    constructor(fp, flushIntervalMs = 5000) {
        this.fp = fp;
        this.records = [];
        this.flushIntervalMs = flushIntervalMs;
        this.flushed = 0;
        this.init();
        this.timer = setInterval(() => this.flush(), flushIntervalMs);
    }
    init() {
        try {
            const dir = path.dirname(this.fp);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            if (!fs.existsSync(this.fp)) {
                const header = Buffer.alloc(100);
                header.write('SQLite format 3\0', 0, 16);
                fs.writeFileSync(this.fp, header);
            }
        }
        catch (e) {
            console.warn('[mcpaudit] audit sqlite init failed:', e instanceof Error ? e.message : String(e));
        }
    }
    log(record) {
        this.records.push(record);
        if (this.records.length >= 100) this.flush();
    }
    flush() {
        if (this.records.length === 0) return;
        const jsonlPath = this.fp + '.jsonl';
        try {
            const lines = this.records.map(r => JSON.stringify(r)).join('\n') + '\n';
            fs.appendFileSync(jsonlPath, lines);
            this.flushed += this.records.length;
            this.records = [];
        }
        catch (e) {
            console.warn('[mcpaudit] audit sqlite flush failed:', e instanceof Error ? e.message : String(e));
        }
    }
    close() {
        if (this.timer) clearInterval(this.timer);
        this.flush();
    }
}
export function createAuditLogger(format, fp, maxMB = 10) {
    if (format === 'sqlite') return new SqliteAuditLogger(fp, 5000);
    return new JsonlAuditLogger(fp, maxMB);
}
export function buildAuditRecords(event, profile, filePath, findings, action, contentHash, blockMode = false, score) {
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
export { JsonlAuditLogger, SqliteAuditLogger };