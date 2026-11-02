/**
 * dsh-mcpaudit — 审计日志持久化
 */
export declare type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface AuditRecord {
    ts: string;
    eventId: string;
    event: 'scan' | 'block' | 'alert' | 'lifecycle_load' | 'lifecycle_register';
    profile: string;
    filePath: string;
    ruleId: string;
    severity: AuditSeverity;
    title: string;
    action: 'blocked' | 'alert' | 'logged' | 'passed';
    contentHash?: string;
    score?: number;
    blockMode?: boolean;
    fingerprint?: string;
}
export interface AuditLogger {
    log(record: AuditRecord): void;
    flush(): void;
    close(): void;
}
export declare class JsonlAuditLogger implements AuditLogger {
    constructor(fp: string, maxMB?: number);
    log(record: AuditRecord): void;
    flush(): void;
    close(): void;
}
export declare class SqliteAuditLogger implements AuditLogger {
    constructor(fp: string, flushIntervalMs?: number);
    log(record: AuditRecord): void;
    flush(): void;
    close(): void;
}
export declare function createAuditLogger(format: 'jsonl' | 'sqlite', fp: string, maxMB?: number): AuditLogger;
export declare function buildAuditRecords(event: AuditRecord['event'], profile: string, filePath: string, findings: Array<{
    ruleId: string;
    severity: AuditSeverity;
    title: string;
    fingerprint: string;
}>, action: AuditRecord['action'], contentHash?: string, blockMode?: boolean, score?: number): AuditRecord[];