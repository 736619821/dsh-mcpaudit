/**
 * dsh-mcpaudit — 配置加载器
 * 读取同目录的 guard-rules.yaml，与内置规则合并
 */
export interface RuleOverride {
    enabled?: boolean;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}
export interface WhitelistEntry {
    paths: string[];
    hashes: string[];
}
export interface LifecycleConfig {
    autoScan: boolean;
    blockMode: boolean;
    alertOnly: boolean;
    blockMinSeverity: 'critical' | 'high' | 'medium';
}
export interface AuditConfig {
    enabled: boolean;
    format: 'jsonl' | 'sqlite';
    dbPath: string;
    jsonlPath: string;
    maxSizeMB: number;
    showSkippedDirs: boolean;
}
export interface ReportConfig {
    defaultFormat: 'json' | 'markdown' | 'sarif';
    showContextLines: boolean;
    sarifVersion: string;
    embedAllFormats: boolean;
}
export interface ProtectedDirsConfig {
    protectedDirs: string[];
    alwaysProtectSensitiveDirs: boolean;
    minReportSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    redactInReport: boolean;
    incremental: boolean;
    hashStorePath: string;
}
export interface GuardConfig {
    rules: Record<string, RuleOverride>;
    whitelist: WhitelistEntry;
    lifecycle: LifecycleConfig;
    audit: AuditConfig;
    report: ReportConfig;
    protectedDirs: ProtectedDirsConfig;
}
export declare const DEFAULT_GUARD_CONFIG: GuardConfig;
export declare function loadGuardConfig(configPath?: string): GuardConfig;
export declare function clearConfigCache(): void;
export declare function sha256Of(content: string): string;
export declare function matchHash(hash: string, patterns: string[]): boolean;
export declare function matchPath(filePath: string, patterns: string[]): boolean;