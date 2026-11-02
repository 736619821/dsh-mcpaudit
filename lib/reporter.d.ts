/**
 * dsh-mcpaudit — 多格式报告输出器
 */
export interface Location {
    line: number;
    column: number;
    offset: number;
}
export interface EnhancedFinding {
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    detail: string;
    source: string;
    filePath: string;
    line: number;
    column: number;
    matchedText: string;
    redactedExcerpt: string;
    contextBefore: Array<{ line: number; content: string }>;
    contextAfter: Array<{ line: number; content: string }>;
    fingerprint: string;
}
export interface FileReport {
    name: string;
    path: string;
    score: number;
    totalFindings: number;
    findings: EnhancedFinding[];
    skippedProtected: boolean;
    skippedProtectedReason?: string;
}
export interface FullReport {
    version: string;
    generatedAt: string;
    scannerVersion: string;
    targets: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    score: number;
    files: FileReport[];
    protectedDirsSkipped?: Array<{ path: string; reason: string }>;
}
export declare function buildEnhancedFindings(filePath: string, content: string, rawFindings: Array<{
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    detail: string;
    source: string;
    excerpt: string;
}>, contextLines?: number, redactEnabled?: boolean): EnhancedFinding[];
export declare function toMarkdown(report: FullReport, showContext?: boolean): string;
export declare function toSARIF(report: FullReport, version?: string): object;
export interface ReportOutput {
    json: FullReport;
    markdown?: string;
    sarif?: object;
}
export declare function buildReportOutput(files: FileReport[], totalTargets: number, version?: string, format?: 'json' | 'markdown' | 'sarif' | 'all', showContext?: boolean): ReportOutput;