/**
 * dsh-mcpaudit 扫描器：扫描文件/目录中的 skill 与 MCP 配置
 */
export interface ScanTarget {
    kind: 'dir' | 'file';
    name: string;
    filePath: string;
    content: string;
}
export interface SkippedDir {
    path: string;
    reason: string;
}
export interface ScanResult {
    targets: ScanTarget[];
    skipped: SkippedDir[];
}
/** 默认扫描位置（常见 MCP 配置 + skill 目录） */
export declare function defaultPaths(): string[];
/** 扫描全部目标（只返回目标） */
export declare function scanAll(extraPaths?: string[]): ScanTarget[];
/** 扫描全部目标，附带被保护跳过目录信息 */
export declare function scanAllWithInfo(extraPaths?: string[]): ScanResult;