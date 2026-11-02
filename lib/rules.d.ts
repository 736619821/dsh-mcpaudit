/**
 * dsh-mcpaudit 检测规则引擎（TypeScript）
 * 17 条规则：UNI/B64/INJ/PTH/SHL/PWD/BH/HMG/NET/REG/FILE/CMD/ENV
 */
export interface Finding {
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    detail: string;
    source: string;
    excerpt: string;
}
declare type Check = (text: string) => string[];
export interface Rule {
    id: string;
    name: string;
    severity: Finding['severity'];
    description: string;
    check: Check;
}
/** 构建默认规则引擎（17 条） */
export declare function buildDefaultEngine(): Rule[];
/** 对一段文本跑全部规则，返回命中列表 */
export declare function scanText(text: string, source: string, rules?: Rule[]): Finding[];
/** 评分：100 - 扣分 */
export declare function severityScore(findings: Finding[]): number;
/** 脱敏：密钥模式替换为 *** */
export declare function redact(s: string): string;
export {};