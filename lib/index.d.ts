/**
 * dsh-mcpaudit - DeepSeek Harness 安全审计插件 (v1.0.0)
 */
import { ToolObserver } from './runtime/observer.js';
import { buildDefaultEngine, scanText, redact, severityScore } from './rules.js';
export declare const name = "mcpaudit";
export declare const inject: string[];
export declare const PLUGIN_VERSION = "1.0.0";
/** 运行时观察器（v1.0，只记录不拦截） */
export declare const observer: ToolObserver;
export { buildDefaultEngine, scanText, redact, severityScore };
export declare function apply(ctx: unknown): void;
declare const _default: {
    name: string;
    inject: string[];
    apply: typeof apply;
};
export default _default;