/**
 * dsh-mcpaudit — Cordis 生命周期钩子
 */
export interface LifecycleBlockResult {
    allowed: boolean;
    reason?: string;
    report?: object;
    severity?: string;
}
export interface LifecycleEvent {
    kind: 'skill' | 'mcp';
    target: string;
    content?: string;
    contentHash?: string;
    profile: string;
    source?: string;
}
export declare function scanForLifecycle(content: string, target: string, profile: string): {
    findings: ReturnType<typeof import('./reporter.js').buildEnhancedFindings>;
    allowed: boolean;
    reason?: string;
};
export declare function makeLifecycleHandler(): (event: LifecycleEvent) => LifecycleBlockResult;
export interface CordisContext {
    on?: (event: string, handler: (...args: unknown[]) => void) => void;
    emit?: (event: string, ...args: unknown[]) => boolean;
    tools?: {
        preExecute?: (hook: (call: unknown, next: () => unknown) => unknown) => void;
    };
}
export declare function registerLifecycleHooks(ctx: CordisContext): ((event: LifecycleEvent) => LifecycleBlockResult) | null;