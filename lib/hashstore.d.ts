/**
 * dsh-mcpaudit — 增量扫描哈希存储
 */
export interface HashEntry {
    path: string;
    hash: string;
    scannedAt: string;
    size: number;
}
export interface HashStore {
    version: 1;
    updatedAt: string;
    entries: Record<string, HashEntry>;
}
export declare function loadHashStore(storePath: string): HashStore;
export declare function saveHashStore(storePath: string, store: HashStore): void;
export interface ScanChange {
    added: string[];
    modified: string[];
    removed: string[];
    unchanged: string[];
}
export declare function diffAgainstStore(files: string[], store: HashStore): ScanChange;
export declare function applyChangesToStore(store: HashStore, files: string[]): HashStore;
export declare function purgeRemovedFromStore(store: HashStore, removed: string[]): HashStore;