/**
 * dsh-mcpaudit — 增量扫描哈希存储
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { sha256Of } from './config.js';
function normalizePath(p) {
    return path.resolve(p).replace(/\\/g, '/').toLowerCase();
}
export function loadHashStore(storePath) {
    try {
        if (fs.existsSync(storePath)) {
            const raw = fs.readFileSync(storePath, 'utf-8');
            return JSON.parse(raw);
        }
    }
    catch {
        // fresh
    }
    return { version: 1, updatedAt: new Date().toISOString(), entries: {} };
}
export function saveHashStore(storePath, store) {
    try {
        const dir = path.dirname(storePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(storePath, JSON.stringify(store, null, 2), 'utf-8');
    }
    catch (e) {
        console.warn('[mcpaudit] failed to save hash store:', e instanceof Error ? e.message : String(e));
    }
}
function hashFile(filePath) {
    try {
        const st = fs.statSync(filePath);
        if (st.size > 256 * 1024) return null;
        const content = fs.readFileSync(filePath, 'utf-8');
        return {
            path: filePath,
            hash: sha256Of(content),
            scannedAt: new Date().toISOString(),
            size: st.size,
        };
    }
    catch {
        return null;
    }
}
export function diffAgainstStore(files, store) {
    const change = { added: [], modified: [], removed: [], unchanged: [] };
    const storedPaths = new Set(Object.keys(store.entries));
    for (const f of files) {
        const key = normalizePath(f);
        storedPaths.delete(key);
        const entry = hashFile(f);
        if (!entry) continue;
        const existing = store.entries[key];
        if (!existing) {
            change.added.push(f);
        }
        else if (existing.hash !== entry.hash) {
            change.modified.push(f);
        }
        else {
            change.unchanged.push(f);
        }
    }
    change.removed = Array.from(storedPaths);
    return change;
}
export function applyChangesToStore(store, files) {
    for (const f of files) {
        const key = normalizePath(f);
        const entry = hashFile(f);
        if (entry) store.entries[key] = entry;
    }
    store.updatedAt = new Date().toISOString();
    return store;
}
export function purgeRemovedFromStore(store, removed) {
    for (const f of removed) {
        delete store.entries[normalizePath(f)];
    }
    store.updatedAt = new Date().toISOString();
    return store;
}