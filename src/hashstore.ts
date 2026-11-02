/**
 * dsh-mcpaudit — 增量扫描哈希存储
 * 记录文件 SHA-256，只扫描改动过的文件
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { sha256Of } from './config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HashEntry {
  path: string;
  /** hex-encoded SHA-256 of the file content */
  hash: string;
  /** ISO timestamp of last scan */
  scannedAt: string;
  size: number;
}

export interface HashStore {
  version: 1;
  updatedAt: string;
  entries: Record<string, HashEntry>; // normalized path → entry
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return path.resolve(p).replace(/\\/g, '/').toLowerCase();
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

export function loadHashStore(storePath: string): HashStore {
  try {
    if (fs.existsSync(storePath)) {
      const raw = fs.readFileSync(storePath, 'utf-8');
      return JSON.parse(raw) as HashStore;
    }
  } catch {
    // corrupted / missing → fresh
  }
  return { version: 1, updatedAt: new Date().toISOString(), entries: {} };
}

export function saveHashStore(storePath: string, store: HashStore): void {
  try {
    const dir = path.dirname(storePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(storePath, JSON.stringify(store, null, 2), 'utf-8');
  } catch (e) {
    console.warn('[mcpaudit] failed to save hash store:', e instanceof Error ? e.message : String(e));
  }
}

// ---------------------------------------------------------------------------
// Compute file hash (with size check)
// ---------------------------------------------------------------------------

function hashFile(filePath: string): HashEntry | null {
  try {
    const st = fs.statSync(filePath);
    if (st.size > 256 * 1024) return null; // skip >256KB
    const content = fs.readFileSync(filePath, 'utf-8');
    return {
      path: filePath,
      hash: sha256Of(content),
      scannedAt: new Date().toISOString(),
      size: st.size,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Incremental scan: diff current vs stored hashes
// ---------------------------------------------------------------------------

export interface ScanChange {
  added: string[];    // new files not in store
  modified: string[]; // content hash changed
  removed: string[];  // files in store but no longer on disk
  unchanged: string[]; // files with same hash
}

export function diffAgainstStore(
  files: string[],
  store: HashStore,
): ScanChange {
  const change: ScanChange = { added: [], modified: [], removed: [], unchanged: [] };
  const storedPaths = new Set(Object.keys(store.entries));

  for (const f of files) {
    const key = normalizePath(f);
    storedPaths.delete(key);
    const entry = hashFile(f);
    if (!entry) continue;

    const existing = store.entries[key];
    if (!existing) {
      change.added.push(f);
    } else if (existing.hash !== entry.hash) {
      change.modified.push(f);
    } else {
      change.unchanged.push(f);
    }
  }

  // Anything left in storedPaths was deleted
  change.removed = Array.from(storedPaths);

  return change;
}

// ---------------------------------------------------------------------------
// Merge new hashes back into store
// ---------------------------------------------------------------------------

export function applyChangesToStore(
  store: HashStore,
  files: string[],
): HashStore {
  for (const f of files) {
    const key = normalizePath(f);
    const entry = hashFile(f);
    if (entry) {
      store.entries[key] = entry;
    }
  }
  store.updatedAt = new Date().toISOString();
  return store;
}

// ---------------------------------------------------------------------------
// Purge removed files from store
// ---------------------------------------------------------------------------

export function purgeRemovedFromStore(store: HashStore, removed: string[]): HashStore {
  for (const f of removed) {
    delete store.entries[normalizePath(f)];
  }
  store.updatedAt = new Date().toISOString();
  return store;
}