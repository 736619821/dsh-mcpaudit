/**
 * dsh-mcpaudit — 配置加载器
 * 读取同目录的 guard-rules.yaml，与内置规则合并
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------

export const DEFAULT_GUARD_CONFIG: GuardConfig = {
  rules: {},
  whitelist: { paths: [], hashes: [] },
  lifecycle: {
    autoScan: false,
    blockMode: false,
    alertOnly: false,
    blockMinSeverity: 'critical',
  },
  audit: {
    enabled: false,
    format: 'jsonl',
    dbPath: '',
    jsonlPath: '',
    maxSizeMB: 10,
    showSkippedDirs: true,
  },
  report: {
    defaultFormat: 'json',
    showContextLines: true,
    sarifVersion: '2.1.0',
    embedAllFormats: false,
  },
  protectedDirs: {
    protectedDirs: ['.ssh', '.aws', '.gnupg', '.git/credentials', '.git/config'],
    alwaysProtectSensitiveDirs: true,
    minReportSeverity: 'info',
    redactInReport: true,
    incremental: true,
    hashStorePath: '',
  },
};

// ---------------------------------------------------------------------------
// YAML parser (safe, no external dep — hand-rolled subset)
// ---------------------------------------------------------------------------

function parseYamlValue(tokens: string[]): unknown {
  const t = tokens[0]?.trim();
  if (!t) return undefined;

  // Array
  if (t === '[' || t === ']') return undefined; // handled by parseYamlArray
  if (t.startsWith('[') && t.endsWith(']')) {
    const inner = t.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map((s) => parseYamlValue([s.trim()]));
  }

  // Boolean
  if (t === 'true') return true;
  if (t === 'false') return false;

  // Number
  const num = Number(t);
  if (!isNaN(num) && t === String(num)) return num;

  // Quoted string
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }

  return t;
}

function parseYamlArray(lines: string[]): unknown[] {
  const result: unknown[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.replace(/^(\s|-)\s*/, '').trim();
    if (!trimmed || trimmed === '[' || trimmed === ']') { i++; continue; }
    // Nested array (indented list items)
    if (trimmed.startsWith('-')) {
      const val = trimmed.replace(/^-\s*/, '').trim();
      if (val === '[') {
        // find matching ]
        let j = i + 1;
        let depth = 1;
        const subLines: string[] = [];
        while (j < lines.length && depth > 0) {
          const l = lines[j].replace(/^\s+/, '');
          if (l.startsWith('-')) depth--;
          subLines.push(lines[j]);
          j++;
        }
        result.push(parseYamlArray(subLines));
        i = j;
      } else {
        result.push(parseYamlValue([val]));
        i++;
      }
    } else {
      result.push(parseYamlValue([trimmed]));
      i++;
    }
  }
  return result;
}

function parseYaml(raw: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = raw.split('\n');
  let currentSection: Record<string, unknown> | null = null;
  let currentKey = '';
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Blank / comment
    if (!trimmed || trimmed.startsWith('#')) { i++; continue; }

    // Section header
    const sectionMatch = trimmed.match(/^(\w+):\s*$/);
    if (sectionMatch && !trimmed.includes('[') && !trimmed.includes('{')) {
      currentKey = sectionMatch[1];
      currentSection = {};
      result[currentKey] = currentSection;
      i++;
      continue;
    }

    // Inline section
    const inlineSection = trimmed.match(/^(\w+):\s*(.+)/);
    if (inlineSection && currentSection === null) {
      const [, key, val] = inlineSection;
      const v = parseYamlValue([val.trim()]);
      if (Array.isArray(v) && key === 'protectedDirs') {
        result[key] = v;
      } else if (v !== undefined) {
        result[key] = v;
      }
      i++;
      continue;
    }

    // Key: value
    const kvMatch = trimmed.match(/^(\w[\w-]*):\s*(.+)/);
    if (kvMatch) {
      const [, key, val] = kvMatch;
      const v = parseYamlValue([val.trim()]);
      if (currentSection) {
        currentSection[key] = v;
      } else {
        result[key] = v;
      }
      i++;
      continue;
    }

    i++;
  }

  return result;
}

function deepMerge<T extends Record<string, unknown>>(base: T, override: Partial<T>): T {
  const out = { ...base } as T;
  for (const [k, v] of Object.entries(override)) {
    if (v !== undefined) {
      if (typeof v === 'object' && v !== null && !Array.isArray(v) && typeof base[k] === 'object' && base[k] !== null) {
        (out as Record<string, unknown>)[k] = deepMerge(base[k] as Record<string, unknown>, v as Record<string, unknown>);
      } else {
        (out as Record<string, unknown>)[k] = v;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

let cachedConfig: GuardConfig | null = null;

export function loadGuardConfig(configPath?: string): GuardConfig {
  if (cachedConfig) return cachedConfig;

  const searchPaths: string[] = [];
  if (configPath) {
    searchPaths.push(configPath);
  } else {
    // Look for guard-rules.yaml in same directory as index.js (lib/)
    const libDir = path.dirname(process.argv[1] ?? import.meta.filename ?? __filename);
    searchPaths.push(path.join(libDir, 'guard-rules.yaml'));
    // Also check project root (dev mode)
    const root = path.resolve(libDir, '..');
    searchPaths.push(path.join(root, 'guard-rules.yaml'));
  }

  let rawYaml = '';
  for (const p of searchPaths) {
    try {
      if (fs.existsSync(p)) {
        rawYaml = fs.readFileSync(p, 'utf-8');
        break;
      }
    } catch {
      // Try next
    }
  }

  if (!rawYaml) {
    cachedConfig = { ...DEFAULT_GUARD_CONFIG };
    return cachedConfig;
  }

  try {
    const parsed = parseYaml(rawYaml) as Partial<GuardConfig>;

    // Merge sections
    const merged = deepMerge(DEFAULT_GUARD_CONFIG, {
      rules: (parsed.rules ?? {}) as Record<string, RuleOverride>,
      whitelist: (parsed.whitelist ?? {}) as WhitelistEntry,
      lifecycle: (parsed.lifecycle ?? {}) as Partial<LifecycleConfig>,
      audit: (parsed.audit ?? {}) as Partial<AuditConfig>,
      report: (parsed.report ?? {}) as Partial<ReportConfig>,
      protectedDirs: (parsed.protectedDirs ?? {}) as Partial<ProtectedDirsConfig>,
    });

    cachedConfig = merged;
    return cachedConfig;
  } catch (e) {
    console.warn('[mcpaudit] failed to parse guard-rules.yaml, using defaults:', e instanceof Error ? e.message : String(e));
    cachedConfig = { ...DEFAULT_GUARD_CONFIG };
    return cachedConfig;
  }
}

export function clearConfigCache(): void {
  cachedConfig = null;
}

// ---------------------------------------------------------------------------
// Hash utilities
// ---------------------------------------------------------------------------

export function sha256Of(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

export function matchHash(hash: string, patterns: string[]): boolean {
  for (const p of patterns) {
    // Support prefix match (first 8 chars)
    const pat = p.toLowerCase();
    const h = hash.toLowerCase();
    if (h === pat || (pat.length <= h.length && h.startsWith(pat))) return true;
  }
  return false;
}

export function matchPath(filePath: string, patterns: string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const p of patterns) {
    const patternNorm = p.replace(/\\/g, '/');
    if (normalized === patternNorm || normalized.startsWith(patternNorm + '/') || normalized.endsWith('/' + patternNorm)) {
      return true;
    }
  }
  return false;
}