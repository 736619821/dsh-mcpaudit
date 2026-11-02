/**
 * dsh-mcpaudit — 配置加载器
 * 读取同目录的 guard-rules.yaml，与内置规则合并
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------
const DEFAULT_GUARD_CONFIG = {
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
// Minimal YAML parser (hand-rolled, no external deps)
// ---------------------------------------------------------------------------
function parseYamlValue(tokens) {
    const t = tokens[0]?.trim();
    if (!t) return undefined;
    if (t === 'true') return true;
    if (t === 'false') return false;
    const num = Number(t);
    if (!isNaN(num) && t === String(num)) return num;
    if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
        return t.slice(1, -1);
    }
    return t;
}

function parseYamlArray(lines) {
    const result = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.replace(/^(\s|-)\s*/, '').trim();
        if (!trimmed || trimmed === '[' || trimmed === ']') { i++; continue; }
        if (trimmed.startsWith('-')) {
            const val = trimmed.replace(/^-\s*/, '').trim();
            if (val === '[') {
                let j = i + 1, depth = 1;
                const subLines = [];
                while (j < lines.length && depth > 0) {
                    const l = lines[j].replace(/^\s+/, '');
                    if (l.startsWith('-')) depth--;
                    subLines.push(lines[j]);
                    j++;
                }
                result.push(parseYamlArray(subLines));
                i = j;
            }
            else {
                result.push(parseYamlValue([val]));
                i++;
            }
        }
        else {
            result.push(parseYamlValue([trimmed]));
            i++;
        }
    }
    return result;
}

function parseYaml(raw) {
    const result = {};
    const lines = raw.split('\n');
    let currentSection = null;
    let currentKey = '';
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) { i++; continue; }
        const sectionMatch = trimmed.match(/^(\w+):\s*$/);
        if (sectionMatch && !trimmed.includes('[') && !trimmed.includes('{')) {
            currentKey = sectionMatch[1];
            currentSection = {};
            result[currentKey] = currentSection;
            i++;
            continue;
        }
        const inlineSection = trimmed.match(/^(\w+):\s*(.+)/);
        if (inlineSection && currentSection === null) {
            const [, key, val] = inlineSection;
            const v = parseYamlValue([val.trim()]);
            if (Array.isArray(v) && key === 'protectedDirs') {
                result[key] = v;
            }
            else if (v !== undefined) {
                result[key] = v;
            }
            i++;
            continue;
        }
        const kvMatch = trimmed.match(/^(\w[\w-]*):\s*(.+)/);
        if (kvMatch) {
            const [, key, val] = kvMatch;
            const v = parseYamlValue([val.trim()]);
            if (currentSection) {
                currentSection[key] = v;
            }
            else {
                result[key] = v;
            }
            i++;
            continue;
        }
        i++;
    }
    return result;
}

function deepMerge(base, override) {
    const out = { ...base };
    for (const [k, v] of Object.entries(override)) {
        if (v !== undefined) {
            if (typeof v === 'object' && v !== null && !Array.isArray(v) && typeof base[k] === 'object' && base[k] !== null) {
                out[k] = deepMerge(base[k], v);
            }
            else {
                out[k] = v;
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------
let cachedConfig = null;

export function loadGuardConfig(configPath) {
    if (cachedConfig) return cachedConfig;
    const searchPaths = [];
    if (configPath) {
        searchPaths.push(configPath);
    }
    else {
        const libDir = path.dirname(process.argv[1] ?? import.meta.filename ?? __filename);
        searchPaths.push(path.join(libDir, 'guard-rules.yaml'));
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
        }
        catch {
            // try next
        }
    }
    if (!rawYaml) {
        cachedConfig = { ...DEFAULT_GUARD_CONFIG };
        return cachedConfig;
    }
    try {
        const parsed = parseYaml(rawYaml);
        const merged = deepMerge(DEFAULT_GUARD_CONFIG, {
            rules: (parsed.rules ?? {}),
            whitelist: (parsed.whitelist ?? {}),
            lifecycle: (parsed.lifecycle ?? {}),
            audit: (parsed.audit ?? {}),
            report: (parsed.report ?? {}),
            protectedDirs: (parsed.protectedDirs ?? {}),
        });
        cachedConfig = merged;
        return cachedConfig;
    }
    catch (e) {
        console.warn('[mcpaudit] failed to parse guard-rules.yaml, using defaults:', e instanceof Error ? e.message : String(e));
        cachedConfig = { ...DEFAULT_GUARD_CONFIG };
        return cachedConfig;
    }
}

export function clearConfigCache() { cachedConfig = null; }

// ---------------------------------------------------------------------------
// Hash utilities
// ---------------------------------------------------------------------------
export function sha256Of(content) {
    return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

export function matchHash(hash, patterns) {
    for (const p of patterns) {
        const pat = p.toLowerCase();
        const h = hash.toLowerCase();
        if (h === pat || (pat.length <= h.length && h.startsWith(pat))) return true;
    }
    return false;
}

export function matchPath(filePath, patterns) {
    const normalized = filePath.replace(/\\/g, '/');
    for (const p of patterns) {
        const patternNorm = p.replace(/\\/g, '/');
        if (normalized === patternNorm || normalized.startsWith(patternNorm + '/') || normalized.endsWith('/' + patternNorm)) {
            return true;
        }
    }
    return false;
}

export { DEFAULT_GUARD_CONFIG };