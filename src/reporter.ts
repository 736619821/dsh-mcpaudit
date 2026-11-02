/**
 * dsh-mcpaudit — 多格式报告输出器
 * 支持 JSON / Markdown / SARIF 三种格式
 * 包含行号、列号、前后 5 行上下文、原始/脱敏 excerpt
 */

import * as crypto from 'node:crypto';
import { redact } from './rules.js';

// ---------------------------------------------------------------------------
// Enhanced Finding model
// ---------------------------------------------------------------------------

export interface Location {
  line: number;   // 1-based
  column: number; // 1-based
  offset: number; // byte offset in full text
}

export interface EnhancedFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  source: string;
  filePath: string;
  /** 0-based line index */
  line: number;
  column: number;
  /** The actual matched text from the file */
  matchedText: string;
  /** Redacted version for display */
  redactedExcerpt: string;
  /** Pre-context: array of [lineContent, lineNumber] */
  contextBefore: Array<{ line: number; content: string }>;
  /** Post-context: array of [lineContent, lineNumber] */
  contextAfter: Array<{ line: number; content: string }>;
  /** SHA-256 of the raw matched text for fingerprinting */
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
  /** Formatted as ISO 8601 */
  scanDuration?: string;
  files: FileReport[];
  protectedDirsSkipped?: Array<{ path: string; reason: string }>;
}

// ---------------------------------------------------------------------------
// Line/column tracker
// ---------------------------------------------------------------------------

function indexLines(text: string): Array<{ line: number; start: number; end: number }> {
  const lines: Array<{ line: number; start: number; end: number }> = [];
  let lineNum = 1;
  let pos = 0;
  let lastNl = -1;
  while (pos < text.length) {
    if (text[pos] === '\n') {
      lines.push({ line: lineNum, start: lastNl + 1, end: pos });
      lineNum++;
      lastNl = pos;
    }
    pos++;
  }
  // last line (no trailing newline)
  lines.push({ line: lineNum, start: lastNl + 1, end: text.length });
  return lines;
}

function offsetToLineCol(text: string, offset: number): Location {
  const idx = indexLines(text);
  for (const entry of idx) {
    if (offset >= entry.start && offset <= entry.end) {
      return { line: entry.line, column: offset - entry.start + 1, offset };
    }
  }
  // fallback
  return { line: idx.length, column: 1, offset };
}

/** Extract position info from a "位置 NNN: …" hit string */
function parseHitPosition(hitStr: string): { offset: number; context: string } {
  const m = hitStr.match(/位置 (\d+):/);
  const offset = m ? parseInt(m[1], 10) : 0;
  const colonIdx = hitStr.indexOf(':');
  const context = colonIdx >= 0 ? hitStr.slice(colonIdx + 1).trim() : hitStr;
  return { offset, context };
}

// ---------------------------------------------------------------------------
// Build enhanced findings from raw text + raw findings
// ---------------------------------------------------------------------------

interface RawFinding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  source: string;
  excerpt: string;
}

export function buildEnhancedFindings(
  filePath: string,
  content: string,
  rawFindings: RawFinding[],
  contextLines = 5,
  redactEnabled = true,
): EnhancedFinding[] {
  const enhanced: EnhancedFinding[] = [];
  const lines = content.split('\n');
  const lineIndex: Record<number, string> = {};
  lines.forEach((l, i) => { lineIndex[i + 1] = l; });

  for (const f of rawFindings) {
    const { offset, context } = parseHitPosition(f.excerpt);
    const loc = offsetToLineCol(content, offset);

    const ctxBefore: EnhancedFinding['contextBefore'] = [];
    const ctxAfter: EnhancedFinding['contextAfter'] = [];

    for (let i = loc.line - contextLines; i < loc.line; i++) {
      if (i >= 1 && lineIndex[i] !== undefined) ctxBefore.push({ line: i, content: lineIndex[i] });
    }
    for (let i = loc.line + 1; i <= loc.line + contextLines; i++) {
      if (lineIndex[i] !== undefined) ctxAfter.push({ line: i, content: lineIndex[i] });
    }

    const rawExcerpt = context.replace(/^…/, '').replace(/…$/, '');
    const redactedExcerpt = redactEnabled ? redact(rawExcerpt) : rawExcerpt;

    let fingerprint = '';
    try {
      fingerprint = crypto.createHash('sha256').update(rawExcerpt).digest('hex').slice(0, 16);
    } catch { /* ok */ }

    enhanced.push({
      ruleId: f.ruleId,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      source: f.source,
      filePath,
      line: loc.line,
      column: loc.column,
      matchedText: redactEnabled ? redact(rawExcerpt) : rawExcerpt,
      redactedExcerpt,
      contextBefore: ctxBefore,
      contextAfter: ctxAfter,
      fingerprint,
    });
  }

  return enhanced;
}

// ---------------------------------------------------------------------------
// Markdown reporter
// ---------------------------------------------------------------------------

function severityEmoji(s: string): string {
  const map: Record<string, string> = {
    critical: '🛑', high: '🔴', medium: '🟡', low: '🟢', info: '⚪',
  };
  return map[s] ?? '⚪';
}

function severityColor(s: string): string {
  const map: Record<string, string> = {
    critical: 'red', high: 'orange', medium: 'yellow', low: 'green', info: 'gray',
  };
  return map[s] ?? 'gray';
}

export function toMarkdown(report: FullReport, showContext = true): string {
  const lines: string[] = [];
  const total = report.critical + report.high + report.medium + report.low + report.info;

  lines.push(`# 🔒 mcpaudit 安全审计报告`);
  lines.push('');
  lines.push(`| 项目 | 值 |`);
  lines.push(`|------|---|`);
  lines.push(`| 扫描时间 | ${report.generatedAt} |`);
  lines.push(`| 扫描版本 | ${report.scannerVersion} |`);
  lines.push(`| 扫描文件数 | ${report.targets} |`);
  lines.push(`| 总风险数 | ${total} |`);
  lines.push(`| 安全评分 | **${report.score}** / 100 |`);
  lines.push(`| 🛑 Critical | ${report.critical} |`);
  lines.push(`| 🔴 High | ${report.high} |`);
  lines.push(`| 🟡 Medium | ${report.medium} |`);
  lines.push(`| 🟢 Low | ${report.low} |`);
  lines.push(`| ⚪ Info | ${report.info} |`);

  if (report.protectedDirsSkipped?.length) {
    lines.push('');
    lines.push(`## 🛡️ 保护目录（跳过扫描）`);
    for (const d of report.protectedDirsSkipped) {
      lines.push(`- \`${d.path}\` — ${d.reason}`);
    }
  }

  if (report.files.length === 0) {
    lines.push('');
    lines.push('✅ **未发现风险。**');
    return lines.join('\n');
  }

  for (const file of report.files) {
    lines.push('');
    lines.push(`## 📄 ${file.name}`);
    lines.push('');
    lines.push(`**路径:** \`${file.path}\``);
    lines.push(`**评分:** ${file.score}/100`);
    lines.push(`**风险数:** ${file.totalFindings}`);

    if (file.totalFindings === 0) {
      lines.push('✅ 此文件未发现风险。');
      continue;
    }

    // Group by severity
    const bySev = file.findings.reduce((acc, f) => {
      (acc[f.severity] ??= []).push(f);
      return acc;
    }, {} as Record<string, EnhancedFinding[]>);

    for (const sev of (['critical', 'high', 'medium', 'low', 'info'] as const)) {
      const items = bySev[sev];
      if (!items?.length) continue;

      for (const finding of items) {
        lines.push('');
        lines.push(`### ${severityEmoji(sev)} **[${finding.ruleId}]** ${finding.title}`);
        lines.push('');
        lines.push(`| 属性 | 值 |`);
        lines.push(`|------|---|`);
        lines.push(`| 严重度 | <span style="color:${severityColor(sev)}">**${sev.toUpperCase()}**</span> |`);
        lines.push(`| 文件 | \`${file.name}\` |`);
        lines.push(`| 位置 | 行 ${finding.line}, 列 ${finding.column} |`);
        lines.push(`| 指纹 | \`${finding.fingerprint}\` |`);

        lines.push('');
        lines.push('**匹配片段（脱敏）:**');
        lines.push('```');
        lines.push(finding.redactedExcerpt);
        lines.push('```');

        if (showContext) {
          if (finding.contextBefore.length) {
            lines.push('');
            lines.push(`**前 ${finding.contextBefore.length} 行:**`);
            lines.push('```');
            for (const { line: ln, content } of finding.contextBefore) {
              lines.push(`${String(ln).padStart(4)} | ${content}`);
            }
            lines.push('```');
          }
          lines.push('');
          lines.push(`**问题行 (${finding.line}):**`);
          lines.push('```');
          const actualLine = finding.contextBefore.length
            ? finding.contextAfter.find(l => l.line === finding.line) ?? { content: '?' }
            : { content: '?' };
          lines.push(`${String(finding.line).padStart(4)} | ${finding.contextBefore.find(l => l.line === finding.line)?.content ?? (finding.contextAfter.find(l => l.line === finding.line)?.content ?? '?')}`);
          lines.push('```');
          if (finding.contextAfter.filter(l => l.line !== finding.line).length) {
            lines.push('');
            lines.push(`**后 ${finding.contextAfter.length - 1} 行:**`);
            lines.push('```');
            for (const { line: ln, content } of finding.contextAfter) {
              if (ln === finding.line) continue;
              lines.push(`${String(ln).padStart(4)} | ${content}`);
            }
            lines.push('```');
          }
        }
      }
    }
  }

  lines.push('');
  lines.push('---');
  lines.push(`*报告由 mcpaudit v${report.scannerVersion} 生成 · ${report.generatedAt}*`);

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// SARIF reporter (v2.1.0)
// ---------------------------------------------------------------------------

export function toSARIF(report: FullReport, version = '2.1.0'): object {
  const runId = crypto.randomUUID();
  const results: object[] = [];

  for (const file of report.files) {
    for (const f of file.findings) {
      results.push({
        ruleId: f.ruleId,
        ruleIndex: 0,
        level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
        message: {
          text: `[${f.ruleId}] ${f.title}: ${f.redactedExcerpt}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: file.path.replace(/\\/g, '/'),
              uriBaseId: '%srcroot%',
            },
            region: {
              startLine: f.line,
              startColumn: f.column,
              snippet: {
                text: f.redactedExcerpt,
              },
            },
          },
        }],
        fingerprints: {
          '2.1:sh256': f.fingerprint,
        },
      });
    }
  }

  return {
    version,
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      uniqueId: { runGuid: runId, name: 'dsh-mcpaudit' },
      invocation: {
        commandLine: `mcpaudit scan`,
        startTime: report.generatedAt,
        endTime: new Date().toISOString(),
        machine: 'localhost',
        workingDirectory: '.',
      },
      results,
      tool: {
        driver: {
          name: 'dsh-mcpaudit',
          version: report.scannerVersion,
          informationUri: 'https://github.com/ChenLaoshiYF/dsh-mcpaudit',
          rules: Array.from(new Set(report.files.flatMap(f => f.findings.map(ff => ff.ruleId)))).map(rid => ({
            id: rid,
            name: rid,
          })),
        },
      },
    }],
  };
}

// ---------------------------------------------------------------------------
// Combined output
// ---------------------------------------------------------------------------

export interface ReportOutput {
  json: FullReport;
  markdown?: string;
  sarif?: object;
}

export function buildReportOutput(
  files: FileReport[],
  totalTargets: number,
  version = '1.0.0',
  format: 'json' | 'markdown' | 'sarif' | 'all' = 'all',
  showContext = true,
): ReportOutput {
  const now = new Date().toISOString();

  let critical = 0, high = 0, medium = 0, low = 0, info = 0;
  for (const f of files) {
    for (const finding of f.findings) {
      if (finding.severity === 'critical') critical++;
      else if (finding.severity === 'high') high++;
      else if (finding.severity === 'medium') medium++;
      else if (finding.severity === 'low') low++;
      else info++;
    }
  }

  const report: FullReport = {
    version: '1.0',
    generatedAt: now,
    scannerVersion: version,
    targets: totalTargets,
    findings: critical + high + medium + low + info,
    critical, high, medium, low, info,
    score: Math.max(0, 100 - critical * 40 - high * 20 - medium * 8 - low * 3 - info),
    files,
  };

  const out: ReportOutput = { json: report };
  if (format === 'markdown' || format === 'all') {
    out.markdown = toMarkdown(report, showContext);
  }
  if (format === 'sarif' || format === 'all') {
    out.sarif = toSARIF(report);
  }
  return out;
}