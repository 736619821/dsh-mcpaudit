/**
 * dsh-mcpaudit — 多格式报告输出器
 */
import * as crypto from 'node:crypto';
import { redact } from './rules.js';
function indexLines(text) {
    const lines = [];
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
    lines.push({ line: lineNum, start: lastNl + 1, end: text.length });
    return lines;
}
function offsetToLineCol(text, offset) {
    const idx = indexLines(text);
    for (const entry of idx) {
        if (offset >= entry.start && offset <= entry.end) {
            return { line: entry.line, column: offset - entry.start + 1, offset };
        }
    }
    return { line: idx.length, column: 1, offset };
}
function parseHitPosition(hitStr) {
    const m = hitStr.match(/位置 (\d+):/);
    const offset = m ? parseInt(m[1], 10) : 0;
    const colonIdx = hitStr.indexOf(':');
    const context = colonIdx >= 0 ? hitStr.slice(colonIdx + 1).trim() : hitStr;
    return { offset, context };
}
export function buildEnhancedFindings(filePath, content, rawFindings, contextLines = 5, redactEnabled = true) {
    const enhanced = [];
    const lines = content.split('\n');
    const lineIndex = {};
    lines.forEach((l, i) => { lineIndex[i + 1] = l; });
    for (const f of rawFindings) {
        const { offset, context } = parseHitPosition(f.excerpt);
        const loc = offsetToLineCol(content, offset);
        const ctxBefore = [];
        const ctxAfter = [];
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
        }
        catch { /* ok */ }
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
function severityEmoji(s) {
    const map = { critical: '🛑', high: '🔴', medium: '🟡', low: '🟢', info: '⚪' };
    return map[s] ?? '⚪';
}
function severityColor(s) {
    const map = { critical: 'red', high: 'orange', medium: 'yellow', low: 'green', info: 'gray' };
    return map[s] ?? 'gray';
}
export function toMarkdown(report, showContext = true) {
    const lines = [];
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
        const bySev = file.findings.reduce((acc, f) => {
            (acc[f.severity] ??= []).push(f);
            return acc;
        }, {});
        for (const sev of (['critical', 'high', 'medium', 'low', 'info'])) {
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
                    lines.push(`${String(finding.line).padStart(4)} | ${finding.contextBefore.find(l => l.line === finding.line)?.content ?? (finding.contextAfter.find(l => l.line === finding.line)?.content ?? '?')}`);
                    lines.push('```');
                    const postCtx = finding.contextAfter.filter(l => l.line !== finding.line);
                    if (postCtx.length) {
                        lines.push('');
                        lines.push(`**后 ${postCtx.length} 行:**`);
                        lines.push('```');
                        for (const { line: ln, content } of postCtx) {
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
export function toSARIF(report, version = '2.1.0') {
    const runId = crypto.randomUUID();
    const results = [];
    for (const file of report.files) {
        for (const f of file.findings) {
            results.push({
                ruleId: f.ruleId,
                ruleIndex: 0,
                level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
                message: { text: `[${f.ruleId}] ${f.title}: ${f.redactedExcerpt}` },
                locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: file.path.replace(/\\/g, '/'), uriBaseId: '%srcroot%' },
                            region: { startLine: f.line, startColumn: f.column, snippet: { text: f.redactedExcerpt } },
                        },
                    }],
                fingerprints: { '2.1:sh256': f.fingerprint },
            });
        }
    }
    return {
        version,
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        runs: [{
                uniqueId: { runGuid: runId, name: 'dsh-mcpaudit' },
                invocation: {
                    commandLine: 'mcpaudit scan',
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
                        rules: Array.from(new Set(report.files.flatMap(f => f.findings.map(ff => ff.ruleId)))).map(rid => ({ id: rid, name: rid })),
                    },
                },
            }],
    };
}
export function buildReportOutput(files, totalTargets, version = '1.0.0', format = 'all', showContext = true) {
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
    const report = {
        version: '1.0',
        generatedAt: now,
        scannerVersion: version,
        targets: totalTargets,
        findings: critical + high + medium + low + info,
        critical, high, medium, low, info,
        score: Math.max(0, 100 - critical * 40 - high * 20 - medium * 8 - low * 3 - info),
        files,
    };
    const out = { json: report };
    if (format === 'markdown' || format === 'all') {
        out.markdown = toMarkdown(report, showContext);
    }
    if (format === 'sarif' || format === 'all') {
        out.sarif = toSARIF(report);
    }
    return out;
}