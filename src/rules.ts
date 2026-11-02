/**
 * dsh-mcpaudit 检测规则引擎（TypeScript）
 * 与 mcpaudit Python/Go 版同一套 8 类规则：UNI/B64/INJ/PTH/SHL/PWD/BH/HMG
 */

export interface Finding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  source: string;
  excerpt: string;
}

type Check = (text: string) => string[];

export interface Rule {
  id: string;
  name: string;
  severity: Finding['severity'];
  description: string;
  check: Check;
}

// ---------------------------------------------------------------------------
// 规则数据
// ---------------------------------------------------------------------------

// Unicode 隐形字符的字符类见 checkHiddenUnicode（需要 u 标志处理 astral 范围）

// 同形字映射
const HOMOGLYPH_MAP: Record<string, string> = {
  // 西里尔
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j',
  '\u0432': 'b', '\u043D': 'h', '\u043A': 'k', '\u043C': 'm',
  '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0425': 'X', '\u0433': 'r', '\u0455': 's',
  // 拉丁扩展
  '\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E4': 'a',
  '\u00E9': 'e', '\u00E8': 'e', '\u00EA': 'e', '\u00EB': 'e',
  '\u00ED': 'i', '\u00EC': 'i', '\u00EE': 'i', '\u00EF': 'i',
  '\u00F3': 'o', '\u00F2': 'o', '\u00F4': 'o', '\u00F6': 'o',
  '\u00FC': 'u', '\u00F9': 'u', '\u00FB': 'u', '\u00E7': 'c',
};
// 数学字母数字符号（U+1D400–U+1D7FF）：粗体/斜体/等宽体字母，肉眼与 ASCII 完全一致
function addMathBlock(start: number, asciiStart: number): void {
  for (let i = 0; i < 26; i++) {
    HOMOGLYPH_MAP[String.fromCodePoint(start + i)] = String.fromCharCode(asciiStart + i);
  }
}
addMathBlock(0x1d400, 0x41); // 数学粗体大写 A-Z
addMathBlock(0x1d41a, 0x61); // 数学粗体小写 a-z
addMathBlock(0x1d4d0, 0x61); // 数学粗斜体小写 a-z
addMathBlock(0x1d608, 0x61); // 数学无衬线粗体小写 a-z
addMathBlock(0x1d622, 0x61); // 数学无衬线斜体小写 a-z

const HOMOGLYPH_TRIGGERS = [
  'ignore', 'previous', 'instructions', 'system prompt', 'override',
  '忽略', '指令', '规则', '忘记', '现在开始', '你扮演', '你是',
  'exfiltrat', 'send to', 'cc ', 'bcc ', 'new prime directive',
];

// 指令覆盖
const IGNORE_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
  /ignore\s+everything\s+(you|i|we)\s+/i,
  /忽略(之前|以上|先前|前面).{0,6}(指令|指示|规则|要求)/,
  /disregard\s+(all\s+)?((previous|prior|above)\s+)?(instruction|rule|prompt)s?/i,
  /忘记|忘掉.{0,6}(之前|以上|所有|一切).{0,6}(指令|提示|规则|要求|内容)/,
  /override\s+(the\s+)?system\s+prompt/i,
  /you\s+are\s+now\s+/i,
  /new\s+prime\s+directive/i,
  /从现在起.{0,12}(你是|扮演|忘记|不再)/,
  /你不再是.{0,12}(AI|助手|机器人|模型)/,
  /输出你(收到|的).{0,6}(系统|所有|全部).{0,4}(指令|提示|prompt)/,
  /(复述|泄露|透露|展示).{0,8}(系统提示|system prompt|系统指令)/,
];

// 角色扮演注入（v0.3.0 同步）
const ROLEPLAY_PATTERNS = [
  /(从现在开始|从现在起|接下来).{0,10}(你是|你扮演|你将扮演|请扮演|假装你是)/i,
  /(你不再|你不是|忘记你).{0,8}(AI助手|AI 助手|语言模型|assistant|chatbot)/i,
  /you\s+are\s+(now\s+)?(no\s+longer\s+)?(an?\s+)?(assistant|chatbot|ai|llm)/i,
  /(act|behave|pretend|roleplay)\s+(as|like)\s+(an?\s+)?(hacker|coder|admin|root|terminal)/i,
  /(扮演|假装|模拟).{0,8}(黑客|管理员|root|终端|系统)/,
  /(system\s+prompt|instructions?)\s+(is\s+)?(now|replaced|overridden)/i,
  /new\s+(instructions?|rules|directives?)\s+(apply|take\s+effect)/i,
];

// 多语言指令覆盖（v0.3.0 同步，日/韩）
const I18N_OVERRIDE_PATTERNS = [
  /(指示|命令|プロンプト).{0,8}(無視|無視して|無視しろ)/i,
  /(これまでの|以前の).{0,6}(指示|命令).{0,8}(無視|すべて)/i,
  /(지시|명령|프롬프트).{0,8}(무시|무시하고|무시해)/i,
  /(이전|지금까지).{0,6}(지시|명령).{0,6}(무시|전부)/i,
];

// 危险路径
const DANGEROUS_PATHS = [
  /[/\\]\.ssh[/\\]/, /[/\\]\.aws[/\\]/, /[/\\]\.git[/\\]config/,
  /\.env\b/, /\bid_rsa\b/, /\bid_ed25519\b/, /credentials\b/, /\.pem\b/,
  /access[_-]?token/, /api[_-]?token/, /bearer[_-]?token/, /api[_-]?key\b/,
  /secret[_-]?key\b/, /client[_-]?secret\b/, /AWS[_A-Z]*SECRET/, /\/etc\/passwd\b/,
].map((r) => new RegExp(r.source, 'i'));

// 危险 shell
const DANGEROUS_SHELL = [
  /curl[^\n]{0,60}\|\s*(ba)?sh/i,
  /wget[^\n]{0,60}\|\s*(ba)?sh/i,
  /rm\s+-rf\s+[/~]?\.?(\/|\*|home|root)/i,
  /rm\s+-rf\s+~\/\\?/i,
  /nc\s+-[^\n]*\s+(-e|-c)\s+/i,
  /base64\s+[^\n]{0,40}-d/i,
  /\beval\s*\(\s*["'$]|\beval\s+\$\s*\(|\beval\s+`/i,
  /\$\s*\(\s*(curl|wget|iwr|irm)\s/i,
  /(?:^|[^`])`(curl|wget|bash|sh|python)\s[^`]*`/i,
  /iex\s*\(\s*(iwr|irm|invoke-webrequest|invoke-restmethod)/i,
  /invoke-expression\s*[\(\s]/i,
  /os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(/i,
  /\bexec\s*\(\s*["']/i,
  /(curl|wget|iwr|irm)[^\n]{0,80}(-o|out-file)[^\n]{0,60}(&&|;|and).{0,20}(bash|sh|\.\/|start)/i,
];

// base64 长串
const B64_RE = /[A-Za-z0-9+/]{40,}={0,2}/;

// 可疑行为
const SUSPICIOUS_BEHAVIOR = [
  /always\s+(bcc|cc|copy|send|forward)[^\n]{0,40}(to|@)/i,
  /without\s+(asking|telling|informing|notifying)[^\n]{0,40}(user|human)/i,
  /静默[^\n]{0,10}(发送|抄送|上传|转发|删除)/,
  /(静默|暗中|偷偷|背着你|不通知|无需确认)[^\n]{0,12}(发送|上传|执行|提交|转发|删除)/,
  /do\s+not\s+(tell|inform|mention)\b[^\n]{0,60}(user|human|author|client)/i,
  /(exfiltrat\w*\s+(data|content|files?|logs|info))|((data|content|files?|logs|info)\s+to\s+.{0,40}(exfiltrat))/i,
  /steal|phish/i,
];

// 密码赋值
const PASSWORD_ASSIGN_RE = /(password|passwd|pwd)\s*[=:]\s*[^\s,;"'\n]{1,60}/i;

// ---------------------------------------------------------------------------
// 规则实现
// ---------------------------------------------------------------------------

function checkHiddenUnicode(text: string): string[] {
  const hits: string[] = [];
  // 注意：\u{E0000} 需要 u 标志（astral 范围，6 位 hex）；其余用 4 位 \uXXXX
  const re = new RegExp(
    '[\u{E0000}-\u{E007F}\u200B\u200C\u200D\u2060\uFEFF\u00AD' +
      '\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069' +
      '\u061C\u034F]',
    'gu',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 20) {
    const start = Math.max(0, m.index - 30);
    const end = Math.min(text.length, m.index + 1 + 30);
    hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
  }
  return hits;
}

function normalizeHomoglyphs(text: string): string {
  let out = '';
  for (const ch of text) {
    out += HOMOGLYPH_MAP[ch] ?? ch;
  }
  return out;
}

function checkHomoglyph(text: string): string[] {
  const hits: string[] = [];
  let hasSuspicious = false;
  for (const ch of text) {
    if (HOMOGLYPH_MAP[ch]) {
      hasSuspicious = true;
      break;
    }
  }
  if (!hasSuspicious) return hits;
  const lowered = normalizeHomoglyphs(text).toLowerCase();
  for (const trigger of HOMOGLYPH_TRIGGERS) {
    let idx = lowered.indexOf(trigger);
    while (idx !== -1 && hits.length < 20) {
      const start = Math.max(0, idx - 25);
      const end = Math.min(text.length, idx + trigger.length + 25);
      hits.push(`位置 ${idx}: …${text.slice(start, end)}…`);
      idx = lowered.indexOf(trigger, idx + 1);
    }
  }
  return hits;
}

function checkBase64(text: string): string[] {
  const hits: string[] = [];
  const re = new RegExp(B64_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 20) {
    const cand = m[0];
    if (/[a-z]{6,}/.test(cand)) continue;
    const before = text.slice(Math.max(0, m.index - 60), m.index);
    if (/data:\s*image\/|data:\s*[a-z]+\/[a-z+.-]+;base64,/i.test(before)) continue;
    hits.push(`位置 ${m.index}: ${cand.slice(0, 60)}…`);
  }
  return hits;
}

function checkInstructionOverride(text: string): string[] {
  const hits: string[] = [];
  for (const pat of IGNORE_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkDangerousPaths(text: string): string[] {
  const hits: string[] = [];
  for (const pat of DANGEROUS_PATHS) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 20);
      const end = Math.min(text.length, m.index + m[0].length + 20);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkPasswordAssignment(text: string): string[] {
  const hits: string[] = [];
  const re = new RegExp(PASSWORD_ASSIGN_RE.source, 'ig');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 10) {
    const start = Math.max(0, m.index - 20);
    const end = Math.min(text.length, m.index + m[0].length + 20);
    hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
  }
  return hits;
}

function checkDangerousShell(text: string): string[] {
  const hits: string[] = [];
  for (const pat of DANGEROUS_SHELL) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkSuspiciousBehavior(text: string): string[] {
  const hits: string[] = [];
  for (const pat of SUSPICIOUS_BEHAVIOR) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkRoleplay(text: string): string[] {
  const hits: string[] = [];
  for (const pat of ROLEPLAY_PATTERNS) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkI18nOverride(text: string): string[] {
  const hits: string[] = [];
  for (const pat of I18N_OVERRIDE_PATTERNS) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// INJ-004: 间接提示注入 / 分隔符劫持
// 伪造对话切片：---、system:、user:、assistant: 在工具描述里非常常见
// ---------------------------------------------------------------------------

const INJ_004_DELIMITER_PATTERNS = [
  /^---+\s*$/m,
  /^(system|user|assistant)\s*:\s*/im,
  /^\s*<\/?(?:system|user|assistant)\s*>/im,
  /^##?\s*(SYSTEM|USER|ASSISTANT)\s*$/im,
  /^(\[SYSTEM\]|\[USER\]|\[ASSISTANT\]|\[You\]|\[Bot\])/im,
];

// 真正的 markdown front-matter 排除（--- 出现在文档开头）
const MARKDOWN_FRONT_MATTER_RE = /^---\n[\s\S]*?\n---\n/;

function checkDelimiterHijack(text: string): string[] {
  const hits: string[] = [];
  // Skip if it looks like a legitimate markdown front-matter
  if (MARKDOWN_FRONT_MATTER_RE.test(text)) return hits;
  for (const pat of INJ_004_DELIMITER_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(text.length, m.index + m[0].length + 30);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// INJ-005: 注入诱饵
// "下面内容是给模型看的，用户不可见"
// ---------------------------------------------------------------------------

const INJ_005_TRAP_PATTERNS = [
  /下面.{0,8}(内容|指令|命令|文本).{0,8}(给.*(看|读取)|模型.*(看|处理)|不可见|用户.*看不见)/i,
  /(这段|这条|这份).{0,8}(内容|指令|文本|描述).{0,8}(仅供|只给|给).{0,8}(模型|AI|assistant)/i,
  /(人类|用户|human|user).{0,6}(看不到|不可见|看不见|别管|忽略)/i,
  /this\s+section\s+is\s+(for|hidden\s+from)\s+(the\s+)?(model|assistant|AI)/i,
  /hidden\s+from\s+(the\s+)?user/i,
  /instruction\s+for\s+the\s+model\s+only/i,
  /model.*(only|eyes|see)|for\s+the\s+AI\s+only/i,
  /\[.*(?:model|assistant|AI).*only\]/i,
  /(skip|bypass|ignore)\s+(this|the)\s+(user|human)/i,
  /do\s+not\s+(show|display|reveal)\s+to\s+user/i,
  // Invisible separator tricks
  /[\u200B\u200C\u200D\uFEFF]{3,}/gu,
];

function checkInjectionTrap(text: string): string[] {
  const hits: string[] = [];
  for (const pat of INJ_005_TRAP_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(text.length, m.index + m[0].length + 30);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// NET-001: 硬编码恶意域名 / IP、直连外部服务器、webhook 外发地址
// ---------------------------------------------------------------------------

const NET_001_PATTERNS = [
  // IP literals (avoid common false positives like 127.0.0.1, 0.0.0.0)
  /\b(?:[1-9][0-9]{0,2}\.){3}[1-9][0-9]{0,2}\b(?!\s*(:443|:80\b|localhost|127\.0\.0\.1|0\.0\.0\.0))/,
  // Suspicious TLDs + common attacker domains
  /\b(?:evil|malicious|hack|phish|exfil|c2|command|control|trojan)\.(?:com|net|io|xyz|tk|ml|ga|cf|gq)\b/i,
  // ngrok / tunnel services (often used for exfil)
  /\b[A-Za-z0-9-]+\.ngrok(?:free\.io|\.app)\b/i,
  /\b[A-Za-z0-9-]+\.serveo\.net\b/i,
  /\b[A-Za-z0-9-]+\.localtunnel\.me\b/i,
  // Webhook URLs with suspicious hosts
  /https?:\/\/[^\s"']+(?:webhook|callback|notify|alert|exfil|steal)(?:[^\s"']*)/i,
  // HTTP(S) URLs with suspicious path keywords + external FQDN
  /https?:\/\/[a-zA-Z0-9.-]+\.(?:com|net|io|xyz|tk|ml|ga|cf|gq|cc|su|top|ru|cn)\/[^\s"'<>]{5,}/i,
  // Raw IP with port (common C2)
  /\b(?:[1-9][0-9]{0,2}\.){3}[1-9][0-9]{0,2}:(?:443|8443|8080|31337|1337)\b/,
  // DNS exfil pattern
  /\b[A-F0-9]{8,}\.(?:dns|ns|lookup|resolve)\.[a-z]+\b/i,
  // Base64-looking subdomains (common DNS exfil)
  /https?:\/\/[A-Za-z0-9+/]{20,}\@[^\s"'<>]+/i,
  // curl/wget to external (already in SHL-001 but broader scope here)
  /(?:curl|wget|fetch|iperf|nc)\s+https?:\/\/[^\s]+/i,
];

function checkNetworkIo(text: string): string[] {
  const hits: string[] = [];
  // Filter out localhost/127.0.0.1 by running context check
  const textWithoutLocalhost = text.replace(/\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b/gi, 'REMOVED');
  for (const pat of NET_001_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(textWithoutLocalhost)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(text.length, m.index + m[0].length + 30);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// REG-001: 危险正则（可读取任意文件、回溯爆炸 ReDoS）
// ---------------------------------------------------------------------------

const REG_001_PATTERNS = [
  // Path traversal in regex (file read via regex substitution)
  /\$\{?\s*[^}]*(\.\.|\.\.\/|\.\.\\)[^}]*\}?/,
  /\(\.\.(\/|\|\\)\)/,
  // Catastrophic backreference (nested groups + quantifiers)
  /\([^)]*[+*][^)]*\)\s*[+*]/,
  /\(\?[=!][^)]*[+*][^)]*\)/,
  // ReDoS: overlapping alternation with quantifiers
  /(\w+|a+|the+)\s*\*\s*$/m,
  // Nested quantifiers: (a+)+, (a*)+ — the classic exponential backtracking form
  /\(\s*(?:[^()\\]|\\.)*[+*][+*]?\s*\)\s*[+*]/,
  /\(\s*\w+\s*\)\s*\+\s*\)/,
  // Ambiguous alternations that share a prefix with quantifiers (e.g. /(a|aa)+/)
  /\(\s*[a-zA-Z0-9_]+\s*\|\s*[a-zA-Z0-9_]+[+*]?\s*\)\s*[+*]/,
  // Greedy .* .+ at start of alternative (can cause massive backtracking)
  /^(?:\.\*|\.\+)\s*\|\|?/,
  // Oversized quantifier braces that force huge repetition
  /\{100,1000\}|\{[0-9]{3,},{0,1}\}/,
  // Double-star in a char class or glob used as a regex anchor
  /\*\*[^*]/,
];

function checkDangerousRegex(text: string): string[] {
  const hits: string[] = [];
  for (const pat of REG_001_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(text.length, m.index + m[0].length + 30);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// FILE-001: 无限制文件读写通配符 *、../ 路径穿越 payload
// ---------------------------------------------------------------------------

const FILE_001_PATTERNS = [
  /\*\s*>\s*\/|^>\s*\*|\|\s*\*$/m,
  /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|%2e%2e\\/i,
  /%2e%2e/i,
  /\.\.%2f|%2e%2e%5c/i,
  /\*\/\*|glob\s*\*|wildcard\s*\*/i,
  /read(?:File|Dir)?(?:Sync)?\s*\(\s*["'`]\s*\*\s*["'`]/i,
  /readFileSync\s*\(\s*["'`]\s*\*\s*["'`]/i,
  /readdir(?:Sync)?\s*\(\s*["'`]\s*\*\s*["'`]/i,
  /writeFile\s*\(\s*["'`]\s*\*\s*["'`]/i,
  /open\s*\(\s*["'`]\s*\*\s*["'`]/i,
  /scan(?:Dir|DirSync)\s*\(\s*["'`]\s*\*\s*["'`]/i,
  // Directory traversal with common encoding
  /\\.\.\\|\\\.\\\|\\\.\\\/|\\\\\.\\\\/,
  /\.\.%5c|%2e%2e%5c/i,
  // Template literal with wildcard
  /`[^`]*\$\{[^}]*\.\.\/[^}]*\}`/,
  // Glob patterns that could expand to sensitive paths
  /\*\*(?:\\|\/)\*\*/,
  /\*\*(?:\\|\/)\./,
];

function checkPathTraversal(text: string): string[] {
  const hits: string[] = [];
  for (const pat of FILE_001_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// CMD-002: Node/TS 危险函数 eval, Function, vm.runInNewContext
// ---------------------------------------------------------------------------

const CMD_002_PATTERNS = [
  // eval variants
  /\beval\s*\(\s*(?:["'`$]|\$\{)/i,
  /\beval\s+\$(?:\(|[{])/i,
  // Function constructor
  /\bFunction\s*\(/i,
  /new\s+Function\s*\(/i,
  // vm.runInNewContext / vm.runInThisContext
  /\bvm\.runInNewContext\s*\(/i,
  /\bvm\.runInThisContext\s*\(/i,
  /\bvm\.createContext\s*\(/i,
  // Generator function from string
  /\b(generator|asyncGenerator)\s*\(.*\)\s*\{/i,
  // new AsyncFunction
  /new\s+AsyncFunction\s*\(/i,
  /new\s+GeneratorFunction\s*\(/i,
  // Reflect.compile
  /\bReflect\.compile\s*\(/i,
  // secretsmanager getSecretValue (aws) - not dangerous but credential-related
  // setTimeout / setInterval with string (similar to eval)
  /setTimeout\s*\(\s*["'`$]/i,
  /setInterval\s*\(\s*["'`$]/i,
  /setImmediate\s*\(\s*["'`$]/i,
  // queueMicrotask
  /\bqueueMicrotask\s*\(\s*["'`$]/i,
  // Script engines
  /\bScriptEngine\s*\(/i,
  /\bScripts?\s*\.?\s*Execute\s*\(/i,
  // Bun /deno eval alternative
  /\b(Bun|deno)\.eval\s*\(/i,
  // exec with string interpolation (minor)
  /exec\s*\(\s*(?:["'`$]|\$\{)/i,
  // node --eval
  /--eval\s+["'][^"']+["']/i,
  // node -e
  /\bnode\s+-e\s+["'][^"']+["']/i,
];

function checkNodeDangerousFunctions(text: string): string[] {
  const hits: string[] = [];
  for (const pat of CMD_002_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// ENV-001: 明文 .env 密钥、base64 编码密钥伪装
// ---------------------------------------------------------------------------

const ENV_001_PATTERNS = [
  // Explicit .env style
  /(?:API|OPENAI|ANTHROPIC|AWS|STRIPE|GITHUB|SLACK|DATABASE|DB|SECRET|TOKEN|PASSWORD|PRIVATE)\s*[=:]\s*["'][^"']{8,}["']/i,
  // Generic key=value where value looks like a key
  /(?:api_key|apiKey|apikey|secret_key|secretKey|auth_token|access_token|authToken|accessToken)\s*[=:]\s*["'][A-Za-z0-9_-]{20,}["']/i,
  // AWS access key
  /(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[=:]\s*["'][^"']{10,}["']/i,
  // Base64-encoded secrets (look like base64 strings assigned to keys)
  /(?:secret|token|key|auth|credential|password)\s*[=:]\s*["'][A-Za-z0-9+/]{30,}={0,2}["']/i,
  // Bearer token (require keyword to avoid FP on long alphanumerics)
  /(?:Bearer\s+|bearer\s+)[A-Za-z0-9._~+/=-]{20,}/i,
  // HMAC / signing keys
  /(?:HMAC|SIGNING|ENCRYPTION)_(?:KEY|SECRET)\s*[=:]\s*["'][^"']{10,}["']/i,
  // JWT in env (not just general JWT detection - specifically in env assignment)
  /JWT\s*[=:]\s*["']eyJ[A-Za-z0-9_-]{10,}/i,
  // Private key block in env context
  /-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
];

function checkEnvSecrets(text: string): string[] {
  const hits: string[] = [];
  for (const pat of ENV_001_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 15) {
      // Skip if inside a comment (// or # or /* */)
      const before = text.slice(Math.max(0, m.index - 50), m.index);
      const lineStart = before.lastIndexOf('\n');
      const lineBefore = before.slice(lineStart + 1);
      // If the whole line before is a comment, skip
      if (/^\s*(?:\/\/|#|\/\*)/.test(lineBefore)) continue;
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------

export function buildDefaultEngine(): Rule[] {
  return [
    { id: 'UNI-001', name: 'Unicode 隐形字符', severity: 'high',
      description: '检测到不可见 Unicode 字符（私有区/零宽字符/双向文本控制符），可能用于隐藏恶意指令以规避人工审查。',
      check: checkHiddenUnicode },
    { id: 'B64-001', name: '可疑 base64 长串', severity: 'medium',
      description: '检测到疑似 base64 编码的长字符串，可能用于混淆指令内容，建议解码后人工确认。',
      check: checkBase64 },
    { id: 'INJ-001', name: '指令覆盖模式', severity: 'critical',
      description: '检测到试图覆盖/忽略原有指令的表述（如 ignore previous instructions），这是提示注入与工具投毒的核心特征。',
      check: checkInstructionOverride },
    { id: 'PTH-001', name: '敏感路径引用', severity: 'high',
      description: '检测到对敏感文件路径的引用（SSH 密钥、AWS 凭据、token 等），存在被利用进行凭据窃取的风险。',
      check: checkDangerousPaths },
    { id: 'SHL-001', name: '危险 shell 模式', severity: 'critical',
      description: '检测到管道执行远程脚本、危险删除、反向 shell 等模式。',
      check: checkDangerousShell },
    { id: 'PWD-001', name: '密码赋值形态', severity: 'info',
      description: '检测到 password= / password: 形式的赋值（可能是配置中的明文密码），仅提示注意，不作高危判定。',
      check: checkPasswordAssignment },
    { id: 'BH-001', name: '可疑工具行为描述', severity: 'high',
      description: '检测到静默操作、自动外发数据、绕过用户知情等异常行为描述，符合已知工具投毒攻击特征。',
      check: checkSuspiciousBehavior },
    { id: 'HMG-001', name: '同形字混淆 (homoglyph)', severity: 'high',
      description: '检测到使用视觉相近的 Unicode 字符冒充 ASCII 字母（如西里尔 а 冒充 a），用于绕过关键词过滤隐藏恶意指令。',
      check: checkHomoglyph },
    { id: 'INJ-002', name: '角色扮演注入', severity: 'critical',
      description: '检测到诱导模型切换角色/行为的表述（如“从现在开始你是黑客”），属于提示注入的语义变体，可绕过关键词过滤。',
      check: checkRoleplay },
    { id: 'INJ-003', name: '多语言指令覆盖', severity: 'high',
      description: '检测到日语/韩语的指令覆盖表述（無視して / 무시하고），多语言提示注入正成为国际工具投毒的趋势手法。',
      check: checkI18nOverride },
    { id: 'INJ-004', name: '间接提示注入 / 分隔符劫持', severity: 'high',
      description: '检测到伪造对话切片（---、system:、user:、assistant:），LLM 工具描述中非常常见，可能用于间接提示注入。',
      check: checkDelimiterHijack },
    { id: 'INJ-005', name: '注入诱饵', severity: 'high',
      description: '检测到“下面内容是给模型看的，用户不可见”等诱饵表述，这类标记常被用于区分模型的可见指令与用户指令。',
      check: checkInjectionTrap },
    { id: 'NET-001', name: '危险网络 I/O', severity: 'critical',
      description: '检测到硬编码恶意域名 / IP、直连外部服务器、webhook 外发地址，可能是数据外泄或 C2 通信。',
      check: checkNetworkIo },
    { id: 'REG-001', name: '危险正则', severity: 'high',
      description: '检测到可能导致 ReDoS（回溯爆炸）或路径穿越的正则表达式。',
      check: checkDangerousRegex },
    { id: 'FILE-001', name: '路径穿越 payload', severity: 'critical',
      description: '检测到无限制文件读写通配符（*、../ 路径穿越 payload），可能被用于读取敏感文件。',
      check: checkPathTraversal },
    { id: 'CMD-002', name: 'Node/TS 危险函数', severity: 'critical',
      description: '检测到 eval、Function、vm.runInNewContext 等危险函数调用，可能导致代码注入。',
      check: checkNodeDangerousFunctions },
    { id: 'ENV-001', name: '明文 .env 密钥', severity: 'critical',
      description: '检测到明文存储的 .env 密钥或 base64 编码密钥伪装，可能导致凭据泄露。',
      check: checkEnvSecrets },
  ];
}

/** 对一段文本跑全部规则，返回命中列表 */
export function scanText(text: string, source: string, rules: Rule[] = buildDefaultEngine()): Finding[] {
  if (!text) return [];
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      const hits = rule.check(text);
      for (const hit of hits) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.name,
          detail: rule.description,
          source,
          excerpt: hit.slice(0, 200),
        });
      }
    } catch {
      // 单条规则异常不影响整体
    }
  }
  return findings;
}

/** 评分：100 - 扣分 */
export function severityScore(findings: Finding[]): number {
  if (!findings.length) return 100;
  const weights: Record<string, number> = { critical: 40, high: 20, medium: 8, low: 3, info: 1 };
  let score = 100;
  for (const f of findings) score -= weights[f.severity] ?? 1;
  return Math.max(0, score);
}

/** 脱敏：密钥模式替换为 *** */
export function redact(s: string): string {
  const patterns = [
    /sk-[A-Za-z0-9_-]{20,}/gi,
    /ghp_[A-Za-z0-9]{30,}/gi,
    /github_pat_[A-Za-z0-9_]{20,}/gi,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
    /AIza[A-Za-z0-9_-]{20,}/gi,
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/gi,
    /password\s*[=:]\s*["'][^"']{6,}["']|password\s*[=:]\s*[^\s,;"']{6,}/gi,
  ];
  let out = s;
  for (const p of patterns) out = out.replace(p, '***');
  return out;
}
