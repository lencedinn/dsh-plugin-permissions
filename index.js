/**
 * Plugin Permissions - what each installed plugin can reach, read, and run.
 *
 * The scanner is static and read-only: it reads the files of the packages in
 * this profile and reports what they *can* do - hosts they talk to, sensitive
 * stores they name, routes they register, processes they spawn, install
 * scripts they ship. It never executes plugin code and never sends anything
 * off the machine.
 *
 * One implementation feeds two callers: the panel (through the scan route) and
 * the agent (through the plugin_permissions tool), so a card on screen and a
 * tool result describe the same findings.
 *
 * Judgement stays with the reader. A plugin that talks to GitHub is not
 * suspicious by itself; the card exists so "which of my plugins can read my
 * cookies" has an answer in seconds instead of an afternoon.
 */

import { readdirSync, readFileSync, lstatSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, extname, join, relative } from 'node:path';

/** Hard dependency: the tool registry is the only way the agent sees results. */
export const inject = ['tools'];

const API_SCAN = '/api/plugin-permissions/scan';
const CACHE_MS = 60_000;
const MAX_FILE_BYTES = 1_500_000;
const MAX_FILES_PER_PACKAGE = 600;
const MAX_FINDINGS_PER_PACKAGE = 240;

/** Files worth reading as text. Everything else is counted, not parsed. */
const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.ps1', '.sh', '.bat', '.cmd',
  '.json', '.html', '.css', '.yml', '.yaml', '.toml',
]);

/** Directories that are code we did not author, docs, or test fixtures — not runtime behaviour. */
const SKIP_DIRS = new Set(['node_modules', '.git', '.pnpm', 'dist', 'build', '.cache', '__pycache__', 'dev', 'test', 'tests', 'docs', 'examples', 'tools']);

/** Hosts that are namespaces, loopback, or metadata — never an external destination. */
const IGNORED_HOSTS = new Set([
  'www.w3.org', 'w3.org', 'schema.org', 'json-schema.org', 'example.com', 'example.org',
  'localhost', '127.0.0.1', '0.0.0.0', '[::1]',
]);

/**
 * Sensitive stores a plugin has no business reading unless it says why.
 * Each entry is [regex, label, severity].
 */
const SENSITIVE = [
  [/\.credentials\.yaml|credentials\.yaml/, 'DSH 凭据文件', 'high'],
  [/(?:\.dsh[\\/])sessions|session\.v4|\.jsonl\.zstd/, 'DSH 会话日志', 'high'],
  [/bili_credential/, 'B站 登录凭证', 'high'],
  [/[\\/]Cookies\b|Local State|Login Data|leveldb/, '浏览器 Cookie/登录库', 'high'],
  [/id_rsa|\.ssh[\\/]|known_hosts/, 'SSH 私钥', 'high'],
  [/\.codex[\\/]|CODEX_HOME/, 'Codex 会话目录', 'medium'],
  [/anonymous-user-id/, '匿名用户 ID', 'medium'],
  [/API[_-]?KEY|apiKey|SESSDATA|bili_jct|Bearer\s/, 'API key / 会话令牌', 'medium'],
];

/** Process execution: local privilege, not necessarily malice. */
const EXEC = /child_process|\bspawn(?:Sync)?\s*\(|\bexecFile(?:Sync)?\s*\(|\bexecSync\s*\(|powershell\.exe|cmd\.exe|subprocess|os\.system/;

/** DOM/eval in client code. */
const ACTIVE = /innerHTML|dangerouslySetInnerHTML|\beval\s*\(|new Function\s*\(/;

/** Runtime downloads an install record would not show. */
const RUNTIME_INSTALL = /\b(?:pip|uv|pnpm|npm|npx)\s+(?:install|add|exec|create)\b|\bcurl\s+-|\bInvoke-WebRequest\b|https?:\/\/[^\s'"]*releases\/download/;

/**
 * @param {string} value
 * @param {number} limit
 */
function clip(value, limit) {
  const oneLine = String(value).replace(/\s+/g, ' ').trim();
  return oneLine.length <= limit ? oneLine : `${oneLine.slice(0, limit - 1)}…`;
}

/**
 * @param {string} file
 * @param {string} text
 * @param {number} at
 */
function lineAt(file, text, at) {
  let line = 1;
  for (let i = 0; i < at && i < text.length; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

/** @param {string} url */
function hostOf(url) {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Read one file and collect findings. Bounded per category and per file.
 *
 * @param {string} absolute
 * @param {string} rel
 * @returns {Array<{category: string, severity: string, file: string, line: number, text: string, host?: string, value?: string}>}
 */
function analyzeFile(absolute, rel) {
  const findings = [];
  let text;
  try {
    if (statSync(absolute).size > MAX_FILE_BYTES) return findings;
    text = readFileSync(absolute, 'utf8');
  } catch {
    return findings;
  }
  if (text.includes('\u0000')) return findings;

  const push = (category, severity, at, extra = {}) => {
    if (findings.filter((f) => f.category === category).length >= 24) return;
    findings.push({
      category,
      severity,
      file: rel,
      line: lineAt(rel, text, at),
      text: clip(text.slice(Math.max(0, at - 60), at + 140), 180),
      ...extra,
    });
  };

  const manifest = basename(absolute) === 'package.json';
  const constants = new Map();
  for (const match of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['"`]([^'"`\n]{2,160})['"`]/g)) {
    constants.set(match[1], match[2]);
  }

  if (!manifest) {
    for (const match of text.matchAll(/https?:\/\/[^\s'"`<>)\]]+/g)) {
      const host = hostOf(match[0]);
      if (host === '' || IGNORED_HOSTS.has(host)) continue;
      if (/[^a-z0-9.:_[\]-]/.test(host)) continue;
      push('egress', 'medium', match.index ?? 0, { host, value: clip(match[0], 120) });
    }
  }

  for (const [re, label, severity] of SENSITIVE) {
    const match = re.exec(text);
    if (match !== null) push('sensitive', severity, match.index, { value: label });
  }

  const execMatch = EXEC.exec(text);
  if (execMatch !== null) push('exec', 'high', execMatch.index);

  const activeMatch = ACTIVE.exec(text);
  if (activeMatch !== null) push('active', 'medium', activeMatch.index);

  const installMatch = RUNTIME_INSTALL.exec(text);
  if (installMatch !== null) push('install', 'high', installMatch.index);

  for (const match of text.matchAll(/webServer\.register\s*\(\s*\{[\s\S]{0,600}?\}\s*\)/g)) {
    const block = match[0];
    const pathToken = /path:\s*(?:['"`]([^'"`]+)['"`]|([A-Za-z_$][\w$]*))/.exec(block);
    const literal = pathToken?.[1] ?? (pathToken?.[2] !== undefined ? constants.get(pathToken[2]) : undefined);
    const kind = /kind:\s*['"`]([^'"`]+)['"`]/.exec(block);
    push('route', kind?.[1] === 'prefix' ? 'high' : 'medium', match.index ?? 0, {
      value: `${kind?.[1] ?? 'exact'} ${literal ?? '(dynamic)'}`,
    });
  }

  return findings;
}

/**
 * @param {string} dir
 * @param {string} rel
 * @param {Array<{file: string, absolute: string}>} out
 * @param {Set<string>} seen
 */
function walk(dir, rel, out, seen) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (out.length >= MAX_FILES_PER_PACKAGE) return;
    if (entry.name.startsWith('.') && entry.name !== '.dsh') continue;
    if (SKIP_DIRS.has(entry.name)) continue;
    const absolute = join(dir, entry.name);
    const childRel = rel === '' ? entry.name : `${rel}/${entry.name}`;
    let stat;
    try {
      stat = lstatSync(absolute);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      walk(absolute, childRel, out, seen);
      continue;
    }
    if (!TEXT_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
    if (stat.size > MAX_FILE_BYTES) continue;
    if (seen.has(absolute)) continue;
    seen.add(absolute);
    out.push({ file: childRel, absolute });
  }
}

/**
 * @param {string} profileDir
 * @returns {Array<{name: string, enabled: boolean, spec: string}>}
 */
function listInstalled(profileDir) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8'));
  } catch {
    return [];
  }
  const bundles = new Set(Array.isArray(manifest?.dsh?.profile?.bundles) ? manifest.dsh.profile.bundles : []);
  const deps = manifest?.dependencies ?? {};
  const rows = [];
  for (const [name, spec] of Object.entries(deps)) {
    if (name.startsWith('@deepseek-ai/')) continue;
    rows.push({ name, enabled: bundles.has(name), spec: String(spec) });
  }
  rows.sort((a, b) => (a.enabled === b.enabled ? a.name.localeCompare(b.name) : a.enabled ? -1 : 1));
  return rows;
}

/**
 * @param {string} profileDir
 * @param {string} name
 */
function resolvePackageDir(profileDir, name) {
  const candidate = join(profileDir, 'node_modules', name);
  try {
    const real = realpathSync(candidate);
    return statSync(real).isDirectory() ? real : undefined;
  } catch {
    return undefined;
  }
}

/**
 * @param {string} dir
 * @param {Array<{file: string, absolute: string}>} files
 */
function scanPackage(dir, files) {
  const findings = [];
  const domains = new Map();
  for (const file of files) {
    for (const finding of analyzeFile(file.absolute, file.file)) {
      if (findings.length >= MAX_FINDINGS_PER_PACKAGE) break;
      findings.push(finding);
      if (finding.category === 'egress' && finding.host) {
        const existing = domains.get(finding.host);
        if (existing === undefined) domains.set(finding.host, { host: finding.host, count: 1, file: finding.file, line: finding.line });
        else existing.count += 1;
      }
    }
  }
  return { findings, domains: [...domains.values()].sort((a, b) => b.count - a.count) };
}

/**
 * What one package gets at a glance. Severity names the permission, not intent.
 *
 * @param {string[]} categories
 * @param {Array<{host: string}>} domains
 * @param {Record<string, unknown>} scripts
 */
function riskOf(categories, domains, scripts) {
  if (categories.includes('sensitive') || categories.includes('exec') || categories.includes('install')) return 'high';
  if (Object.keys(scripts).some((key) => /install|prepare|postinstall|preinstall/.test(key))) return 'high';
  if (categories.includes('route') || domains.length > 0) return 'medium';
  return 'low';
}

/**
 * A profile directory is the one whose package.json carries `dsh.profile`.
 *
 * @param {string} dir
 */
function isProfileDir(dir) {
  try {
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    return manifest !== null && typeof manifest === 'object' && manifest.dsh?.profile !== undefined;
  } catch {
    return false;
  }
}

/**
 * Find the profile to scan without trusting a single environment variable:
 * explicit config, then $DSH_PROFILE_DIR, then the Host's working directory
 * (the desktop shell starts the Host with the profile as cwd), then the usual
 * home layout.
 *
 * @param {any} settings
 * @returns {string} the absolute profile directory, or '' when none was found
 */
function resolveProfileDir(settings) {
  const explicit = typeof settings.profileDir === 'string' ? settings.profileDir.trim() : '';
  if (explicit !== '' && isProfileDir(explicit)) return explicit;

  const fromEnv = typeof process.env.DSH_PROFILE_DIR === 'string' ? process.env.DSH_PROFILE_DIR.trim() : '';
  if (fromEnv !== '' && isProfileDir(fromEnv)) return fromEnv;

  let current = process.cwd();
  for (let depth = 0; depth < 4; depth += 1) {
    if (isProfileDir(current)) return current;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }

  const profileName = typeof process.env.DSH_PROFILE === 'string' ? process.env.DSH_PROFILE.trim() : '';
  if (profileName !== '') {
    const candidate = join(homedir(), '.dsh', 'profiles', profileName);
    if (isProfileDir(candidate)) return candidate;
  }
  return '';
}

/**
 * @param {unknown} error
 */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(payload.byteLength),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

/**
 * Read routes expose local paths and source snippets, so a foreign page must
 * not be able to read them through the user's browser.
 *
 * @param {import('node:http').IncomingMessage} req
 */
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (typeof origin !== 'string' || origin.length === 0) return true;
  const host = req.headers.host;
  if (typeof host !== 'string' || host.length === 0) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

/**
 * @param {any} ctx
 * @param {unknown} [config]
 */
export function apply(ctx, config) {
  const settings = config !== null && typeof config === 'object' ? config : {};
  const profileDir = resolveProfileDir(settings);
  const includeOurs = settings.includeOurs !== false;
  const excluded = new Set(Array.isArray(settings.exclude) ? settings.exclude.map(String) : []);

  /** @type {{at: number, data: any} | null} */
  let cache = null;
  let scanning = null;

  /**
   * Scan every installed package once and cache the result.
   *
   * @param {boolean} force
   */
  async function scan(force) {
    if (!force && cache !== null && Date.now() - cache.at < CACHE_MS) return cache.data;
    if (scanning !== null) return scanning;
    scanning = (async () => {
      const startedAt = Date.now();
      if (profileDir === '') throw new Error('profile directory is unknown; set profileDir in the plugin config');
      const installed = listInstalled(profileDir);
      const packages = [];
      let filesSeen = 0;
      for (const entry of installed) {
        const ours = entry.name.startsWith('@local/');
        if (ours && !includeOurs) continue;
        if (excluded.has(entry.name)) continue;
        const dir = resolvePackageDir(profileDir, entry.name);
        if (dir === undefined) continue;
        let manifest = {};
        try {
          manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
        } catch {
          manifest = {};
        }
        const files = [];
        walk(dir, '', files, new Set());
        filesSeen += files.length;
        const { findings, domains } = scanPackage(dir, files);
        const scripts = manifest?.scripts ?? {};
        for (const [key, value] of Object.entries(scripts)) {
          if (!/^(pre|post)?install$|^prepare$/.test(key)) continue;
          findings.unshift({
            category: 'install',
            severity: 'high',
            file: 'package.json',
            line: 1,
            text: `${key}: ${clip(String(value), 120)}`,
          });
        }
        const categories = [...new Set(findings.map((finding) => finding.category))];
        packages.push({
          name: entry.name,
          version: String(manifest?.version ?? '?'),
          enabled: entry.enabled,
          ours,
          source: entry.spec.startsWith('link:') ? 'link' : entry.spec.startsWith('github:') ? 'git' : 'registry',
          realPath: dir,
          files: files.length,
          categories,
          risk: riskOf(categories, domains, scripts),
          domains,
          routes: findings.filter((finding) => finding.category === 'route').map((finding) => finding.value),
          findings,
          scripts: Object.keys(scripts),
        });
      }
      const data = {
        generatedAt: new Date().toISOString(),
        tookMs: Date.now() - startedAt,
        profileDir,
        counts: {
          packages: packages.length,
          enabled: packages.filter((entry) => entry.enabled).length,
          files: filesSeen,
          high: packages.filter((entry) => entry.risk === 'high').length,
          medium: packages.filter((entry) => entry.risk === 'medium').length,
        },
        packages,
      };
      cache = { at: Date.now(), data };
      return data;
    })()
      .finally(() => {
        scanning = null;
      });
    return scanning;
  }

  // Scan once in the background so the first panel open is instant.
  void scan(false).catch(() => undefined);

  /* ---------------------------------------------------------------- *
   * Route
   * ---------------------------------------------------------------- */

  ctx.inject(['webServer'], (scope) => {
    const webServer = scope.webServer;
    scope.effect(() => webServer.register({
      kind: 'exact',
      path: API_SCAN,
      handler: async (req, res) => {
        if (req.method !== 'GET') {
          sendJson(res, 405, { error: 'GET required' });
          return;
        }
        if (!sameOrigin(req)) {
          sendJson(res, 403, { error: 'cross-origin request refused' });
          return;
        }
        try {
          const url = new URL(req.url ?? API_SCAN, 'http://localhost');
          const data = await scan(url.searchParams.get('refresh') === '1');
          sendJson(res, 200, data);
        } catch (error) {
          sendJson(res, 500, { error: messageOf(error) });
        }
      },
    }), 'plugin-permissions: scan route');
  });

  /* ---------------------------------------------------------------- *
   * Tool: the same findings, compact enough for a model
   * ---------------------------------------------------------------- */

  ctx.effect(() => ctx.tools.register({
    name: 'plugin_permissions',
    description:
      'Report what the installed plugins in this DSH profile can reach, read, and run, from a static scan of their own files: outbound hosts, '
      + 'sensitive local stores they name (credentials, session logs, cookies, SSH keys), routes they register, process execution, and runtime '
      + 'package installs. Read-only; it never runs plugin code. Use it when the user asks whether a plugin is safe, what it phones home to, or '
      + 'which plugin can read their tokens.',
    parameters: {
      type: 'object',
      properties: {
        plugin: {
          type: 'string',
          description: 'Exact package name to inspect, e.g. dsh-bili-scroll. Omit to summarize every scanned package.',
        },
        category: {
          type: 'string',
          enum: ['egress', 'sensitive', 'route', 'exec', 'install', 'active'],
          description: 'Only report findings in this category.',
        },
        limit: {
          type: 'number',
          description: 'Maximum findings to render per plugin, 1-50. Defaults to 8.',
        },
      },
      required: [],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          generatedAt: { type: 'string' },
          packages: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                name: { type: 'string' },
                version: { type: 'string' },
                risk: { type: 'string' },
                enabled: { type: 'boolean' },
                domains: { type: 'array', items: { type: 'string' } },
                routes: { type: 'array', items: { type: 'string' } },
                findings: {
                  type: 'array',
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                      category: { type: 'string' },
                      severity: { type: 'string' },
                      file: { type: 'string' },
                      line: { type: 'number' },
                      text: { type: 'string' },
                    },
                    required: ['category', 'severity', 'file', 'line', 'text'],
                  },
                },
              },
              required: ['name', 'version', 'risk', 'enabled', 'domains', 'routes', 'findings'],
            },
          },
        },
        required: ['generatedAt', 'packages'],
      },
      render(_args, value) {
        const lines = [`Plugin permission scan (${value.generatedAt})`];
        for (const entry of value.packages) {
          lines.push(`\n## ${entry.name} ${entry.version}  risk=${entry.risk}${entry.enabled ? '' : ' (disabled)'}`);
          if (entry.domains.length > 0) lines.push(`hosts: ${entry.domains.join(', ')}`);
          if (entry.routes.length > 0) lines.push(`routes: ${entry.routes.join(', ')}`);
          for (const finding of entry.findings) {
            lines.push(`- [${finding.category}/${finding.severity}] ${finding.file}:${finding.line} ${finding.text}`);
          }
        }
        return [{ type: 'text', text: lines.join('\n') }];
      },
    },
    async execute(args) {
      const input = args !== null && typeof args === 'object' ? /** @type {any} */ (args) : {};
      const want = typeof input.plugin === 'string' ? input.plugin.trim() : '';
      const category = typeof input.category === 'string' ? input.category : '';
      const limit = Number.isFinite(input.limit) ? Math.min(50, Math.max(1, Math.floor(input.limit))) : 8;
      const data = await scan(false);
      const packages = [];
      for (const entry of data.packages) {
        if (want !== '' && entry.name !== want) continue;
        const findings = entry.findings
          .filter((finding) => category === '' || finding.category === category)
          .slice(0, limit)
          .map((finding) => ({
            category: finding.category,
            severity: finding.severity,
            file: finding.file,
            line: finding.line,
            text: finding.text,
          }));
        if (want === '' && category !== '' && findings.length === 0) continue;
        packages.push({
          name: entry.name,
          version: entry.version,
          risk: entry.risk,
          enabled: entry.enabled,
          domains: entry.domains.slice(0, 12).map((domain) => domain.host),
          routes: entry.routes.slice(0, 8),
          findings,
        });
      }
      if (want !== '' && packages.length === 0) throw new Error(`no installed package named "${want}"`);
      return { generatedAt: data.generatedAt, packages };
    },
  }), 'plugin-permissions: tool');
}
