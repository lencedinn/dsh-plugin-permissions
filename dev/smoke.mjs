/**
 * Smoke test for the Plugin Permissions Host half.
 *
 * Builds a throwaway profile with two fixture packages - one deliberately
 * noisy, one clean - runs the real scanner through a stub Cordis context, and
 * checks the findings, the risk verdict, and the route's guards.
 *
 * Usage: node dev/smoke.mjs
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { apply, inject } from '../index.js';

let passed = 0;
function check(name, run) {
  run();
  passed += 1;
  console.log(`PASS ${name}`);
}
async function checkAsync(name, run) {
  const value = await run();
  passed += 1;
  console.log(`PASS ${name}`);
  return value;
}

/** One simulated host: tools, routes, and the inject seam. */
function host(profileDir) {
  const tools = new Map();
  const routes = new Map();
  const webServer = {
    register(route) {
      routes.set(route.path, route);
      return () => routes.delete(route.path);
    },
  };
  const ctx = {
    webServer,
    effect(run) {
      return run();
    },
    inject(deps, callback) {
      if (deps.every((name) => name !== 'webServer' || webServer !== undefined)) callback(ctx);
      return { dispose() {} };
    },
    tools: {
      register(definition) {
        tools.set(definition.name, definition);
        return () => tools.delete(definition.name);
      },
    },
  };
  apply(ctx, { profileDir });
  return { ctx, tools, routes };
}

function writeFile(path, content) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content, 'utf8');
}

const root = mkdtempSync(join(tmpdir(), 'plugin-permissions-smoke-'));

try {
  // ---- fixture profile -------------------------------------------------
  writeFile(join(root, 'package.json'), JSON.stringify({
    name: 'fixture-profile',
    private: true,
    dsh: { profile: { bundles: ['demo-bad'] } },
    dependencies: {
      'demo-bad': '1.0.0',
      'demo-clean': '1.0.0',
      '@deepseek-ai/dsh-should-be-skipped': '1.0.0',
    },
  }, null, 2));

  writeFile(join(root, 'node_modules', 'demo-bad', 'package.json'), JSON.stringify({
    name: 'demo-bad',
    version: '1.0.0',
    scripts: { postinstall: 'node setup.js' },
  }, null, 2));
  writeFile(join(root, 'node_modules', 'demo-bad', 'index.js'), [
    "import { spawn } from 'node:child_process';",
    "import { readFileSync } from 'node:fs';",
    "const endpoint = 'https://api.example.com/v1/data';",
    'await fetch(endpoint);',
    'const key = process.env.DEEPSEEK_API_KEY;',
    "const cred = readFileSync(join(home, '.dsh', 'bili-duty', 'bili_credential.json'), 'utf8');",
    "spawn('powershell.exe', ['-Command', 'dir']);",
    "webServer.register({ kind: 'prefix', path: '/api/bad', handler: (req, res) => res.end() });",
  ].join('\n'));

  writeFile(join(root, 'node_modules', 'demo-clean', 'package.json'), JSON.stringify({
    name: 'demo-clean',
    version: '1.0.0',
  }, null, 2));
  writeFile(join(root, 'node_modules', 'demo-clean', 'index.js'), 'export const answer = 42;\n');

  writeFile(join(root, 'node_modules', '@deepseek-ai', 'dsh-should-be-skipped', 'package.json'), JSON.stringify({
    name: '@deepseek-ai/dsh-should-be-skipped',
    version: '1.0.0',
  }));
  writeFile(join(root, 'node_modules', '@deepseek-ai', 'dsh-should-be-skipped', 'index.js'), "fetch('https://shipped.example.com');\n");

  const app = host(root);
  assert.deepEqual(inject, ['tools']);

  const result = await checkAsync('scans every non-official package and skips @deepseek-ai', async () => {
    const tool = app.tools.get('plugin_permissions');
    assert.ok(tool, 'tool is registered');
    return tool.execute({ limit: 20 }, {});
  });

  check('the noisy package is rated high and the clean one low', () => {
    const byName = new Map(result.packages.map((entry) => [entry.name, entry]));
    assert.equal(byName.has('@deepseek-ai/dsh-should-be-skipped'), false);
    assert.equal(byName.get('demo-bad').risk, 'high');
    assert.equal(byName.get('demo-clean').risk, 'low');
    assert.equal(byName.get('demo-bad').enabled, true);
    assert.equal(byName.get('demo-clean').enabled, false);
  });

  check('hosts, routes, sensitive reads, execution and install scripts are all found', () => {
    const bad = result.packages.find((entry) => entry.name === 'demo-bad');
    assert.deepEqual(bad.domains, ['api.example.com']);
    assert.ok(bad.routes.some((route) => route.includes('/api/bad')), JSON.stringify(bad.routes));
    const categories = new Set(bad.findings.map((finding) => finding.category));
    for (const category of ['egress', 'sensitive', 'exec', 'route', 'install']) {
      assert.ok(categories.has(category), `missing ${category}: ${[...categories].join(',')}`);
    }
    assert.ok(bad.findings.every((finding) => typeof finding.file === 'string' && typeof finding.line === 'number' && finding.line >= 1));
    // The tool output schema is closed: extra per-finding fields would be rejected at runtime.
    for (const finding of bad.findings) {
      assert.deepEqual(Object.keys(finding).sort(), ['category', 'file', 'line', 'severity', 'text']);
    }
  });

  check('the clean package reports no findings', () => {
    const clean = result.packages.find((entry) => entry.name === 'demo-clean');
    assert.deepEqual(clean.domains, []);
    assert.deepEqual(clean.routes, []);
    assert.deepEqual(clean.findings, []);
  });

  await checkAsync('the scan route serves the same data and honours the origin guard', async () => {
    const route = app.routes.get('/api/plugin-permissions/scan');
    assert.ok(route, 'scan route is registered');

    const ok = makeResponse();
    await route.handler(makeRequest('GET'), ok);
    assert.equal(ok.out.status, 200);
    assert.equal(ok.out.body.counts.packages, 2);

    const foreign = makeRequest('GET');
    foreign.headers = { origin: 'https://evil.example', host: '127.0.0.1:62125' };
    const blocked = makeResponse();
    await route.handler(foreign, blocked);
    assert.equal(blocked.out.status, 403);

    const wrongMethod = makeResponse();
    await route.handler(makeRequest('POST'), wrongMethod);
    assert.equal(wrongMethod.out.status, 405);

    const refreshed = makeResponse();
    await route.handler(makeRequest('GET', '?refresh=1'), refreshed);
    assert.equal(refreshed.out.status, 200);
  });

  await checkAsync('an unknown package name is an error', async () => {
    const tool = app.tools.get('plugin_permissions');
    await assert.rejects(() => tool.execute({ plugin: 'nope' }, {}), /no installed package named "nope"/);
  });

  await checkAsync('finds the profile from the working directory when no config is given', async () => {
    const previousCwd = process.cwd();
    const previousEnv = process.env.DSH_PROFILE_DIR;
    delete process.env.DSH_PROFILE_DIR;
    process.chdir(root);
    try {
      const plain = host(undefined);
      const value = await plain.tools.get('plugin_permissions').execute({}, {});
      assert.equal(value.packages.length, 2);
    } finally {
      process.chdir(previousCwd);
      if (previousEnv !== undefined) process.env.DSH_PROFILE_DIR = previousEnv;
    }
  });

  console.log(`\n${passed} checks passed. Fixture: ${root}`);
} finally {
  rmSync(root, { recursive: true, force: true });
}

/** A request the route handler can read. */
function makeRequest(method, search = '') {
  return {
    method,
    url: `/api/plugin-permissions/scan${search}`,
    headers: {},
  };
}

/** A response that records status and body. */
function makeResponse() {
  const out = { status: 0, body: null };
  return {
    out,
    writeHead(status) {
      out.status = status;
    },
    end(payload) {
      out.body = JSON.parse(payload.toString('utf8'));
    },
  };
}
