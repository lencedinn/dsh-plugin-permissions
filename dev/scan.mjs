/**
 * Run the permission scan against a real profile from the command line.
 *
 * Usage: node dev/scan.mjs [profileDir]
 * Prints the same text the agent tool returns, without starting DSH.
 */
import { join } from 'node:path';
import { homedir } from 'node:os';
import { apply } from '../index.js';

const profileDir = process.argv[2] ?? join(homedir(), '.dsh', 'profiles', 'desktop');
const tools = new Map();
const ctx = {
  effect(run) {
    return run();
  },
  inject(deps, callback) {
    if (deps.every((name) => name !== 'webServer')) return { dispose() {} };
    callback({ ...ctx, webServer: { register: () => () => undefined } });
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
const tool = tools.get('plugin_permissions');
const value = await tool.execute({}, {});
const rendered = tool.output.render({}, value);
console.log(rendered.map((block) => block.text).join('\n'));
console.log(`\npackages: ${value.packages.length}  profile: ${profileDir}`);
