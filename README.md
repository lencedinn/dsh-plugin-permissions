# dsh-plugin-permissions

**What can each of your DSH plugins actually reach?**

A DSH profile is a pile of third-party code running with your user rights.
This plugin reads every installed package and gives it a card: outbound hosts,
sensitive local stores it names, HTTP routes it opens, processes it spawns,
and package installs it performs at runtime. Static and read-only — it never
imports or runs plugin code.

```
┌───────────────────────────────────────────────────────────────┐
│ dsh-bili-scroll  2.0.0  已启用                          [高]  │
│ 12 域名 · 1 路由 · 1 敏感读取                                 │
│ 域名   www.bilibili.com  api.bilibili.com  passport…          │
│ 路由   prefix /api/bili-duty                                  │
│ 发现   [敏感读取] client.js:489  扫码成功但响应里没有 SESSDATA… │
└───────────────────────────────────────────────────────────────┘
```

## What it finds

| Category | Examples |
| --- | --- |
| Hosts | every external URL in the code, grouped by domain |
| Sensitive reads | `.credentials.yaml`, `~/.dsh/sessions`, browser cookie stores, SSH keys, `bili_credential.json`, `~/.codex` |
| Routes | `webServer.register()` paths, with `prefix` routes called out |
| Execution | `child_process`, `spawn`, PowerShell, Python subprocesses |
| Runtime installs | `pip` / `pnpm` / `curl` downloads the package record does not show |
| Install scripts | `preinstall` / `postinstall` / `prepare` hooks |

Findings describe **capability, not intent**. A plugin that talks to GitHub is
not suspicious by itself; the card exists so "which of my plugins can read my
tokens" takes seconds instead of an afternoon.

## Install

```bash
dsh plugin --profile web add github:lencedinn/dsh-plugin-permissions
```

For the desktop profile, the same command with `--profile desktop`.

A new package registers its client half on install; if the panel icon does not
appear, refresh the page once.

## Panel

Left rail → **插件透视 / Plugin Permissions**. Filter by high risk, network, or
routes; search by package, host, or route; expand a card for `file:line`
evidence. `Rescan` refreshes the 60-second cache.

## Tool

The agent sees the same scan:

```js
plugin_permissions({ plugin: "dsh-bili-scroll" })
plugin_permissions({ category: "sensitive" })
```

## Scope and limits

- Scans the profile's installed dependencies, skipping `@deepseek-ai/*`
  packages shipped with the harness; `@local/*` packages are included and
  tagged local.
- Skips `node_modules`, `dist`, `dev`, `test`, `docs`, and files over 1.5 MB.
- Regex-based: it reports what code *names*, not what it does at runtime. A
  minified bundle or a dynamically built URL can hide a destination.
- The scan route refuses cross-origin requests because findings expose local
  paths and source snippets.

## Config

| Field | Default | Meaning |
| --- | --- | --- |
| `profileDir` | auto-detected | Profile whose `node_modules` is scanned. |
| `includeOurs` | `true` | Include `@local/*` packages. |
| `exclude` | `[]` | Exact package names to skip. |

## Development

```bash
node dev/smoke.mjs          # fixture profile: scanner, risk verdict, route guards
node dev/scan.mjs [profile] # print the scan for a real profile
```

## License

MIT
