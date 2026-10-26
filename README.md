# dsh-plugin-permissions

**What can each of your DSH plugins actually reach?**

A DSH profile is a pile of third-party code running with your user rights.
This plugin reads every installed package and turns it into a permission card:
outbound hosts, sensitive local stores it names, HTTP routes it opens,
processes it spawns, and installs it performs at runtime.

Static and read-only — it never imports or runs plugin code.

## What it reports

| Category | What the card shows |
| --- | --- |
| Hosts | every external domain named in the code, grouped and counted |
| Sensitive reads | credential stores, session logs, browser cookie files, SSH keys, API tokens |
| Routes | `webServer.register()` paths, with `prefix` routes called out |
| Execution | child processes, shells, PowerShell, Python subprocesses |
| Runtime installs | downloads the package record does not show |
| Install scripts | `preinstall` / `postinstall` / `prepare` hooks |

Each finding carries the file and line it came from, so a card is a starting
point for reading the code, not a verdict. Findings describe **capability, not
intent**: a plugin that talks to GitHub is not suspicious by itself. The point
is that "which of my plugins can read my tokens" takes seconds instead of an
afternoon.

## The panel

Left rail → **插件透视 / Plugin Permissions**. One card per package, sorted with
enabled packages first:

```
┌───────────────────────────────────────────────────────────────┐
│ plugin-name  1.2.3  已启用                             [高]   │
│ 3 域名 · 1 路由 · 1 敏感读取                                  │
│                                                               │
│ 域名    api.example.net   cdn.example.net   …                 │
│ 路由    prefix /api/plugin-name                               │
│ 发现    [敏感读取] index.js:42   读取了凭据文件 …              │
└───────────────────────────────────────────────────────────────┘
```

- **Header** — how many packages were scanned and how many are high risk, plus
  a `Rescan` button.
- **Filter tabs** — all / high risk / has network / has routes.
- **Search** — matches package names, hosts, routes, and finding text.
- **Expand** — the first few findings are always visible; expanding shows every
  finding with its `file:line`.
- **Empty and clean packages** say so: no hosts, no routes, no findings.

## The tool

The agent sees the same scan through one tool, so a question in chat and a card
on screen never disagree:

```js
plugin_permissions({ plugin: "some-plugin" })
plugin_permissions({ category: "sensitive" })
```

## Install

```bash
dsh plugin --profile web add github:lencedinn/dsh-plugin-permissions
```

Use `--profile desktop` for the desktop app. A newly installed package is picked
up on the next page load; if the panel icon does not appear, refresh once.

## Scope and limits

- Scans the profile's installed dependencies. `@deepseek-ai/*` packages shipped
  with the harness are skipped; `@local/*` packages are included and tagged
  local.
- Skips `node_modules`, `dist`, `dev`, `test`, `docs`, and files over 1.5 MB.
- Regex-based and static: it reports what code *names*, not what it does at
  runtime. A minified bundle or a dynamically built URL can hide a destination.
- The scan route refuses cross-origin requests, because findings expose local
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
