/**
 * Plugin Permissions - Client half.
 *
 * One panel in the left rail. It renders the scan the Host performed: per
 * package, its risk badge, outbound hosts, routes, and every finding with a
 * file and line. The panel never scans anything itself - the Host owns the
 * filesystem, and one implementation keeps the card and the agent tool equal.
 *
 * Plain JavaScript on purpose - no JSX, no imports beyond the module table.
 */
window.__ModuleLoader__.load({
  id: 'dsh-plugin-permissions',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const NS = 'plugin-permissions';
    const PANEL_ID = 'plugin-permissions';
    const ENDPOINT = '/api/plugin-permissions/scan';

    const CATEGORY_LABEL = {
      egress: '外发',
      sensitive: '敏感读取',
      route: '路由',
      exec: '进程',
      install: '运行时安装',
      active: 'DOM / eval',
    };

    const COPY = {
      zh: {
        panel: '插件透视',
        title: '插件透视',
        subtitle: '静态扫描已安装插件的文件：它们能连哪些域名、读哪些敏感存储、开哪些路由、起哪些进程。只读，不执行任何插件代码。',
        rescan: '重扫',
        scanning: '扫描中…',
        searchPlaceholder: '搜索插件名、域名或路由',
        all: '全部',
        high: '高风险',
        withEgress: '有外发',
        withRoutes: '有路由',
        enabled: '已启用',
        disabled: '未启用',
        ours: '自研',
        riskHigh: '高',
        riskMedium: '中',
        riskLow: '低',
        domains: '域名',
        routes: '路由',
        findings: '发现',
        noFindings: '没扫到可疑能力',
        empty: '没有匹配的插件。',
        failed: '扫描失败',
        generated: '扫描于',
        summary: '个插件',
        files: '个文件',
        footer: '扫描范围：当前 profile 的已装依赖，跳过 @deepseek-ai 官方包。判定只陈述能力，不代表恶意。',
        loading: '加载中…',
      },
      en: {
        panel: 'Plugin permissions',
        title: 'Plugin Permissions',
        subtitle: 'Static scan of installed plugins: hosts they reach, sensitive stores they name, routes they open, processes they spawn. Read-only; no plugin code runs.',
        rescan: 'Rescan',
        scanning: 'Scanning…',
        searchPlaceholder: 'Search package, host, or route',
        all: 'All',
        high: 'High risk',
        withEgress: 'Network',
        withRoutes: 'Routes',
        enabled: 'enabled',
        disabled: 'disabled',
        ours: 'local',
        riskHigh: 'high',
        riskMedium: 'medium',
        riskLow: 'low',
        domains: 'hosts',
        routes: 'routes',
        findings: 'findings',
        noFindings: 'No notable capability found',
        empty: 'No matching plugin.',
        failed: 'Scan failed',
        generated: 'Scanned',
        summary: 'plugins',
        files: 'files',
        footer: 'Scope: installed dependencies of this profile, excluding @deepseek-ai packages. Findings describe capability, not intent.',
        loading: 'Loading…',
      },
    };

    const CSS = `
.pp-root { display: flex; flex-direction: column; height: 100%; min-height: 0; color: var(--dsw-alias-label-primary); }
.pp-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 24px 14px; border-bottom: 1px solid var(--dsw-alias-border-l1); }
.pp-title { margin: 0; font-size: 16px; font-weight: 600; line-height: 1.4; }
.pp-subtitle { margin: 4px 0 0; font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-secondary); max-width: 720px; }
.pp-headActions { display: flex; align-items: center; gap: 8px; flex: none; }
.pp-stat { font-size: 12px; color: var(--dsw-alias-label-secondary); white-space: nowrap; }
.pp-body { flex: 1; min-height: 0; overflow: auto; padding: 16px 24px 28px; }
.pp-toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.pp-search { flex: 1; min-width: 0; height: 30px; padding: 0 10px; font: inherit; font-size: 12px; color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px; }
.pp-search:focus { outline: none; border-color: var(--dsw-alias-brand-primary); }
.pp-tabs { display: inline-flex; flex: none; border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px; overflow: hidden; }
.pp-tab { padding: 6px 10px; font: inherit; font-size: 12px; color: var(--dsw-alias-label-secondary); background: transparent; border: none; border-right: 1px solid var(--dsw-alias-border-l1); cursor: pointer; }
.pp-tab:last-child { border-right: none; }
.pp-tab:hover { color: var(--dsw-alias-label-primary); }
.pp-tab.is-on { color: var(--dsw-alias-brand-primary); background: var(--dsw-alias-bg-layer-2); }
.pp-list { display: flex; flex-direction: column; gap: 8px; margin: 0; padding: 0; list-style: none; }
.pp-card { padding: 12px 14px; background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-border-l1); border-left-width: 3px; border-radius: 8px; }
.pp-card.risk-high { border-left-color: var(--dsw-alias-state-error-primary); }
.pp-card.risk-medium { border-left-color: var(--dsw-alias-state-warn-primary); }
.pp-card.risk-low { border-left-color: var(--dsw-alias-state-success-primary); }
.pp-headRow { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.pp-name { font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
.pp-ver { font-size: 11px; color: var(--dsw-alias-label-secondary); font-variant-numeric: tabular-nums; }
.pp-tag { padding: 1px 7px; font-size: 11px; line-height: 1.7; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-2); border-radius: 4px; }
.pp-risk { margin-left: auto; padding: 1px 8px; font-size: 11px; line-height: 1.7; border: 1px solid currentColor; border-radius: 4px; }
.pp-risk.high { color: var(--dsw-alias-state-error-primary); }
.pp-risk.medium { color: var(--dsw-alias-state-warn-primary); }
.pp-risk.low { color: var(--dsw-alias-state-success-primary); }
.pp-badges { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.pp-badge { padding: 1px 7px; font-size: 11px; line-height: 1.7; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-layer-2); border-radius: 4px; }
.pp-section { margin-top: 10px; }
.pp-sectionTitle { font-size: 11px; font-weight: 600; letter-spacing: 0.03em; color: var(--dsw-alias-label-secondary); text-transform: uppercase; }
.pp-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
.pp-chip { padding: 1px 7px; font-size: 11px; line-height: 1.7; background: var(--dsw-alias-bg-layer-2); border-radius: 4px; overflow-wrap: anywhere; }
.pp-chip code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.pp-findings { margin: 6px 0 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 4px; }
.pp-finding { display: flex; gap: 8px; font-size: 11px; line-height: 1.6; color: var(--dsw-alias-label-secondary); }
.pp-cat { flex: none; min-width: 74px; color: var(--dsw-alias-label-primary); }
.pp-loc { flex: none; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--dsw-alias-brand-primary); }
.pp-text { min-width: 0; overflow-wrap: anywhere; }
.pp-alert { margin-bottom: 12px; padding: 10px 12px; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-state-error-primary); background: var(--dsw-alias-bg-layer-1); border: 1px solid var(--dsw-alias-state-error-primary); border-radius: 6px; }
.pp-empty { padding: 40px 0; font-size: 13px; text-align: center; color: var(--dsw-alias-label-secondary); }
.pp-footer { margin: 22px 0 0; padding-top: 12px; border-top: 1px solid var(--dsw-alias-border-l1); font-size: 11px; line-height: 1.7; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }
.pp-btn { padding: 4px 10px; font: inherit; font-size: 12px; color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-layer-2); border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px; cursor: pointer; }
.pp-btn:hover:not(:disabled) { border-color: var(--dsw-alias-border-l2); }
.pp-btn:disabled { opacity: 0.55; cursor: default; }
.pp-btnPrimary { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); background: transparent; }
.pp-toggle { margin-top: 8px; padding: 0; font: inherit; font-size: 11px; color: var(--dsw-alias-brand-primary); background: none; border: none; cursor: pointer; }
`;

    /** @param {unknown} error */
    function messageOf(error) {
      return error instanceof Error ? error.message : String(error);
    }

    /** @param {string} url */
    async function requestJson(url) {
      if (typeof fetch !== 'function') throw new Error('this page cannot reach the Host');
      const response = await fetch(url, { headers: { accept: 'application/json' } });
      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      if (!response.ok) {
        const reason = body !== null && typeof body === 'object' && typeof body.error === 'string'
          ? body.error
          : `Host answered ${response.status}`;
        throw new Error(reason);
      }
      if (body === null || typeof body !== 'object') throw new Error('the Host returned no data');
      return body;
    }

    function fallbackTranslate(key) {
      const dict = COPY.zh;
      return typeof dict[key] === 'string' ? dict[key] : key;
    }

    /**
     * @param {{t: Function, entry: any}} props
     */
    function PackageCard({ t, entry }) {
      const [open, setOpen] = React.useState(false);
      const counts = {
        egress: entry.domains.length,
        route: entry.routes.length,
        sensitive: entry.findings.filter((finding) => finding.category === 'sensitive').length,
        exec: entry.findings.filter((finding) => finding.category === 'exec').length,
        install: entry.findings.filter((finding) => finding.category === 'install').length,
      };
      const badges = [
        counts.egress > 0 ? `${counts.egress} ${t('domains')}` : '',
        counts.route > 0 ? `${counts.route} ${t('routes')}` : '',
        counts.sensitive > 0 ? `${counts.sensitive} ${CATEGORY_LABEL.sensitive}` : '',
        counts.exec > 0 ? CATEGORY_LABEL.exec : '',
        counts.install > 0 ? CATEGORY_LABEL.install : '',
      ].filter((value) => value !== '');

      const shown = open ? entry.findings : entry.findings.slice(0, 4);
      const riskLabel = entry.risk === 'high' ? t('riskHigh') : entry.risk === 'medium' ? t('riskMedium') : t('riskLow');

      return h('li', { className: `pp-card risk-${entry.risk}` },
        h('div', { className: 'pp-headRow' },
          h('span', { className: 'pp-name' }, entry.name),
          h('span', { className: 'pp-ver' }, entry.version),
          h('span', { className: 'pp-tag' }, entry.enabled ? t('enabled') : t('disabled')),
          entry.ours ? h('span', { className: 'pp-tag' }, t('ours')) : null,
          h('span', { className: `pp-risk ${entry.risk}` }, riskLabel),
        ),
        badges.length > 0 ? h('div', { className: 'pp-badges' }, badges.map((badge) => h('span', { key: badge, className: 'pp-badge' }, badge))) : null,
        entry.domains.length > 0
          ? h('div', { className: 'pp-section' },
            h('div', { className: 'pp-sectionTitle' }, t('domains')),
            h('div', { className: 'pp-chips' },
              entry.domains.slice(0, open ? 40 : 6).map((domain) => h('span', { key: domain.host, className: 'pp-chip' },
                h('code', null, domain.host), domain.count > 1 ? ` ×${domain.count}` : '')),
              !open && entry.domains.length > 6 ? h('span', { className: 'pp-chip' }, `+${entry.domains.length - 6}`) : null,
            ),
          )
          : null,
        entry.routes.length > 0
          ? h('div', { className: 'pp-section' },
            h('div', { className: 'pp-sectionTitle' }, t('routes')),
            h('div', { className: 'pp-chips' },
              entry.routes.slice(0, open ? 20 : 4).map((route) => h('span', { key: route, className: 'pp-chip' }, h('code', null, route)))),
            )
          : null,
        shown.length > 0
          ? h('div', { className: 'pp-section' },
            h('div', { className: 'pp-sectionTitle' }, `${t('findings')} (${entry.findings.length})`),
            h('ul', { className: 'pp-findings' },
              shown.map((finding, index) => h('li', { key: `${finding.file}:${finding.line}:${index}`, className: 'pp-finding' },
                h('span', { className: 'pp-cat' }, CATEGORY_LABEL[finding.category] ?? finding.category),
                h('span', { className: 'pp-loc' }, `${finding.file}:${finding.line}`),
                h('span', { className: 'pp-text' }, finding.text),
              )),
            ),
          )
          : h('div', { className: 'pp-section' }, h('span', { className: 'pp-badge' }, t('noFindings'))),
        entry.findings.length > 4
          ? h('button', { type: 'button', className: 'pp-toggle', onClick: () => setOpen((value) => !value) },
            open ? t('all') + ' ⌃' : t('all') + ' ⌄')
          : null,
      );
    }

    /**
     * @param {{t?: Function}} props
     */
    function PermissionsPanel(props) {
      const t = typeof props?.t === 'function' ? props.t : fallbackTranslate;
      const [data, setData] = React.useState(null);
      const [loading, setLoading] = React.useState(true);
      const [busy, setBusy] = React.useState(false);
      const [error, setError] = React.useState('');
      const [query, setQuery] = React.useState('');
      const [filter, setFilter] = React.useState('all');
      const [nonce, setNonce] = React.useState(0);

      React.useEffect(() => {
        let live = true;
        setLoading(true);
        requestJson(nonce === 0 ? ENDPOINT : `${ENDPOINT}?refresh=1`)
          .then((value) => {
            if (!live) return;
            setData(value);
            setError('');
          })
          .catch((cause) => {
            if (live) setError(messageOf(cause));
          })
          .finally(() => {
            if (live) {
              setLoading(false);
              setBusy(false);
            }
          });
        return () => {
          live = false;
        };
      }, [nonce]);

      const packages = data !== null && Array.isArray(data.packages) ? data.packages : [];

      const visible = React.useMemo(() => {
        const words = query.trim().toLowerCase().split(/\s+/).filter((word) => word.length > 0);
        return packages.filter((entry) => {
          if (filter === 'high' && entry.risk !== 'high') return false;
          if (filter === 'egress' && entry.domains.length === 0) return false;
          if (filter === 'routes' && entry.routes.length === 0) return false;
          if (words.length === 0) return true;
          const haystack = [
            entry.name,
            entry.version,
            ...entry.domains.map((domain) => domain.host),
            ...entry.routes,
            ...entry.findings.slice(0, 12).map((finding) => `${finding.file} ${finding.text}`),
          ].join(' ').toLowerCase();
          return words.every((word) => haystack.includes(word));
        });
      }, [packages, filter, query]);

      const tab = (key, label) => h('button', {
        type: 'button',
        className: `pp-tab${filter === key ? ' is-on' : ''}`,
        'aria-pressed': filter === key,
        onClick: () => setFilter(key),
      }, label);

      return h('div', { className: 'pp-root' },
        h('style', { key: 'pp-style' }, CSS),
        h('div', { className: 'pp-head' },
          h('div', null,
            h('h2', { className: 'pp-title' }, t('title')),
            h('p', { className: 'pp-subtitle' }, t('subtitle')),
          ),
          h('div', { className: 'pp-headActions' },
            h('span', { className: 'pp-stat' },
              data !== null ? `${data.counts.packages} ${t('summary')} · ${data.counts.high} ${t('riskHigh')}` : '—'),
            h('button', {
              type: 'button',
              className: 'pp-btn pp-btnPrimary',
              disabled: busy || loading,
              onClick: () => {
                setBusy(true);
                setNonce((value) => value + 1);
              },
            }, busy || loading ? t('scanning') : t('rescan')),
          ),
        ),
        h('div', { className: 'pp-body' },
          error.length > 0 ? h('div', { className: 'pp-alert' }, `${t('failed')}: ${error}`) : null,
          h('div', { className: 'pp-toolbar' },
            h('input', {
              className: 'pp-search',
              value: query,
              placeholder: t('searchPlaceholder'),
              'aria-label': t('searchPlaceholder'),
              onChange: (event) => setQuery(event.target.value),
            }),
            h('div', { className: 'pp-tabs' },
              tab('all', t('all')),
              tab('high', t('high')),
              tab('egress', t('withEgress')),
              tab('routes', t('withRoutes')),
            ),
          ),
          visible.length === 0
            ? h('p', { className: 'pp-empty' }, loading ? t('loading') : t('empty'))
            : h('ul', { className: 'pp-list' }, visible.map((entry) => h(PackageCard, { key: entry.name, t, entry }))),
          h('p', { className: 'pp-footer' },
            t('footer'),
            data !== null ? ` ${t('generated')} ${data.generatedAt} · ${data.counts.files} ${t('files')}` : '',
            data !== null ? h('div', null, h('code', null, data.profileDir)) : null,
          ),
        ),
      );
    }

    /**
     * Sidebar glyph: a lens over a package.
     *
     * @param {{size: number}} props
     */
    function LensIcon({ size }) {
      return h('svg', {
        width: size,
        height: size,
        viewBox: '0 0 24 24',
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 1.7,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
        'aria-hidden': true,
        focusable: false,
      },
        h('circle', { cx: 10.5, cy: 10.5, r: 5.8 }),
        h('path', { d: 'M14.8 14.8L20 20' }),
        h('path', { d: 'M8.2 10.5h4.6M10.5 8.2v4.6' }),
      );
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, COPY), 'plugin-permissions: dictionaries');
        const t = ctx.locale.bind(NS);

        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
          name: 'sidebar.panellist',
          id: PANEL_ID,
          order: 40,
          label: () => t('panel'),
        }, LensIcon));

        ctx.slots.inject('main', () => ctx.slots.register({
          name: 'main',
          key: PANEL_ID,
          locale: NS,
        }, PermissionsPanel));
      },
    };
  },
});
