// Bastion Shield — dashboard «Website-Ausnahmen»: per-site settings
// (protection off, blocking mode, script blocking, fingerprinting level),
// add / remove, search, import / export. Sites forced by policy are shown
// read-only with a lock.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BlockingMode, EffectiveConfig, FingerprintLevel, SiteSettings, SitesMap } from '../../../shared/types.ts';
import { downloadText, h, pickTextFile, replace, toast } from '../../shared/dom.ts';
import { plural, t } from '../../shared/i18n.ts';
import { hostnameCandidates } from '../../../shared/hash.ts';
import { icon } from '../../shared/icons.ts';
import { confirmDialog, lockIcon, switchControl } from '../../shared/controls.ts';
import { emptyState, errorState, nextId, normaliseHost, pageHead, panel, type View, mount } from '../common.ts';
import { getConfig, getSites, isLocked, setSites } from '../store.ts';

const MODES: BlockingMode[] = ['standard', 'aggressive'];
const FP: FingerprintLevel[] = ['off', 'standard', 'strict'];

function cleanEntry(v: unknown): SiteSettings | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const out: SiteSettings = {};
  if (typeof o.enabled === 'boolean') out.enabled = o.enabled;
  if (typeof o.mode === 'string' && (MODES as string[]).includes(o.mode)) out.mode = o.mode as BlockingMode;
  if (typeof o.blockScripts === 'boolean') out.blockScripts = o.blockScripts;
  if (typeof o.fingerprinting === 'string' && (FP as string[]).includes(o.fingerprinting)) out.fingerprinting = o.fingerprinting as FingerprintLevel;
  return out;
}

/** Accepts our export, a full backup, a plain {host: settings} map, or one hostname per line. */
export function parseSitesImport(text: string): SitesMap | null {
  const out: SitesMap = {};
  let data: unknown = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    const d = data as Record<string, unknown>;
    const map = (d.sites && typeof d.sites === 'object' ? d.sites : d) as Record<string, unknown>;
    for (const [k, v] of Object.entries(map)) {
      const host = normaliseHost(k);
      const entry = cleanEntry(v);
      if (host && entry) out[host] = entry;
    }
  } else if (data === null) {
    for (const line of text.split(/\r?\n/)) {
      const s = line.trim();
      if (!s || s.startsWith('#') || s.startsWith('!')) continue;
      const host = normaliseHost(s);
      if (host) out[host] = { enabled: false };
    }
  }
  return Object.keys(out).length ? out : null;
}

export function sitesView(): View {
  return {
    async render(root) {
      const [cfgR, sitesR] = await Promise.all([getConfig(), getSites()]);
      if (!cfgR.ok || !sitesR.ok) {
        mount(root, pageHead(t('sitesTitle'), t('sitesLead')), errorState(() => location.reload()));
        return;
      }
      const cfg: EffectiveConfig = cfgR.data;
      let sites: SitesMap = sitesR.data;
      const policyOff = new Set((cfg.managed.disabledSites ?? []).map((s) => normaliseHost(s)).filter((s): s is string => !!s));
      const policyAggr = new Set((cfg.managed.aggressiveSites ?? []).map((s) => normaliseHost(s)).filter((s): s is string => !!s));
      // Pseudo-path 'sites.enabled': users may not switch protection off (allowUserSiteToggle: false).
      const userToggleLocked = cfg.locked.includes('sites.enabled') || cfg.managed.allowUserSiteToggle === false;
      const settingsLocked = isLocked(cfg, 'sites');
      let query = '';

      // sites:set answers { sites }: the user's map as stored (the SW may drop locked or no-op entries).
      const save = async (next: SitesMap): Promise<boolean> => {
        const r = await setSites(next);
        if (!r.ok) {
          toast(r.error === 'locked' ? t('lockedByPolicy') : t('errorSaveFailed'), icon(r.error === 'locked' ? 'lock' : 'alert', 15));
          return false;
        }
        sites = r.data;
        return true;
      };
      const patch = async (host: string, p: SiteSettings): Promise<boolean> => {
        const next = { ...sites, [host]: { ...(sites[host] ?? {}), ...p } };
        return save(next);
      };

      const tbody = h('tbody');
      const tableWrap = h('div', { class: 'sites-scroll' });
      const countEl = h('span', { class: 'db-muted' });

      const draw = (focusHost?: string): void => {
        const hosts = Array.from(new Set([...Object.keys(sites), ...policyOff, ...policyAggr])).sort((a, b) => a.localeCompare(b));
        const shown = hosts.filter((x) => !query || x.includes(query));
        countEl.textContent = plural(hosts.length, 'sitesCountOne', 'sitesCount');
        if (!hosts.length) {
          replace(tableWrap, emptyState(t('sitesEmptyTitle'), t('sitesEmptyText')));
          return;
        }
        if (!shown.length) {
          replace(tableWrap, emptyState(t('sitesNoMatch')));
          return;
        }
        replace(
          tbody,
          ...shown.map((host) => {
            const s = sites[host] ?? {};
            // Policy hostnames include their subdomains (as the service worker enforces).
            const cands = hostnameCandidates(host);
            const forcedOff = cands.some((c) => policyOff.has(c));
            const forcedAggr = cands.some((c) => policyAggr.has(c));
            const rowLocked = forcedOff || forcedAggr || cfg.locked.includes(`sites.${host}`);
            const hostId = nextId('site');
            const enabled = forcedOff ? false : s.enabled !== false;

            const sw = switchControl({
              checked: enabled,
              label: `${t('sitesColProtection')}: ${host}`,
              disabled: forcedOff || userToggleLocked || settingsLocked,
              onChange: (v) => patch(host, { enabled: v }),
            });
            const modeSel = h(
              'select',
              { class: 'select select--sm', attrs: { 'aria-label': `${t('sitesColMode')}: ${host}`, disabled: forcedAggr || settingsLocked } },
              h('option', { attrs: { value: '' }, text: t('sitesDefault', cfg.settings.defaultMode === 'aggressive' ? t('modeAggressive') : t('modeStandard')) }),
              h('option', { attrs: { value: 'standard' }, text: t('modeStandard') }),
              h('option', { attrs: { value: 'aggressive' }, text: t('modeAggressive') }),
            );
            modeSel.value = forcedAggr ? 'aggressive' : (s.mode ?? '');
            modeSel.addEventListener('change', async () => {
              const prev = s.mode ?? '';
              const v = modeSel.value as BlockingMode | '';
              const next: SitesMap = { ...sites, [host]: { ...(sites[host] ?? {}) } };
              if (v) next[host].mode = v;
              else delete next[host].mode;
              if (!(await save(next))) modeSel.value = prev;
            });
            const scripts = switchControl({
              checked: !!s.blockScripts,
              label: `${t('sitesColScripts')}: ${host}`,
              disabled: settingsLocked,
              onChange: (v) => patch(host, { blockScripts: v }),
            });
            const fpSel = h(
              'select',
              { class: 'select select--sm', attrs: { 'aria-label': `${t('sitesColFingerprinting')}: ${host}`, disabled: settingsLocked } },
              h('option', { attrs: { value: '' }, text: t('sitesDefault', t(cfg.settings.privacy.fingerprinting === 'off' ? 'fpOff' : cfg.settings.privacy.fingerprinting === 'strict' ? 'fpStrict' : 'fpStandard')) }),
              h('option', { attrs: { value: 'off' }, text: t('fpOff') }),
              h('option', { attrs: { value: 'standard' }, text: t('fpStandard') }),
              h('option', { attrs: { value: 'strict' }, text: t('fpStrict') }),
            );
            fpSel.value = s.fingerprinting ?? '';
            fpSel.addEventListener('change', async () => {
              const prev = s.fingerprinting ?? '';
              const v = fpSel.value as FingerprintLevel | '';
              const next: SitesMap = { ...sites, [host]: { ...(sites[host] ?? {}) } };
              if (v) next[host].fingerprinting = v;
              else delete next[host].fingerprinting;
              if (!(await save(next))) fpSel.value = prev;
            });
            const remove = h(
              'button',
              { class: 'icon-btn', attrs: { type: 'button', 'aria-label': t('sitesRemoveAria', host), title: t('actionRemove'), disabled: !(host in sites) || settingsLocked } },
              icon('trash', 15),
            );
            remove.addEventListener('click', async () => {
              const next = { ...sites };
              delete next[host];
              if (await save(next)) {
                toast(t('sitesRemoved', host), icon('check', 15));
                draw();
              }
            });

            const tr = h(
              'tr',
              { dataset: { host } },
              h('th', { attrs: { scope: 'row', id: hostId } }, h('span', { class: 'sites-host' }, h('span', { class: 'mono', text: host }), rowLocked ? lockIcon(t('sitesPolicyRow')) : null)),
              h('td', null, sw.el),
              h('td', null, modeSel),
              h('td', null, scripts.el),
              h('td', null, fpSel),
              h('td', { class: 'sites-actions' }, remove),
            );
            return tr;
          }),
        );
        replace(
          tableWrap,
          h(
            'table',
            { class: 'sites-table' },
            h('caption', { class: 'sr-only', text: t('sitesTitle') }),
            h(
              'thead',
              null,
              h(
                'tr',
                null,
                ...[t('sitesColSite'), t('sitesColProtection'), t('sitesColMode'), t('sitesColScripts'), t('sitesColFingerprinting')].map((c) => h('th', { text: c, attrs: { scope: 'col' } })),
                h('th', { attrs: { scope: 'col' } }, h('span', { class: 'sr-only', text: t('actionRemove') })),
              ),
            ),
            tbody,
          ),
        );
        if (focusHost) {
          for (const tr of Array.from(tbody.querySelectorAll<HTMLElement>('tr'))) {
            if (tr.dataset.host === focusHost) {
              tr.classList.add('sites-row--new');
              tr.querySelector<HTMLElement>('.switch')?.focus();
            }
          }
        }
      };

      // ---- Add form -------------------------------------------------------------
      const input = h('input', { class: 'input', attrs: { type: 'text', placeholder: t('sitesAddPlaceholder'), 'aria-label': t('sitesAddLabel'), spellcheck: 'false', autocomplete: 'off', inputmode: 'url' } });
      const addHint = h('p', { class: 'sites-add__hint', attrs: { id: 'sites-add-hint', role: 'status' }, text: t('sitesAddHint') });
      input.setAttribute('aria-describedby', 'sites-add-hint');
      const form = h(
        'form',
        { class: 'sites-add' },
        input,
        h('button', { class: 'btn btn--primary', attrs: { type: 'submit', disabled: settingsLocked } }, icon('plus', 15), t('sitesAdd')),
      );
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const host = normaliseHost(input.value);
        if (!host) {
          addHint.textContent = t('sitesInvalid');
          input.focus();
          return;
        }
        if (host in sites) {
          addHint.textContent = t('sitesExists', host);
          draw(host);
          return;
        }
        if (await save({ ...sites, [host]: { enabled: false } })) {
          input.value = '';
          addHint.textContent = t('sitesAdded', host);
          draw(host);
        }
      });

      const search = h('input', { class: 'input', attrs: { type: 'search', placeholder: t('sitesSearch'), 'aria-label': t('sitesSearch'), spellcheck: 'false' } });
      search.addEventListener('input', () => {
        query = search.value.trim().toLowerCase();
        draw();
      });

      const exportBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' } }, icon('download', 14), t('actionExport'));
      exportBtn.addEventListener('click', () => {
        const stamp = new Date().toISOString().slice(0, 10);
        downloadText(`bastion-shield-sites-${stamp}.json`, `${JSON.stringify({ format: 'bastion-shield-sites', version: 1, exportedAt: new Date().toISOString(), sites }, null, 2)}\n`, 'application/json');
      });
      const importBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', disabled: settingsLocked } }, icon('upload', 14), t('actionImport'));
      importBtn.addEventListener('click', async () => {
        const text = await pickTextFile('.json,.txt,application/json,text/plain');
        if (text === null) return;
        const imported = parseSitesImport(text);
        if (!imported) {
          toast(t('sitesImportInvalid'), icon('alert', 15));
          return;
        }
        const n = Object.keys(imported).length;
        const ok = await confirmDialog({ title: t('sitesImportTitle'), body: plural(n, 'sitesImportTextOne', 'sitesImportText'), confirmLabel: t('actionImport') });
        if (!ok) return;
        if (await save({ ...sites, ...imported })) {
          toast(plural(n, 'sitesImportedOne', 'sitesImported'), icon('check', 15));
          draw();
        }
      });

      mount(root, 
        pageHead(t('sitesTitle'), t('sitesLead')),
        panel({ title: t('sitesAddTitle') }, form, addHint),
        panel(
          { title: t('sitesListTitle'), aside: countEl, flush: true },
          h('div', { class: 'sites-tools' }, h('span', { class: 'act-search' }, icon('search', 14), search), h('div', { class: 'sites-tools__io' }, importBtn, exportBtn)),
          tableWrap,
        ),
        h('p', { class: 'db-footnote', text: t('sitesFootnote') }),
      );
      draw();
    },
  };
}
