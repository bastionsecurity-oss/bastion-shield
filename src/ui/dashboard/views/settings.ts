// Bastion Shield — dashboard «Einstellungen»: default blocking mode, toolbar
// badge, activity log, history and retention, backup export / import and
// reset to defaults, and the nerd-mode switches. Backups are plain JSON files
// the user saves locally.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BackupFile, BlockingMode, EffectiveConfig, Settings } from '../../../shared/types.ts';
import { append, downloadText, h, pickTextFile, replace, toast } from '../../shared/dom.ts';
import { clearI18nCache, fmtDateTime, fmtNumber, plural, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { call } from '../../shared/messaging.ts';
import { confirmDialog, lockBadge, lockIcon, notice, segmented, switchControl } from '../../shared/controls.ts';
import { errorState, nextId, openTabButton, pageHead, panel, popupMode, settingRow, type View, mount } from '../common.ts';
import { adoptConfig, getConfig, getLists, ignoredPaths, isLocked, saveSettings } from '../store.ts';
import { persist } from './privacy.ts';
import { revealNerd } from '../nerd-reveal.ts';
import { shortcutLabel } from '../rail.ts';
import { commandHelp } from '../../popup/commands.ts';

const RETENTION = [1, 7, 30, 90, 180, 365];

/** localStorage, a per-device convenience only: the nerd help decoded once already. */
const HELP_SEEN = 'bs.nerdHelp.seen';

function readFlag(key: string): boolean {
  try {
    return localStorage.getItem(key) === '1';
  } catch {
    return false;
  }
}

function writeFlag(key: string): void {
  try {
    localStorage.setItem(key, '1');
  } catch {
    /* private window or blocked storage: the reveal may play again next time */
  }
}

/** Documented defaults (src/shared/types.ts). Used by «Zurücksetzen». */
export function defaultSettings(): Settings {
  return {
    version: 1,
    defaultMode: 'standard',
    lists: {},
    privacy: {
      gpc: true,
      stripParams: true,
      debounce: true,
      deAmp: true,
      fingerprinting: 'standard',
      blockHyperlinkAuditing: true,
      webrtcPolicy: 'default',
      blockThirdPartyCookies: null,
      disablePrivacySandboxAds: true,
      clipboardGuard: true,
    },
    ui: { badge: true, activityLog: true, incidentCta: true, language: 'auto' },
    history: { enabled: true, retentionDays: 30 },
    nerd: { enabled: false, contextMenu: true, filterHistory: true, fingerprintMeter: true, lookalike: true, protectedDomains: [] },
  };
}

/** Minimal structural validation of an imported backup file. */
export function validateBackup(data: unknown): BackupFile | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Partial<BackupFile>;
  if (d.format !== 'bastion-shield-backup' || d.version !== 1) return null;
  if (!d.settings || typeof d.settings !== 'object' || (d.settings as Settings).version !== 1) return null;
  if (d.sites !== undefined && (typeof d.sites !== 'object' || d.sites === null || Array.isArray(d.sites))) return null;
  if (d.customFilters !== undefined && typeof d.customFilters !== 'string') return null;
  return { format: 'bastion-shield-backup', version: 1, exportedAt: String(d.exportedAt ?? ''), settings: d.settings as Settings, sites: d.sites ?? {}, customFilters: d.customFilters ?? '' };
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

/**
 * Protected domains typed one per line (also accepts commas and URLs):
 * lower-cased, scheme, path and a leading "www." removed, IDNs punycoded,
 * deduplicated. `invalid` holds the entries that are not domain names.
 */
export function parseProtectedDomains(text: string): { domains: string[]; invalid: string[] } {
  const domains: string[] = [];
  const invalid: string[] = [];
  for (const raw of text.split(/[\n,;]+/)) {
    const s = raw.trim();
    if (s === '' || s.startsWith('#') || s.startsWith('!')) continue;
    let d = s.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/:?#].*$/, '').replace(/\.$/, '');
    try {
      d = new URL(`https://${d}`).hostname;
    } catch {
      /* keep d; the check below rejects it */
    }
    d = d.replace(/^www\./, '');
    if (DOMAIN_RE.test(d)) {
      if (!domains.includes(d)) domains.push(d);
    } else {
      invalid.push(s);
    }
  }
  return { domains, invalid };
}

/**
 * «Nerd-Modus»: a normal settings group. The master switch row carries one
 * sober line; while it is on, a short reference (the popup's Ctrl+K command
 * line and the bisect shortcut), the switches for the visible extras
 * (context menu, filter history links), the guards (fingerprinting meter,
 * lookalike warning) and the protected-domain list appear. Policy domains are shown read-only; the user's own
 * list is the effective list minus the policy's.
 */
function nerdPanel(cfg: EffectiveConfig): HTMLElement {
  const n = cfg.settings.nerd ?? defaultSettings().nerd;
  const policyDomains = (cfg.managed.protectedDomains ?? []).map((d) => d.toLowerCase());
  const userDomains = n.protectedDomains.filter((d) => !policyDomains.includes(d));

  const sub = h('div', { class: 'nerd-sub', hidden: !n.enabled });

  const row = (path: string, value: boolean, labelKey: string, descKey: string, patch: (v: boolean) => Parameters<typeof persist>[0]): HTMLElement => {
    const labelId = nextId('set');
    const descId = nextId('set-d');
    const locked = isLocked(cfg, path);
    const sw = switchControl({ checked: value, labelledBy: labelId, describedBy: descId, disabled: locked, onChange: (v) => persist(patch(v)) });
    return settingRow({ label: t(labelKey), desc: t(descKey), control: sw.el, locked, labelId, descId });
  };

  // Keyboard shortcuts: none is suggested in the manifest (a suggested key that clashes with a
  // browser shortcut shows as set but does not fire), so the user sets them here in one click.
  const kbd = (k: string): HTMLElement => h('kbd', { class: 'lab-kbd', text: k });
  const keyValue = (): HTMLElement => h('span', { class: 'nerd-help__unset', text: t('nerdHelpNoShortcut') });
  const popupKey = h('span', { class: 'nerd-keys__key' }, keyValue());
  const bisectKey = h('span', { class: 'nerd-keys__key' }, keyValue());
  const paintKeys = async (): Promise<void> => {
    try {
      // As the browser names them (US key positions), matching its own shortcuts page.
      for (const c of (await chrome.commands?.getAll()) ?? []) {
        const cell = c.name === '_execute_action' ? popupKey : c.name === 'nerd-bisect' ? bisectKey : null;
        if (cell) replace(cell, c.shortcut ? kbd(c.shortcut) : keyValue());
      }
    } catch {
      /* no commands API (tests) */
    }
  };
  void paintKeys();
  // Back from the shortcuts page: show what was set there.
  window.addEventListener('focus', () => void paintKeys());
  const shortcutsUrl = /Edg\//.test(navigator.userAgent) ? 'edge://extensions/shortcuts' : 'chrome://extensions/shortcuts';
  const keysLabel = nextId('set');
  const shortcuts = h(
    'div',
    { class: 'db-row nerd-keys' },
    h(
      'div',
      { class: 'db-row__text' },
      h('div', { class: 'db-row__label', text: t('nerdKeysTitle'), attrs: { id: keysLabel } }),
      h(
        'p',
        { class: 'nerd-keys__list' },
        h('span', { class: 'nerd-keys__item' }, h('span', { text: t('nerdHelpKeyPopup') }), popupKey),
        h('span', { class: 'nerd-keys__item' }, h('span', { text: t('nerdHelpKeyBisect') }), bisectKey),
      ),
    ),
    h(
      'div',
      { class: 'db-row__ctl' },
      h(
        'button',
        { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', 'aria-describedby': keysLabel }, on: { click: () => void chrome.tabs.create({ url: shortcutsUrl }) } },
        icon('external', 12),
        t('nerdHelpShortcuts'),
      ),
    ),
  );

  // What nerd mode unlocks that has no switch of its own: the command line. Collapsed by
  // default; the first open decodes the text like the switch does.
  const helpBody = h(
    'div',
    { class: 'nerd-help__body' },
    h('p', { class: 'db-muted nerd-help__lead' }, h('span', { text: t('nerdHelpCmdLead') }), ' ', kbd(shortcutLabel('K')), ' ', h('span', { text: t('nerdHelpCmdLeadTail') })),
    h('dl', { class: 'nerd-help__cmds' }, ...commandHelp().flatMap((c) => [h('dt', { class: 'mono', text: c.usage }), h('dd', { text: t(c.desc) })])),
  );
  const help = h(
    'details',
    { class: 'nerd-help' },
    h('summary', { class: 'db-row nerd-help__summary' }, h('span', { class: 'db-row__label', text: t('nerdHelpTitle') }), icon('chevronRight', 14, 'nerd-help__chev')),
    helpBody,
  );
  // A double click on the summary would select the text it just revealed.
  help.querySelector('summary')?.addEventListener('mousedown', (ev) => {
    if (ev.detail > 1) ev.preventDefault();
  });
  help.addEventListener('toggle', () => {
    if (!(help as HTMLDetailsElement).open) return;
    const sel = getSelection();
    if (sel && !sel.isCollapsed && sel.anchorNode && help.contains(sel.anchorNode)) sel.removeAllRanges();
    // The decode is a one-time welcome; after that the help just opens.
    if (readFlag(HELP_SEEN)) return;
    writeFlag(HELP_SEEN);
    revealNerd(helpBody);
  });

  // Master switch: the sub-settings and the «Entwicklertools» (developer tools) navigation entry follow it live.
  const masterLabel = nextId('set');
  const masterDesc = nextId('set-d');
  const masterLocked = isLocked(cfg, 'nerd.enabled');
  const master = switchControl({
    checked: n.enabled,
    labelledBy: masterLabel,
    describedBy: masterDesc,
    disabled: masterLocked,
    onChange: async (v) => {
      const ok = await persist({ nerd: { enabled: v } });
      if (ok) sub.hidden = !v;
      // Easter egg: the unlocked settings decode in place.
      if (ok && v) revealNerd(sub);
      return ok;
    },
  });

  // Protected domains editor.
  const domLocked = isLocked(cfg, 'nerd.protectedDomains');
  const domLabel = nextId('set');
  const area = h('textarea', {
    class: 'input nerd-domains mono',
    attrs: { rows: 5, spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', 'aria-labelledby': domLabel, 'aria-describedby': `${domLabel}-hint`, placeholder: 'postfinance.ch\nubs.com', readonly: domLocked },
  });
  area.value = userDomains.join('\n');
  let saved = area.value;
  const status = h('span', { class: 'nerd-domains__status', attrs: { role: 'status' } });
  const saveBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button', disabled: true } }, icon('check', 14), t('actionApply'));
  area.addEventListener('input', () => {
    saveBtn.disabled = domLocked || area.value === saved;
    status.textContent = '';
  });
  saveBtn.addEventListener('click', async () => {
    const { domains, invalid } = parseProtectedDomains(area.value);
    saveBtn.disabled = true;
    const r = await saveSettings({ nerd: { protectedDomains: domains } });
    if (!r.ok || r.data.ignored.length) {
      saveBtn.disabled = false;
      const locked = r.ok && r.data.ignored.some((p) => isLocked(r.data.config, p));
      toast(locked ? t('lockedByPolicy') : t('errorSaveFailed'), icon(locked ? 'lock' : 'alert', 15));
      return;
    }
    const eff = r.data.config?.settings.nerd?.protectedDomains ?? domains;
    const mine = eff.filter((d) => !policyDomains.includes(d));
    area.value = mine.join('\n');
    saved = area.value;
    status.textContent = invalid.length ? t('nerdSettingsDomainsInvalid', invalid.slice(0, 5).join(', ')) : plural(mine.length, 'nerdSettingsDomainsSavedOne', 'nerdSettingsDomainsSaved');
    toast(t('saved'), icon('check', 15));
  });

  append(sub, [
    shortcuts,
    help,
    row('nerd.contextMenu', n.contextMenu, 'nerdSettingsContextMenu', 'nerdSettingsContextMenuDesc', (v) => ({ nerd: { contextMenu: v } })),
    row('nerd.filterHistory', n.filterHistory, 'nerdSettingsFilterHistory', 'nerdSettingsFilterHistoryDesc', (v) => ({ nerd: { filterHistory: v } })),
    row('nerd.fingerprintMeter', n.fingerprintMeter, 'nerdSettingsFpMeter', 'nerdSettingsFpMeterDesc', (v) => ({ nerd: { fingerprintMeter: v } })),
    row('nerd.lookalike', n.lookalike, 'nerdSettingsLookalike', 'nerdSettingsLookalikeDesc', (v) => ({ nerd: { lookalike: v } })),
    h(
      'div',
      { class: `nerd-domains__block${domLocked ? ' db-row--locked' : ''}` },
      h('div', { class: 'nerd-domains__head' }, h('div', { class: 'db-row__label', text: t('nerdSettingsDomains'), attrs: { id: domLabel } }), domLocked ? lockIcon() : null),
      h('p', { class: 'db-muted nerd-domains__hint', text: t('nerdSettingsDomainsHint'), attrs: { id: `${domLabel}-hint` } }),
      area,
      domLocked ? null : h('div', { class: 'nerd-domains__actions' }, saveBtn, status),
      policyDomains.length
        ? h(
            'div',
            { class: 'nerd-domains__policy' },
            h('div', { class: 'nerd-domains__policy-head' }, h('span', { text: t('nerdSettingsDomainsPolicy') }), lockBadge()),
            h('ul', { class: 'nerd-chips' }, ...policyDomains.map((d) => h('li', { class: 'nerd-chip mono', text: d }))),
          )
        : null,
    ),
  ]);

  return panel(
    { title: t('nerdSettingsTitle'), flush: true, class: 'nerd-panel' },
    settingRow({ label: t('nerdSettingsEnabled'), desc: t('nerdSettingsEnabledDesc'), control: master.el, locked: masterLocked, labelId: masterLabel, descId: masterDesc }),
    sub,
  );
}

/**
 * After backup:import (EffectiveConfig & { ignored }): adopt the new state,
 * say whether policy-locked settings were left as they are, then reload so
 * every view and the navigation show the restored configuration.
 */
async function afterRestore(reply: unknown, doneKey: string, partlyKey: string): Promise<void> {
  if (!adoptConfig(reply)) await getConfig(true);
  await getLists(true);
  const partly = ignoredPaths(reply).length > 0;
  toast(t(partly ? partlyKey : doneKey), icon(partly ? 'lock' : 'check', 15));
  // Leave the message on screen long enough to read before the page reloads.
  setTimeout(() => location.reload(), partly ? 2600 : 900);
}

export function settingsView(): View {
  return {
    async render(root) {
      const r = await getConfig();
      if (!r.ok) {
        mount(root, pageHead(t('setTitle'), t('setLead')), errorState(() => location.reload()));
        return;
      }
      const cfg: EffectiveConfig = r.data;
      const s = cfg.settings;

      const toggle = (path: string, value: boolean, labelKey: string, descKey: string, patch: (v: boolean) => Parameters<typeof persist>[0]): HTMLElement => {
        const labelId = nextId('set');
        const descId = nextId('set-d');
        const locked = isLocked(cfg, path);
        const sw = switchControl({ checked: value, labelledBy: labelId, describedBy: descId, disabled: locked, onChange: (v) => persist(patch(v)) });
        return settingRow({ label: t(labelKey), desc: t(descKey), control: sw.el, locked, labelId, descId });
      };

      // Default blocking mode.
      const modeLabel = nextId('set');
      const modeDesc = nextId('set-d');
      const modeLocked = isLocked(cfg, 'defaultMode');
      const mode = segmented<BlockingMode>({
        options: [
          { value: 'standard', label: t('modeStandard') },
          { value: 'aggressive', label: t('modeAggressive') },
        ],
        value: s.defaultMode,
        labelledBy: modeLabel,
        disabled: modeLocked,
        onChange: (v) => persist({ defaultMode: v }),
      });

      // Retention.
      const retLabel = nextId('set');
      const retDesc = nextId('set-d');
      const retLocked = isLocked(cfg, 'history.retentionDays');
      const days = RETENTION.includes(s.history.retentionDays) ? RETENTION : [...RETENTION, s.history.retentionDays].sort((a, b) => a - b);
      const ret = h(
        'select',
        { class: 'select', attrs: { 'aria-labelledby': retLabel, 'aria-describedby': retDesc, disabled: retLocked } },
        ...days.map((d) => h('option', { attrs: { value: String(d) }, text: d === 1 ? t('setDaysOne') : t('setDays', fmtNumber(d)) })),
      );
      ret.value = String(s.history.retentionDays);
      ret.addEventListener('change', async () => {
        const prev = s.history.retentionDays;
        const v = Number(ret.value);
        if (await persist({ history: { retentionDays: v } })) s.history.retentionDays = v;
        else ret.value = String(prev);
      });

      // Language: native names, so anyone can find their way back.
      const langLabel = nextId('set');
      const langLocked = isLocked(cfg, 'ui.language');
      const LANGS: [Settings['ui']['language'], string][] = [
        ['de', 'Deutsch'],
        ['en', 'English'],
        ['fr', 'Français'],
        ['it', 'Italiano'],
        ['auto', t('setLanguageAuto')],
      ];
      const lang = h('select', { class: 'select', attrs: { 'aria-labelledby': langLabel, disabled: langLocked, 'data-setting': 'ui.language' } }, ...LANGS.map(([v, label]) => h('option', { attrs: { value: v }, text: label })));
      lang.value = s.ui.language;
      lang.addEventListener('change', async () => {
        const prev = s.ui.language;
        const v = lang.value as Settings['ui']['language'];
        if (await persist({ ui: { language: v } })) {
          s.ui.language = v;
          // Every label on the page changes: reload in the new language.
          clearI18nCache();
          setTimeout(() => location.reload(), 300);
        } else {
          lang.value = prev;
        }
      });

      // Clear history.
      const clearBtn = h('button', { class: 'btn btn--secondary btn--sm', attrs: { type: 'button' } }, icon('trash', 14), t('actClearHistory'));
      clearBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({ title: t('actClearHistoryTitle'), body: t('actClearHistoryText'), confirmLabel: t('actClearHistory') });
        if (!ok) return;
        const res = await call<unknown>({ type: 'history:clear' });
        toast(res.ok ? t('actHistoryCleared') : t('errorSaveFailed'), icon(res.ok ? 'check' : 'alert', 15));
      });

      // Backup.
      const exportBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button' } }, icon('download', 15), t('setBackupExport'));
      exportBtn.addEventListener('click', async () => {
        const res = await call<unknown>({ type: 'backup:export' });
        const data = res.ok ? validateBackup((res.data as { data?: unknown })?.data ?? res.data) : null;
        if (!data) {
          toast(t('setBackupFailed'), icon('alert', 15));
          return;
        }
        const stamp = new Date().toISOString().slice(0, 10);
        downloadText(`bastion-shield-backup-${stamp}.json`, `${JSON.stringify(data, null, 2)}\n`, 'application/json');
      });
      const importLocked = !!cfg.managed.lockSettings;
      const importBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button', disabled: importLocked } }, icon('upload', 15), t('setBackupImport'));
      importBtn.addEventListener('click', async () => {
        const text = await pickTextFile('.json,application/json');
        if (text === null) return;
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = null;
        }
        const data = validateBackup(parsed);
        if (!data) {
          toast(t('setBackupInvalid'), icon('alert', 15));
          return;
        }
        const when = Date.parse(data.exportedAt);
        const ok = await confirmDialog({
          title: t('setBackupImportTitle'),
          body: Number.isFinite(when) ? t('setBackupImportTextDated', fmtDateTime(when)) : t('setBackupImportText'),
          confirmLabel: t('actionImport'),
        });
        if (!ok) return;
        const res = await call<unknown>({ type: 'backup:import', data });
        if (!res.ok) {
          toast(t('setBackupFailed'), icon('alert', 15));
          return;
        }
        await afterRestore(res.data, 'setBackupImported', 'setBackupImportedPartly');
      });

      // Reset.
      const resetBtn = h('button', { class: 'btn btn--secondary', attrs: { type: 'button', disabled: importLocked } }, icon('reload', 15), t('setResetAction'));
      resetBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({ title: t('setResetTitle'), body: t('setResetText'), confirmLabel: t('setResetConfirm') });
        if (!ok) return;
        // No dedicated reset message in the contract yet: importing a backup of
        // the documented defaults replaces settings, sites and custom filters.
        const data: BackupFile = { format: 'bastion-shield-backup', version: 1, exportedAt: new Date().toISOString(), settings: defaultSettings(), sites: {}, customFilters: '' };
        const res = await call<unknown>({ type: 'backup:import', data });
        if (!res.ok) {
          toast(t('errorSaveFailed'), icon('alert', 15));
          return;
        }
        await afterRestore(res.data, 'setResetDone', 'setResetDonePartly');
      });

      mount(root, 
        pageHead(t('setTitle'), t('setLead')),
        cfg.managed.lockSettings ? h('div', { class: 'db-gap' }, notice(t('privLockedTitle'), t('privLockedText'), 'info')) : null,
        panel(
          { title: t('setGroupBlocking'), flush: true },
          settingRow({ label: t('setMode'), desc: t('setModeDesc'), control: mode.el, locked: modeLocked, labelId: modeLabel, descId: modeDesc }),
        ),
        panel(
          { title: t('setGroupLanguage'), flush: true },
          settingRow({ label: t('setLanguage'), control: lang, locked: langLocked, labelId: langLabel }),
        ),
        panel(
          { title: t('setGroupDisplay'), flush: true },
          toggle('ui.badge', s.ui.badge, 'setBadge', 'setBadgeDesc', (v) => ({ ui: { badge: v } })),
          toggle('ui.incidentCta', s.ui.incidentCta, 'setIncidentCta', 'setIncidentCtaDesc', (v) => ({ ui: { incidentCta: v } })),
        ),
        panel(
          { title: t('setGroupActivity'), flush: true },
          toggle('ui.activityLog', s.ui.activityLog, 'setActivityLog', 'setActivityLogDesc', (v) => ({ ui: { activityLog: v } })),
          toggle('history.enabled', s.history.enabled, 'setHistory', 'setHistoryDesc', (v) => ({ history: { enabled: v } })),
          settingRow({ label: t('setRetention'), desc: t('setRetentionDesc'), control: ret, locked: retLocked, labelId: retLabel, descId: retDesc }),
          settingRow({ label: t('setClearHistory'), desc: t('setClearHistoryDesc'), control: clearBtn, labelId: nextId('set') }),
        ),
        nerdPanel(cfg),
        // File dialogs close the popup: backups are made in the dashboard tab.
        popupMode
          ? panel({ title: t('setGroupBackup'), flush: true }, settingRow({ label: t('setBackupInTab'), control: openTabButton('settings', t('panelOpenInTab')), labelId: nextId('set') }))
          : panel(
              { title: t('setGroupBackup') },
              h('p', { class: 'db-muted', text: t('setBackupDesc') }),
              h('div', { class: 'set-actions' }, exportBtn, importBtn),
            ),
        panel(
          { title: t('setGroupReset') },
          h('p', { class: 'db-muted', text: t('setResetDesc') }),
          h('div', { class: 'set-actions' }, resetBtn),
        ),
      );
    },
  };
}
