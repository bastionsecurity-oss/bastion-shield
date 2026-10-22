// Bastion Shield — dashboard «Einstellungen» (DB28, DB29, DB42): general
// settings (blocking mode, language, badge, «Cyber-Vorfall?»), activity and
// history with «Verlauf löschen…» (D01), the nerd-mode group, backup export
// and restore with a file summary (D03), and «Alles zurücksetzen…» (D02,
// checkbox «Ich habe eine Sicherung» and a link that exports one). Backups
// are plain JSON files the user saves locally.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BackupFile, BlockingMode, EffectiveConfig, Settings } from '../../../shared/types.ts';
import { append, downloadText, h, pickNamedTextFile, replace, toast } from '../../shared/dom.ts';
import { clearI18nCache, fmtDateTime, fmtNumber, plural, resolveLanguage, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { call } from '../../shared/messaging.ts';
import { confirmDialog, segmented, switchControl } from '../../shared/controls.ts';
import { truncateMiddle } from '../../shared/text.ts';
import { errorState, lockedNote, nextId, openTabButton, pageHead, panel, popupMode, settingRow, type View, mount, withBusy } from '../common.ts';
import { adoptConfig, getConfig, getLists, ignoredPaths, isLocked, saveSettings } from '../store.ts';
import { lockNotice, persist, retryConfig, rowDesc } from './privacy.ts';
import { revealNerd } from '../nerd-reveal.ts';
import { shortcutLabel } from '../rail.ts';
import { commandHelp } from '../../popup/commands.ts';
import { backupSummary, defaultSettings, MAX_PROTECTED_DOMAINS, parseProtectedDomains, validateBackup } from '../settings-core.ts';

export { defaultSettings, parseProtectedDomains, validateBackup } from '../settings-core.ts';

const RETENTION = [1, 7, 30, 90, 180, 365];

/** Native language names, so anyone can find their way back. */
const LANG_NAMES: Record<'de' | 'en' | 'fr' | 'it', string> = { de: 'Deutsch', en: 'English', fr: 'Français', it: 'Italiano' };

/** localStorage, a per-device convenience only: the nerd help decoded once already. */
const HELP_SEEN = 'bs.nerdHelp.seen';

/** Policy domains shown as chips before «+38 weitere». */
const POLICY_CHIPS = 2;

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

/** «Ctrl K» with a non-breaking space (AGENTS.md «Copy»). */
function keyLabel(k: string): string {
  return shortcutLabel(k).replace('+', '\u00a0');
}

/** Ask the service worker for a backup and save it as a file. Resolves false when that failed. */
async function exportBackup(): Promise<boolean> {
  const res = await call<unknown>({ type: 'backup:export' });
  const data = res.ok ? validateBackup((res.data as { data?: unknown })?.data ?? res.data) : null;
  if (!data) {
    toast(t('setBackupFailed'), icon('alert', 15));
    return false;
  }
  const stamp = new Date().toISOString().slice(0, 10);
  downloadText(`bastion-shield-backup-${stamp}.json`, `${JSON.stringify(data, null, 2)}\n`, 'application/json');
  return true;
}

/**
 * «Nerd-Modus»: the master switch row; while it is on, an indented block with
 * the keyboard shortcuts, the command-line reference, the switches for the
 * extras and guards, and the protected-domain list. Policy domains are shown
 * read-only; the user's own list is the effective list minus the policy's.
 */
function nerdPanel(cfg: EffectiveConfig, signal: AbortSignal): HTMLElement {
  const n = cfg.settings.nerd ?? defaultSettings().nerd;
  const policyDomains = (cfg.managed.protectedDomains ?? []).map((d) => d.toLowerCase());
  const userDomains = n.protectedDomains.filter((d) => !policyDomains.includes(d));

  const sub = h('div', { class: 'nerd-sub', hidden: !n.enabled });

  const row = (path: string, value: boolean, labelKey: string, descKey: string, patch: (v: boolean) => Parameters<typeof persist>[0]): HTMLElement => {
    const labelId = nextId('set');
    const descId = nextId('set-d');
    const locked = isLocked(cfg, path);
    const sw = switchControl({ checked: value, labelledBy: labelId, describedBy: descId, disabled: locked, onChange: (v) => persist(patch(v)) });
    return settingRow({ label: t(labelKey), desc: rowDesc(descKey), control: sw.el, locked, labelId, descId });
  };

  // Keyboard shortcuts: none is suggested in the manifest (a suggested key that clashes with a
  // browser shortcut shows as set but does not fire), so the user sets them here in one click.
  const kbd = (k: string): HTMLElement => h('kbd', { class: 'set-kbd', attrs: { translate: 'no' }, text: k.replace(/\+/g, '\u00a0') });
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
  // Back from the shortcuts page: show what was set there (until the view is left).
  window.addEventListener('focus', () => void paintKeys(), { signal });
  const shortcutsUrl = /Edg\//.test(navigator.userAgent) ? 'edge://extensions/shortcuts' : 'chrome://extensions/shortcuts';
  const keysLabel = nextId('set');
  const keysDesc = nextId('set-d');
  const shortcuts = settingRow({
    label: t('nerdKeysTitle'),
    labelId: keysLabel,
    control: h(
      'button',
      { class: 'btn btn--outline btn--h', attrs: { type: 'button', 'aria-describedby': keysDesc }, on: { click: () => void chrome.tabs.create({ url: shortcutsUrl }) } },
      t('nerdHelpShortcuts'),
      icon('external', 12),
    ),
  });
  shortcuts.querySelector('.db-row__text')?.append(
    h('p', { class: 'db-row__desc nerd-keys__list', attrs: { id: keysDesc } }, `${t('nerdHelpKeyPopup')}: `, popupKey, ` - ${t('nerdHelpKeyBisect')}: `, bisectKey),
  );

  // What nerd mode unlocks that has no switch of its own: the command line. Collapsed by
  // default; the first open decodes the text like the switch does.
  const helpBody = h(
    'div',
    { class: 'nerd-help__body' },
    h('p', { class: 'db-muted nerd-help__lead' }, h('span', { text: t('nerdHelpCmdLead') }), ' ', kbd(keyLabel('K')), ' ', h('span', { text: t('nerdHelpCmdLeadTail') })),
    h('dl', { class: 'nerd-help__cmds' }, ...commandHelp().flatMap((c) => [h('dt', { class: 'mono', attrs: { translate: 'no' }, text: c.usage }), h('dd', { text: t(c.desc) })])),
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

  // Protected domains editor (counter from 80 % of the limit, error below the field).
  const domLocked = isLocked(cfg, 'nerd.protectedDomains');
  const domLabel = nextId('set');
  const statusId = `${domLabel}-status`;
  const area = h('textarea', {
    class: 'input nerd-domains mono',
    attrs: {
      rows: 6,
      spellcheck: 'false',
      autocapitalize: 'off',
      autocomplete: 'off',
      translate: 'no',
      'aria-labelledby': domLabel,
      'aria-describedby': `${domLabel}-hint ${statusId}`,
      placeholder: 'postfinance.ch\nubs.com',
      readonly: domLocked,
    },
  });
  area.value = userDomains.join('\n');
  let saved = area.value;
  const counter = h('span', { class: 'nerd-domains__count mono', attrs: { 'aria-live': 'polite' } });
  const status = h('p', { class: 'nerd-domains__status', attrs: { id: statusId, 'aria-live': 'polite' } });
  const saveBtn = h('button', { class: 'btn btn--primary btn--h', attrs: { type: 'button', disabled: true } }, t('nerdSettingsDomainsSave'));
  const paintCount = (): void => {
    const count = parseProtectedDomains(area.value).domains.length;
    counter.textContent = count > 0 ? t('nerdSettingsDomainsCount', [fmtNumber(count), fmtNumber(MAX_PROTECTED_DOMAINS)]) : '';
    counter.classList.toggle('nerd-domains__count--over', count > MAX_PROTECTED_DOMAINS);
  };
  paintCount();
  area.addEventListener('input', () => {
    saveBtn.disabled = domLocked || area.value === saved;
    replace(status);
    status.classList.remove('nerd-domains__status--error');
    paintCount();
  });
  saveBtn.addEventListener('click', () =>
    void withBusy(saveBtn, async () => {
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
      paintCount();
      const savedText = plural(mine.length, 'nerdSettingsDomainsSavedOne', 'nerdSettingsDomainsSaved');
      if (invalid.length) {
        const items = invalid.slice(0, 5).map((x) => t('nerdSettingsDomainsBadItem', [x.text, fmtNumber(x.line)])).join(', ');
        replace(status, icon('alert', 14), h('span', { text: t('nerdSettingsDomainsBad', [savedText, items]) }));
        status.classList.add('nerd-domains__status--error');
      } else {
        replace(status, h('span', { text: savedText }));
      }
      toast(t('saved'), icon('check', 15));
    }),
  );

  const chips = policyDomains.slice(0, POLICY_CHIPS).map((d) => h('li', { class: 'nerd-chip mono', attrs: { translate: 'no', title: d }, text: truncateMiddle(d, 28) }));
  const rest = policyDomains.length - POLICY_CHIPS;
  const moreChip = rest > 0 ? h('li', { class: 'nerd-chip nerd-chip--more' }, h('button', { class: 'nerd-chip__more', attrs: { type: 'button', 'aria-expanded': 'false' }, text: t('nerdSettingsDomainsMore', fmtNumber(rest)) })) : null;
  moreChip?.querySelector('button')?.addEventListener('click', (ev) => {
    const btn = ev.currentTarget as HTMLElement;
    btn.setAttribute('aria-expanded', 'true');
    moreChip.replaceWith(...policyDomains.slice(POLICY_CHIPS).map((d) => h('li', { class: 'nerd-chip mono', attrs: { translate: 'no', title: d }, text: truncateMiddle(d, 28) })));
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
      h('div', { class: 'nerd-domains__head' }, h('div', { class: 'db-row__label', text: t('nerdSettingsDomains'), attrs: { id: domLabel } }), counter),
      domLocked ? lockedNote(`${domLabel}-hint`) : h('p', { class: 'db-row__desc nerd-domains__hint', text: t('nerdSettingsDomainsHint'), attrs: { id: `${domLabel}-hint` } }),
      h('div', { class: 'nerd-domains__edit' }, area, domLocked ? null : saveBtn),
      status,
      policyDomains.length
        ? h('div', { class: 'nerd-domains__policy' }, icon('lock', 12), h('span', { text: t('nerdSettingsDomainsPolicy') }), h('ul', { class: 'nerd-chips' }, ...chips, moreChip))
        : null,
    ),
  ]);

  return panel(
    { title: t('nerdSettingsTitle'), flush: true, class: 'nerd-panel' },
    settingRow({ label: t('nerdSettingsEnabled'), desc: rowDesc('nerdSettingsEnabledDesc'), control: master.el, locked: masterLocked, labelId: masterLabel, descId: masterDesc }),
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
  // Ends the window listeners of this visit when the view is left.
  const alive = new AbortController();
  return {
    dispose() {
      alive.abort();
    },
    async render(root) {
      const r = await getConfig();
      if (!r.ok) {
        mount(root, pageHead(t('setTitle'), t('setLead')), errorState(retryConfig));
        return;
      }
      const cfg: EffectiveConfig = r.data;
      const s = cfg.settings;

      const toggle = (path: string, value: boolean, labelKey: string, descKey: string, patch: (v: boolean) => Parameters<typeof persist>[0]): HTMLElement => {
        const labelId = nextId('set');
        const descId = nextId('set-d');
        const locked = isLocked(cfg, path);
        const sw = switchControl({ checked: value, labelledBy: labelId, describedBy: descId, disabled: locked, onChange: (v) => persist(patch(v)) });
        return settingRow({ label: t(labelKey), desc: rowDesc(descKey), control: sw.el, locked, labelId, descId });
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
        { class: 'select set-select', attrs: { 'aria-labelledby': retLabel, 'aria-describedby': retDesc, disabled: retLocked } },
        ...days.map((d) => h('option', { attrs: { value: String(d) }, text: d === 1 ? t('setDaysOne') : t('setDays', fmtNumber(d)) })),
      );
      ret.value = String(s.history.retentionDays);
      ret.addEventListener('change', async () => {
        const prev = s.history.retentionDays;
        const v = Number(ret.value);
        if (await persist({ history: { retentionDays: v } })) s.history.retentionDays = v;
        else ret.value = String(prev);
      });

      // Language: native names, so anyone can find their way back; «Wie Browser» names the language it means.
      const langLabel = nextId('set');
      const langDesc = nextId('set-d');
      const langLocked = isLocked(cfg, 'ui.language');
      const LANGS: [Settings['ui']['language'], string][] = [
        ['auto', t('setLanguageAutoNamed', LANG_NAMES[resolveLanguage('auto')])],
        ['de', LANG_NAMES.de],
        ['en', LANG_NAMES.en],
        ['fr', LANG_NAMES.fr],
        ['it', LANG_NAMES.it],
      ];
      const lang = h(
        'select',
        { class: 'select set-select', attrs: { 'aria-labelledby': langLabel, 'aria-describedby': langDesc, disabled: langLocked, 'data-setting': 'ui.language' } },
        ...LANGS.map(([v, label]) => h('option', { attrs: { value: v }, text: label })),
      );
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

      // Clear history (D01): irreversible, so a danger dialog whose buttons name the outcome.
      const clearBtn = h('button', { class: 'btn btn--danger btn--h', attrs: { type: 'button' } }, icon('trash', 15), t('setClearHistoryAction'));
      clearBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({ title: t('setClearTitle'), body: t('setClearText'), confirmLabel: t('setClearConfirm'), cancelLabel: t('setClearKeep'), danger: true, icon: 'trash' });
        if (!ok) return;
        await withBusy(clearBtn, async () => {
          const res = await call<unknown>({ type: 'history:clear' });
          toast(res.ok ? t('actHistoryCleared') : t('errorSaveFailed'), icon(res.ok ? 'check' : 'alert', 15));
        });
      });

      // Backup.
      const importLocked = !!cfg.managed.lockSettings;
      const exportBtn = h('button', { class: 'btn btn--outline btn--h', attrs: { type: 'button' } }, icon('download', 15), t('setBackupExport'));
      exportBtn.addEventListener('click', () => void withBusy(exportBtn, exportBackup));
      const importBtn = h('button', { class: 'btn btn--outline btn--h', attrs: { type: 'button', disabled: importLocked } }, icon('upload', 15), t('setBackupImport'));
      importBtn.addEventListener('click', async () => {
        const file = await pickNamedTextFile('.json,application/json', 20 * 1024 * 1024);
        if (file === null) return;
        let parsed: unknown = null;
        if (!('tooLarge' in file)) {
          try {
            parsed = JSON.parse(file.text);
          } catch {
            parsed = null;
          }
        }
        const data = validateBackup(parsed);
        if (!data || 'tooLarge' in file) {
          toast(t('setBackupInvalid'), icon('alert', 15));
          return;
        }
        // D03: the file and what it holds, so the right one is restored.
        const sum = backupSummary(data);
        const meta = [
          sum.created !== null ? t('setBackupCreated', fmtDateTime(sum.created)) : null,
          plural(sum.sites, 'setBackupSitesOne', 'setBackupSites'),
          plural(sum.filters, 'setBackupFiltersOne', 'setBackupFilters'),
        ].filter((x): x is string => !!x);
        const ok = await confirmDialog({
          title: t('setBackupImportTitle'),
          body: t('setBackupImportText'),
          icon: 'upload',
          confirmLabel: t('setBackupConfirm'),
          content: h(
            'div',
            { class: 'set-file' },
            icon('filters', 16),
            h('div', { class: 'set-file__text' }, h('span', { class: 'set-file__name mono', attrs: { title: file.name, translate: 'no' }, text: truncateMiddle(file.name, 36) }), h('span', { class: 'set-file__meta', text: meta.join(' - ') })),
          ),
        });
        if (!ok) return;
        const res = await call<unknown>({ type: 'backup:import', data });
        if (!res.ok) {
          toast(t('setBackupFailed'), icon('alert', 15));
          return;
        }
        await afterRestore(res.data, 'setBackupImported', 'setBackupImportedPartly');
      });

      // Reset (D02): heavy, so the dialog needs «Ich habe eine Sicherung» ticked; its link exports one.
      const resetBtn = h('button', { class: 'btn btn--danger btn--h', attrs: { type: 'button', disabled: importLocked } }, t('setResetAction'));
      resetBtn.addEventListener('click', async () => {
        const exportLink = h('button', { class: 'btn btn--quiet dialog__link', attrs: { type: 'button' }, text: t('setBackupExport') });
        exportLink.addEventListener('click', () => void withBusy(exportLink, exportBackup));
        const ok = await confirmDialog({
          title: t('setResetTitle'),
          body: t('setResetText'),
          icon: 'reload',
          danger: true,
          confirmLabel: t('setResetConfirm'),
          check: { label: t('setResetCheck'), aside: exportLink },
        });
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

      const clearLabel = nextId('set');
      const clearDesc = nextId('set-d');
      clearBtn.setAttribute('aria-describedby', `${clearLabel} ${clearDesc}`);
      const general = panel(
        { title: t('setGroupGeneral'), flush: true },
        settingRow({ label: t('setMode'), desc: rowDesc('setModeDesc'), control: mode.el, locked: modeLocked, labelId: modeLabel, descId: modeDesc }),
        settingRow({ label: t('setLanguage'), desc: rowDesc('setLanguageDesc'), control: lang, locked: langLocked, labelId: langLabel, descId: langDesc }),
        toggle('ui.badge', s.ui.badge, 'setBadge', 'setBadgeDesc', (v) => ({ ui: { badge: v } })),
        toggle('ui.incidentCta', s.ui.incidentCta, 'setIncidentCta', 'setIncidentCtaDesc', (v) => ({ ui: { incidentCta: v } })),
      );
      const activity = panel(
        { title: t('setGroupActivity'), flush: true },
        toggle('ui.activityLog', s.ui.activityLog, 'setActivityLog', 'setActivityLogDesc', (v) => ({ ui: { activityLog: v } })),
        toggle('history.enabled', s.history.enabled, 'setHistory', 'setHistoryDesc', (v) => ({ history: { enabled: v } })),
        settingRow({ label: t('setRetention'), desc: rowDesc('setRetentionDesc'), control: ret, locked: retLocked, labelId: retLabel, descId: retDesc }),
        settingRow({ label: t('setClearHistory'), desc: rowDesc('setClearHistoryDesc'), control: clearBtn, labelId: clearLabel, descId: clearDesc }),
      );
      const lockPaths = ['defaultMode', 'ui.language', 'ui.badge', 'ui.incidentCta', 'ui.activityLog', 'history.enabled', 'history.retentionDays', 'nerd.enabled'];

      // Expanded popup (DB42): the everyday settings; backup, reset and nerd mode live in the tab
      // (file dialogs close the popup).
      if (popupMode) {
        mount(
          root,
          pageHead(t('setTitle')),
          lockNotice(cfg, lockPaths),
          general,
          activity,
          panel({ title: t('setGroupBackup'), flush: true }, settingRow({ label: t('setGroupBackup'), desc: t('setBackupInTab'), control: openTabButton('settings', t('panelOpenInTab')), labelId: nextId('set'), descId: nextId('set-d') })),
        );
        return;
      }
      const backupLabel = nextId('set');
      const resetLabel = nextId('set');
      mount(
        root,
        pageHead(t('setTitle'), t('setLead')),
        lockNotice(cfg, lockPaths),
        general,
        activity,
        nerdPanel(cfg, alive.signal),
        panel(
          { title: t('setGroupBackup'), flush: true },
          settingRow({ label: t('setBackupRow'), desc: rowDesc('setBackupDesc'), control: h('div', { class: 'set-actions' }, exportBtn, importBtn), labelId: backupLabel, descId: nextId('set-d'), locked: false }),
        ),
        panel(
          { title: t('setGroupReset'), flush: true },
          settingRow({ label: t('setResetRow'), desc: rowDesc('setResetDesc'), control: resetBtn, labelId: resetLabel, descId: nextId('set-d'), locked: importLocked }),
        ),
      );
    },
  };
}
