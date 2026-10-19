// Bastion Shield — dashboard «Einstellungen»: default blocking mode, toolbar
// badge, activity log, history and retention, backup export / import and
// reset to defaults. Backups are plain JSON files the user saves locally.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { BackupFile, BlockingMode, EffectiveConfig, Settings } from '../../../shared/types.ts';
import { downloadText, h, pickTextFile, toast } from '../../shared/dom.ts';
import { clearI18nCache, fmtDateTime, fmtNumber, t } from '../../shared/i18n.ts';
import { icon } from '../../shared/icons.ts';
import { call } from '../../shared/messaging.ts';
import { confirmDialog, notice, segmented, switchControl } from '../../shared/controls.ts';
import { errorState, nextId, openTabButton, pageHead, panel, popupMode, settingRow, type View, mount } from '../common.ts';
import { adoptConfig, getConfig, getLists, ignoredPaths, isLocked } from '../store.ts';
import { persist } from './privacy.ts';

const RETENTION = [1, 7, 30, 90, 180, 365];

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
    },
    ui: { badge: true, activityLog: true, incidentCta: true, language: 'de' },
    history: { enabled: true, retentionDays: 30 },
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
