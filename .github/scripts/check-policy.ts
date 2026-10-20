// Validates the admin-facing policy artefacts so a broken schema or example
// never reaches a customer: policy/managed_schema.json against Chromium's
// managed-storage schema rules (an invalid schema stops the extension from
// loading), the schema against ManagedPolicy in src/shared/types.ts, and the
// .reg / .json / .mobileconfig / .ps1 examples against the schema.
// Run: node .github/scripts/check-policy.ts   (exit code 1 on any error)
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';

const ROOT = join(import.meta.dirname, '..', '..');
const errors: string[] = [];
const warnings: string[] = [];
const err = (where: string, msg: string): void => {
  errors.push(`${where}: ${msg}`);
};
const warn = (where: string, msg: string): void => {
  warnings.push(`${where}: ${msg}`);
};

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type JsonObject = { [k: string]: Json };
const isObj = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);

// ---------------------------------------------------------------------------
// 1. Chromium schema rules (components/policy/core/common/schema.cc)
// ---------------------------------------------------------------------------

// Attribute -> expected JSON type, per schema type. Mirrors the
// kAttributesAndTypesFor* tables. Chromium ignores unknown attributes when it
// parses an extension schema, but we reject them so the file stays within the
// documented subset.
const ATTRS: Record<string, Record<string, string>> = {
  array: { description: 'string', id: 'string', items: 'object', sensitiveValue: 'boolean', title: 'string', type: 'string' },
  boolean: { description: 'string', id: 'string', sensitiveValue: 'boolean', title: 'string', type: 'string' },
  integer: { description: 'string', enum: 'array', id: 'string', maximum: 'number', minimum: 'number', sensitiveValue: 'boolean', title: 'string', type: 'string' },
  number: { description: 'string', id: 'string', sensitiveValue: 'boolean', title: 'string', type: 'string' },
  object: { additionalProperties: 'object', description: 'string', id: 'string', patternProperties: 'object', properties: 'object', required: 'array', sensitiveValue: 'boolean', title: 'string', type: 'string' },
  string: { description: 'string', enum: 'array', id: 'string', pattern: 'string', sensitiveValue: 'boolean', title: 'string', type: 'string' },
};
const REF_ATTRS: Record<string, string> = { description: 'string', $ref: 'string', title: 'string' };

function jsonType(v: unknown): string {
  if (Array.isArray(v)) return 'array';
  if (v === null) return 'null';
  return typeof v;
}

function checkSchemaNode(node: unknown, path: string): void {
  if (!isObj(node)) {
    err(path, 'schema node must be an object');
    return;
  }
  if ('$ref' in node) {
    for (const [k, v] of Object.entries(node)) {
      if (!(k in REF_ATTRS)) err(path, `unsupported attribute "${k}" next to $ref`);
      else if (jsonType(v) !== REF_ATTRS[k]) err(path, `attribute "${k}" must be ${REF_ATTRS[k]}`);
    }
    return;
  }
  const type = node.type;
  if (typeof type !== 'string') {
    err(path, 'every schema needs a string "type" (or "$ref")');
    return;
  }
  const allowed = ATTRS[type];
  if (!allowed) {
    err(path, `unknown type "${type}"`);
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    if (!(k in allowed)) {
      err(path, `attribute "${k}" is not supported for type ${type}`);
      continue;
    }
    if (jsonType(v) !== allowed[k]) err(path, `attribute "${k}" must be of JSON type ${allowed[k]}`);
  }
  // Chromium applies only one restriction per node (enum, else pattern, else
  // range), so combining them silently drops all but the first.
  const restrictions = ['enum', 'pattern', 'minimum', 'maximum'].filter((k) => k in node);
  if (restrictions.includes('enum') && restrictions.length > 1) err(path, 'enum cannot be combined with pattern/minimum/maximum');
  if (restrictions.includes('pattern') && (restrictions.includes('minimum') || restrictions.includes('maximum'))) {
    err(path, 'pattern cannot be combined with minimum/maximum');
  }
  if ('enum' in node) {
    const values = node.enum;
    if (!Array.isArray(values) || values.length === 0) err(path, 'enum must be a non-empty list');
    else {
      const want = type === 'integer' ? 'number' : 'string';
      for (const item of values) {
        if (jsonType(item) !== want || (type === 'integer' && !Number.isInteger(item))) err(path, `enum item ${JSON.stringify(item)} must be ${type}`);
      }
      if (new Set(values.map((x) => JSON.stringify(x))).size !== values.length) err(path, 'enum has duplicate values');
    }
  }
  if (type === 'integer') {
    // ParseRangedInt reads the bounds with FindInt: fractional bounds are ignored.
    for (const k of ['minimum', 'maximum']) {
      if (k in node && !Number.isInteger(node[k])) err(path, `${k} must be an integer`);
    }
    if (typeof node.minimum === 'number' && typeof node.maximum === 'number' && node.minimum > node.maximum) {
      err(path, 'minimum is greater than maximum');
    }
  }
  if (type === 'string' && typeof node.pattern === 'string') {
    try {
      new RegExp(node.pattern);
    } catch (e) {
      err(path, `pattern does not compile: ${(e as Error).message}`);
    }
  }
  if (type === 'array') {
    if (!isObj(node.items)) err(path, 'type array needs an "items" schema object');
    else checkSchemaNode(node.items, `${path}.items`);
  }
  if (type === 'object') {
    if (isObj(node.properties)) {
      for (const [k, v] of Object.entries(node.properties)) checkSchemaNode(v, `${path}.properties.${k}`);
    }
    if (isObj(node.patternProperties)) {
      for (const [k, v] of Object.entries(node.patternProperties)) {
        try {
          new RegExp(k);
        } catch (e) {
          err(path, `patternProperties key /${k}/ does not compile: ${(e as Error).message}`);
        }
        checkSchemaNode(v, `${path}.patternProperties[${k}]`);
      }
    }
    if ('additionalProperties' in node) checkSchemaNode(node.additionalProperties, `${path}.additionalProperties`);
    if (Array.isArray(node.required)) {
      for (const r of node.required) {
        if (typeof r !== 'string' || !isObj(node.properties) || !(r in node.properties)) err(path, `required entry ${JSON.stringify(r)} is not a declared property`);
      }
    }
  }
}

function checkTopLevel(schema: unknown, where: string): void {
  if (!isObj(schema)) {
    err(where, 'top level must be a JSON object');
    return;
  }
  if (schema.type !== 'object') err(where, 'top-level "type" must be "object"');
  if ('additionalProperties' in schema || 'patternProperties' in schema) {
    err(where, 'additionalProperties / patternProperties are not allowed at the top level');
  }
  checkSchemaNode(schema, where);
}

// ---------------------------------------------------------------------------
// 2. Schema vs ManagedPolicy (src/shared/types.ts)
// ---------------------------------------------------------------------------

type Expect =
  | { kind: 'string' | 'boolean' | 'integer' }
  | { kind: 'enum'; values: string[] }
  | { kind: 'string[]' }
  | { kind: 'map-boolean' };

function parseStringUnion(text: string): string[] | null {
  const parts = text.split('|').map((s) => s.trim());
  const out: string[] = [];
  for (const p of parts) {
    const m = /^'([^']*)'$/.exec(p);
    if (!m) return null;
    out.push(m[1]);
  }
  return out;
}

function managedPolicyFromTypes(): Map<string, Expect> {
  const src = readFileSync(join(ROOT, 'src', 'shared', 'types.ts'), 'utf8');
  const aliases = new Map<string, string[]>();
  for (const m of src.matchAll(/export type (\w+)\s*=\s*([^;]+);/g)) {
    const values = parseStringUnion(m[2].replace(/\s+/g, ' '));
    if (values) aliases.set(m[1], values);
  }
  const body = /export interface ManagedPolicy \{([\s\S]*?)\n\}/.exec(src);
  const out = new Map<string, Expect>();
  if (!body) {
    err('src/shared/types.ts', 'interface ManagedPolicy not found');
    return out;
  }
  const noComments = body[1].replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const m of noComments.matchAll(/^\s*(\w+)\?\s*:\s*([^;]+);/gm)) {
    const [, name, rawType] = m;
    const t = rawType.trim();
    let e: Expect | null = null;
    if (t === 'string' || t === 'boolean') e = { kind: t };
    else if (t === 'number') e = { kind: 'integer' };
    else if (t === 'string[]') e = { kind: 'string[]' };
    else if (/^Record<string,\s*boolean>$/.test(t)) e = { kind: 'map-boolean' };
    else if (aliases.has(t)) e = { kind: 'enum', values: aliases.get(t)! };
    else {
      const lit = parseStringUnion(t);
      if (lit) e = { kind: 'enum', values: lit };
    }
    if (!e) err('src/shared/types.ts', `ManagedPolicy.${name}: type "${t}" is not mapped by check-policy.ts`);
    else out.set(name, e);
  }
  return out;
}

function compareSchemaToTypes(schema: JsonObject, expected: Map<string, Expect>): void {
  const where = 'policy/managed_schema.json';
  const props = isObj(schema.properties) ? schema.properties : {};
  for (const name of Object.keys(props)) {
    if (!expected.has(name)) err(where, `property "${name}" does not exist in ManagedPolicy`);
  }
  for (const [name, e] of expected) {
    const node = props[name];
    if (!isObj(node)) {
      err(where, `ManagedPolicy.${name} is missing from the schema`);
      continue;
    }
    const at = `${where} ${name}`;
    switch (e.kind) {
      case 'string':
      case 'boolean':
      case 'integer':
        if (node.type !== e.kind) err(at, `type must be "${e.kind}"`);
        if (e.kind === 'string' && 'enum' in node) err(at, 'unexpected enum for a free-form string');
        break;
      case 'enum': {
        if (node.type !== 'string') err(at, 'type must be "string"');
        const got = Array.isArray(node.enum) ? node.enum.map(String).sort() : [];
        const want = [...e.values].sort();
        if (JSON.stringify(got) !== JSON.stringify(want)) err(at, `enum must be ${JSON.stringify(want)}, found ${JSON.stringify(got)}`);
        break;
      }
      case 'string[]':
        if (node.type !== 'array' || !isObj(node.items) || node.items.type !== 'string') err(at, 'must be an array of strings');
        break;
      case 'map-boolean':
        if (node.type !== 'object' || !isObj(node.additionalProperties) || node.additionalProperties.type !== 'boolean') {
          err(at, 'must be an object with additionalProperties {type: boolean}');
        }
        break;
    }
  }
}

// ---------------------------------------------------------------------------
// 3. Value validation (examples)
// ---------------------------------------------------------------------------

function validateValue(value: unknown, node: JsonObject, at: string): void {
  switch (node.type) {
    case 'boolean':
      if (typeof value !== 'boolean') err(at, 'must be true or false');
      return;
    case 'integer':
      if (typeof value !== 'number' || !Number.isInteger(value)) err(at, 'must be an integer');
      else {
        if (typeof node.minimum === 'number' && value < node.minimum) err(at, `must be >= ${node.minimum}`);
        if (typeof node.maximum === 'number' && value > node.maximum) err(at, `must be <= ${node.maximum}`);
      }
      return;
    case 'string':
      if (typeof value !== 'string') err(at, 'must be a string');
      else if (Array.isArray(node.enum) && !node.enum.includes(value)) err(at, `must be one of ${JSON.stringify(node.enum)}`);
      return;
    case 'array':
      if (!Array.isArray(value)) err(at, 'must be an array');
      else value.forEach((v, i) => validateValue(v, node.items as JsonObject, `${at}[${i}]`));
      return;
    case 'object': {
      if (!isObj(value)) {
        err(at, 'must be an object');
        return;
      }
      const props = isObj(node.properties) ? node.properties : {};
      for (const [k, v] of Object.entries(value)) {
        if (isObj(props[k])) validateValue(v, props[k] as JsonObject, `${at}.${k}`);
        else if (isObj(node.additionalProperties)) validateValue(v, node.additionalProperties, `${at}.${k}`);
        else err(at, `unknown key "${k}" (Chromium drops it)`);
      }
      return;
    }
  }
}

const EXT_ID = /^[a-p]{32}$/;
const CHROME_PLACEHOLDER = '<CHROME_WEB_STORE_ID>';
const EDGE_PLACEHOLDER = '<EDGE_ADDONS_ID>';
const isIdOrPlaceholder = (s: string): boolean => EXT_ID.test(s) || s === CHROME_PLACEHOLDER || s === EDGE_PLACEHOLDER;

function checkHostList(list: unknown, at: string): void {
  if (!Array.isArray(list)) return;
  list.forEach((h, i) => {
    if (typeof h !== 'string' || !/^[a-z0-9.-]+$/.test(h) || h.startsWith('.') || h.endsWith('.')) {
      err(`${at}[${i}]`, `${JSON.stringify(h)} is not a plain lower-case hostname (no scheme, path, port or wildcard)`);
    }
  });
}

function checkPolicyObject(policy: unknown, schema: JsonObject, at: string): void {
  validateValue(policy, schema, at);
  if (isObj(policy)) {
    checkHostList(policy.disabledSites, `${at}.disabledSites`);
    checkHostList(policy.aggressiveSites, `${at}.aggressiveSites`);
    if (isObj(policy.lists)) {
      for (const id of Object.keys(policy.lists)) if (!/^[a-z0-9-]+$/.test(id)) err(`${at}.lists`, `list id "${id}" is not [a-z0-9-]+`);
      const catalog = JSON.parse(readFileSync(join(ROOT, 'filters', 'catalog.json'), 'utf8')) as { lists: { id: string }[] };
      const known = new Set(catalog.lists.map((l) => l.id));
      for (const id of Object.keys(policy.lists)) if (!known.has(id)) err(`${at}.lists`, `list id "${id}" is not in filters/catalog.json`);
    }
  }
}

// ---------------------------------------------------------------------------
// 4. .reg files
// ---------------------------------------------------------------------------

type RegValue = { kind: 'sz'; value: string } | { kind: 'dword'; value: number } | { kind: 'delete' };
interface RegKey {
  path: string;
  values: Map<string, RegValue>;
}

function parseRegString(raw: string, at: string): string {
  // raw is the text between the outer quotes; only \\ and \" are escapes.
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === '\\') {
      const n = raw[i + 1];
      if (n === '\\' || n === '"') {
        out += n;
        i++;
        continue;
      }
      err(at, `invalid escape "\\${n ?? ''}" in string value`);
      continue;
    }
    if (c === '"') err(at, 'unescaped quote inside string value');
    out += c;
  }
  return out;
}

function parseReg(file: string): RegKey[] {
  const text = readFileSync(file, 'utf8');
  const where = `policy/examples/${basename(file)}`;
  if (/[^\x09\x0a\x0d\x20-\x7e]/.test(text)) err(where, 'contains non-ASCII characters; regedit expects ASCII or UTF-16');
  if (!/\r\n/.test(text) || /[^\r]\n/.test(text)) warn(where, 'use CRLF line endings for .reg files');
  const lines = text.split(/\r?\n/);
  if (lines[0] !== 'Windows Registry Editor Version 5.00') err(where, 'first line must be "Windows Registry Editor Version 5.00"');
  const keys: RegKey[] = [];
  let cur: RegKey | null = null;
  lines.slice(1).forEach((line, idx) => {
    const at = `${where}:${idx + 2}`;
    if (line.trim() === '' || line.startsWith(';')) return;
    const sec = /^\[(-?)(HKEY_[^\]]+)\]$/.exec(line);
    if (sec) {
      cur = { path: sec[2], values: new Map() };
      if (sec[1] !== '-') keys.push(cur);
      else cur = null;
      return;
    }
    if (!cur) {
      err(at, 'value outside of a key section');
      return;
    }
    const sz = /^"([^"\\]+)"="(.*)"$/.exec(line);
    const dw = /^"([^"\\]+)"=dword:([0-9a-fA-F]{8})$/.exec(line);
    const del = /^"([^"\\]+)"=-$/.exec(line);
    const key: RegKey = cur;
    if (sz) key.values.set(sz[1], { kind: 'sz', value: parseRegString(sz[2], at) });
    else if (dw) key.values.set(dw[1], { kind: 'dword', value: parseInt(dw[2], 16) });
    else if (del) key.values.set(del[1], { kind: 'delete' });
    else err(at, `cannot parse line: ${line}`);
  });
  return keys;
}

const POLICY_ROOTS: Record<string, string> = {
  chrome: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome',
  edge: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge',
  brave: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\BraveSoftware\\Brave',
};
const STORE_URL: Record<string, string> = {
  chrome: 'https://clients2.google.com/service/update2/crx',
  brave: 'https://clients2.google.com/service/update2/crx',
  edge: 'https://edge.microsoft.com/extensionwebstorebase/v1/crx',
};

function checkExtensionSettings(json: string, browser: string, at: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    err(at, `ExtensionSettings is not valid JSON: ${(e as Error).message}`);
    return;
  }
  if (!isObj(parsed)) {
    err(at, 'ExtensionSettings must be a JSON object');
    return;
  }
  const toolbarKey = browser === 'edge' ? 'toolbar_state' : 'toolbar_pin';
  const wrongToolbarKey = browser === 'edge' ? 'toolbar_pin' : 'toolbar_state';
  const toolbarValues = browser === 'edge' ? ['force_shown', 'default_shown', 'default_hidden'] : ['force_pinned', 'default_pinned', 'default_unpinned'];
  for (const [id, cfg] of Object.entries(parsed)) {
    if (id === '*') continue;
    if (!isIdOrPlaceholder(id)) err(at, `"${id}" is neither a 32-letter extension id nor a documented placeholder`);
    if (!isObj(cfg)) {
      err(at, `entry ${id} must be an object`);
      continue;
    }
    if (browser === 'edge' && id === CHROME_PLACEHOLDER) err(at, 'Edge must use <EDGE_ADDONS_ID>, not the Chrome Web Store id');
    if (browser !== 'edge' && id === EDGE_PLACEHOLDER) err(at, `${browser} must use <CHROME_WEB_STORE_ID>`);
    if (cfg.installation_mode !== 'force_installed') warn(at, `${id}: installation_mode is ${String(cfg.installation_mode)}, examples should force-install`);
    if (cfg.update_url !== STORE_URL[browser]) err(at, `${id}: update_url must be ${STORE_URL[browser]} for a store-hosted install`);
    if (wrongToolbarKey in cfg) err(at, `${id}: "${wrongToolbarKey}" is not valid for ${browser} (use "${toolbarKey}")`);
    if (toolbarKey in cfg && !toolbarValues.includes(String(cfg[toolbarKey]))) {
      // Chrome rejects the whole ExtensionSettings policy for an out-of-enum toolbar_pin.
      err(at, `${id}: ${toolbarKey} must be one of ${toolbarValues.join(', ')}`);
    }
  }
}

function regToPolicy(key: RegKey, subkeys: RegKey[], schema: JsonObject, at: string): JsonObject {
  const props = schema.properties as JsonObject;
  const lowerToName = new Map(Object.keys(props).map((k) => [k.toLowerCase(), k]));
  const out: JsonObject = {};
  for (const [rawName, v] of key.values) {
    const name = lowerToName.get(rawName.toLowerCase());
    if (!name) {
      err(at, `value "${rawName}" is not a policy key`);
      continue;
    }
    if (name !== rawName) warn(at, `value "${rawName}" should be spelled "${name}"`);
    const node = props[name] as JsonObject;
    if (v.kind === 'delete') continue;
    if (node.type === 'boolean') {
      if (v.kind !== 'dword') err(at, `${name} must be a dword (0 or 1)`);
      else if (v.value > 1) err(at, `${name} should be dword:00000000 or dword:00000001`);
      else out[name] = v.value === 1;
    } else if (node.type === 'integer') {
      if (v.kind !== 'dword') err(at, `${name} must be a dword`);
      else out[name] = v.value;
    } else if (node.type === 'string') {
      if (v.kind !== 'sz') err(at, `${name} must be a string (REG_SZ)`);
      else out[name] = v.value;
    } else if (v.kind !== 'sz') {
      err(at, `${name} must be a REG_SZ JSON string or a sub-key`);
    } else {
      try {
        out[name] = JSON.parse(v.value) as Json;
      } catch (e) {
        err(at, `${name} is not valid JSON: ${(e as Error).message}`);
      }
    }
  }
  for (const sub of subkeys) {
    const rawName = sub.path.slice(key.path.length + 1);
    const name = lowerToName.get(rawName.toLowerCase());
    if (!name || rawName.includes('\\')) {
      err(at, `sub-key "${rawName}" is not a policy key`);
      continue;
    }
    if (name in out) err(at, `${name} is set both as a value and as a sub-key`);
    const node = props[name] as JsonObject;
    if (node.type === 'array') {
      const items: Json[] = [];
      for (const [n, v] of sub.values) {
        if (!/^\d+$/.test(n)) err(at, `${name}\\${n}: list entries must be named 1, 2, 3, ...`);
        else if (v.kind !== 'sz') err(at, `${name}\\${n}: must be REG_SZ`);
        else items.push(v.value);
      }
      out[name] = items;
    } else if (node.type === 'object') {
      const obj: JsonObject = {};
      for (const [n, v] of sub.values) {
        if (v.kind !== 'dword' || v.value > 1) err(at, `${name}\\${n}: must be dword 0 or 1`);
        else obj[n] = v.value === 1;
      }
      out[name] = obj;
    } else err(at, `${name} cannot be a sub-key`);
  }
  return out;
}

function checkRegFile(file: string, schema: JsonObject): void {
  const name = basename(file);
  const where = `policy/examples/${name}`;
  const keys = parseReg(file);
  const browser = (['chrome', 'edge', 'brave'] as const).find((b) => name.includes(b));
  if (!browser) {
    err(where, 'file name must contain chrome, edge or brave');
    return;
  }
  const root = POLICY_ROOTS[browser];
  for (const k of keys) {
    if (!k.path.startsWith(root)) err(where, `key ${k.path} is outside ${root}`);
    const m = /\\3rdparty\\extensions\\([^\\]+)\\policy$/.exec(k.path);
    if (m) {
      if (!isIdOrPlaceholder(m[1])) err(where, `extension id "${m[1]}" is neither an id nor a placeholder`);
      if (browser === 'edge' && m[1] === CHROME_PLACEHOLDER) err(where, 'Edge policy must be keyed by <EDGE_ADDONS_ID>');
      if (browser !== 'edge' && m[1] === EDGE_PLACEHOLDER) err(where, `${browser} policy must be keyed by <CHROME_WEB_STORE_ID>`);
      const subs = keys.filter((s) => s.path.startsWith(k.path + '\\'));
      const policy = regToPolicy(k, subs, schema, `${where} [${k.path}]`);
      checkPolicyObject(policy, schema, `${where} policy`);
    }
    const es = k.values.get('ExtensionSettings');
    if (es && es.kind === 'sz') checkExtensionSettings(es.value, browser, `${where} ExtensionSettings`);
    else if (es) err(where, 'ExtensionSettings must be REG_SZ');
  }
}

// ---------------------------------------------------------------------------
// 5. Minimal plist parser for the .mobileconfig examples
// ---------------------------------------------------------------------------

function decodeXml(s: string): string {
  return s.replace(/&(lt|gt|amp|quot|apos);/g, (_, e: string) => ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" })[e] as string);
}

function parsePlist(text: string, where: string): Json {
  const body = text.replace(/<\?xml[^>]*\?>/, '').replace(/<!DOCTYPE[^>]*>/, '').replace(/<!--[\s\S]*?-->/g, '');
  const tokens = body.match(/<[^>]+>|[^<]+/g) ?? [];
  let i = 0;
  const next = (): string => {
    while (i < tokens.length && tokens[i].trim() === '') i++;
    return tokens[i++] ?? '';
  };
  const textUntil = (close: string): string => {
    let s = '';
    while (i < tokens.length && tokens[i] !== close) s += tokens[i++];
    if (tokens[i++] !== close) throw new Error(`missing ${close}`);
    return decodeXml(s);
  };
  const value = (tag: string): Json => {
    switch (tag) {
      case '<dict>': {
        const out: JsonObject = {};
        for (;;) {
          const t = next();
          if (t === '</dict>') return out;
          if (t !== '<key>') throw new Error(`expected <key>, got ${t}`);
          const k = textUntil('</key>');
          if (k in out) throw new Error(`duplicate key ${k}`);
          out[k] = value(next());
        }
      }
      case '<dict/>':
        return {};
      case '<array>': {
        const out: Json[] = [];
        for (;;) {
          const t = next();
          if (t === '</array>') return out;
          out.push(value(t));
        }
      }
      case '<array/>':
        return [];
      case '<string>':
        return textUntil('</string>');
      case '<string/>':
        return '';
      case '<integer>': {
        const s = textUntil('</integer>').trim();
        if (!/^-?\d+$/.test(s)) throw new Error(`bad integer ${s}`);
        return Number(s);
      }
      case '<true/>':
        return true;
      case '<false/>':
        return false;
      default:
        throw new Error(`unsupported plist element ${tag}`);
    }
  };
  try {
    if (next() !== '<plist version="1.0">') throw new Error('expected <plist version="1.0">');
    const root = value(next());
    if (next() !== '</plist>') throw new Error('expected </plist>');
    return root;
  } catch (e) {
    err(where, `plist parse error: ${(e as Error).message}`);
    return null;
  }
}

function checkMobileconfig(file: string, schema: JsonObject): void {
  const name = basename(file);
  const where = `policy/examples/${name}`;
  const text = readFileSync(file, 'utf8');
  const root = parsePlist(text, where);
  if (!isObj(root)) return;
  const browser = name.includes('Chrome') ? 'chrome' : name.includes('Edge') ? 'edge' : name.includes('Brave') ? 'brave' : null;
  const domain = browser === 'chrome' ? 'com.google.Chrome' : browser === 'edge' ? 'com.microsoft.Edge' : 'com.brave.Browser';
  const placeholder = browser === 'edge' ? 'EDGE_ADDONS_ID' : 'CHROME_WEB_STORE_ID';
  if (!browser) {
    err(where, 'file name must name the browser');
    return;
  }
  for (const k of ['PayloadType', 'PayloadIdentifier', 'PayloadUUID', 'PayloadVersion', 'PayloadDisplayName', 'PayloadContent']) {
    if (!(k in root)) err(where, `top-level ${k} missing`);
  }
  if (root.PayloadType !== 'Configuration') err(where, 'top-level PayloadType must be "Configuration"');
  const uuids = new Set<string>();
  const uuid = (u: Json, at: string): void => {
    if (typeof u !== 'string' || !/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(u)) err(at, 'PayloadUUID must be an upper-case UUID');
    else if (uuids.has(u)) err(at, 'PayloadUUID is not unique');
    else uuids.add(u);
  };
  uuid(root.PayloadUUID, where);
  const payloads = Array.isArray(root.PayloadContent) ? root.PayloadContent : [];
  let sawBrowser = false;
  let sawExtension = false;
  for (const p of payloads) {
    if (!isObj(p)) continue;
    const type = String(p.PayloadType);
    const at = `${where} payload ${type}`;
    uuid(p.PayloadUUID, at);
    for (const k of ['PayloadIdentifier', 'PayloadVersion']) if (!(k in p)) err(at, `${k} missing`);
    const prefs: JsonObject = {};
    for (const [k, v] of Object.entries(p)) if (!k.startsWith('Payload')) prefs[k] = v;
    if (type === domain) {
      sawBrowser = true;
      if (!isObj(prefs.ExtensionSettings)) err(at, 'ExtensionSettings dict missing');
      else checkExtensionSettings(JSON.stringify(prefs.ExtensionSettings).replaceAll(placeholder, placeholder === 'EDGE_ADDONS_ID' ? EDGE_PLACEHOLDER : CHROME_PLACEHOLDER), browser, `${at} ExtensionSettings`);
    } else if (type === `${domain}.extensions.${placeholder}`) {
      sawExtension = true;
      checkPolicyObject(prefs, schema, `${at}`);
    } else err(at, `unexpected PayloadType (expected ${domain} or ${domain}.extensions.${placeholder})`);
  }
  if (!sawBrowser) err(where, `no ${domain} payload`);
  if (!sawExtension) err(where, `no ${domain}.extensions.${placeholder} payload`);
}

// ---------------------------------------------------------------------------
// 6. PowerShell scripts
// ---------------------------------------------------------------------------

function checkPowerShell(dir: string, schema: JsonObject): void {
  const setPath = join(dir, 'Set-BastionShieldPolicy.ps1');
  const detPath = join(dir, 'Detect-BastionShieldPolicy.ps1');
  const set = readFileSync(setPath, 'utf8');
  const det = readFileSync(detPath, 'utf8');
  for (const [p, t] of [
    [setPath, set],
    [detPath, det],
  ] as const) {
    // Windows PowerShell 5.1 reads BOM-less files as ANSI; keep them ASCII.
    if (/[^\x09\x0a\x0d\x20-\x7e]/.test(t)) err(basename(p), 'contains non-ASCII characters (Windows PowerShell 5.1 would misread them)');
    if (!t.includes('SPDX-License-Identifier: GPL-3.0-or-later')) err(basename(p), 'SPDX header missing');
  }
  // The detection script must be the apply script with only the default mode changed.
  const norm = (t: string): string =>
    t
      .replace(/\r\n/g, '\n')
      .replace(/^\s*\[string\]\$Mode = '(Apply|Detect)'.*$/m, '<MODE>')
      .replace(/^# Default mode: .*$/m, '<MODE-NOTE>');
  if (norm(set) !== norm(det)) err('Detect-BastionShieldPolicy.ps1', 'must be identical to Set-BastionShieldPolicy.ps1 except for the default $Mode line and its "# Default mode:" note');
  if (!/^\s*\[string\]\$Mode = 'Apply'/m.test(set)) err('Set-BastionShieldPolicy.ps1', "default $Mode must be 'Apply'");
  if (!/^\s*\[string\]\$Mode = 'Detect'/m.test(det)) err('Detect-BastionShieldPolicy.ps1', "default $Mode must be 'Detect'");
  // The script carries its own copy of the schema (it runs on devices without the repo).
  const table = /\$PolicySchema = \[ordered\]@\{([\s\S]*?)\n\}/.exec(set);
  if (!table) {
    err('Set-BastionShieldPolicy.ps1', '$PolicySchema table not found');
  } else {
    const entries = new Map<string, string>();
    for (const m of table[1].matchAll(/^\s*(\w+)\s*=\s*'([^']+)'/gm)) entries.set(m[1], m[2]);
    const props = schema.properties as JsonObject;
    for (const [k, nodeJ] of Object.entries(props)) {
      const node = nodeJ as JsonObject;
      let want: string;
      if (node.type === 'boolean') want = 'bool';
      else if (node.type === 'integer') want = `int:${node.minimum ?? ''}:${node.maximum ?? ''}`;
      else if (node.type === 'string' && Array.isArray(node.enum)) want = `enum:${node.enum.join(',')}`;
      else if (node.type === 'string') want = 'string';
      else if (node.type === 'array') want = 'string[]';
      else want = 'map-bool';
      const got = entries.get(k);
      if (got !== want) err('Set-BastionShieldPolicy.ps1', `$PolicySchema.${k} is ${JSON.stringify(got)}, expected '${want}'`);
    }
    for (const k of entries.keys()) if (!(k in props)) err('Set-BastionShieldPolicy.ps1', `$PolicySchema.${k} is not in managed_schema.json`);
  }
  // The embedded example configuration must validate too.
  const emb = /\$EmbeddedConfig = @'\r?\n([\s\S]*?)\r?\n'@/.exec(set);
  if (!emb) err('Set-BastionShieldPolicy.ps1', '$EmbeddedConfig here-string not found');
  else checkConfigJson(emb[1], schema, 'Set-BastionShieldPolicy.ps1 $EmbeddedConfig');
}

function checkConfigJson(text: string, schema: JsonObject, where: string): void {
  let cfg: unknown;
  try {
    cfg = JSON.parse(text);
  } catch (e) {
    err(where, `not valid JSON: ${(e as Error).message}`);
    return;
  }
  if (!isObj(cfg)) {
    err(where, 'must be an object');
    return;
  }
  for (const k of Object.keys(cfg)) if (!['$comment', 'extensionIds', 'policy'].includes(k)) err(where, `unknown top-level key "${k}"`);
  if (!isObj(cfg.extensionIds)) err(where, 'extensionIds object missing');
  else {
    for (const [b, id] of Object.entries(cfg.extensionIds)) {
      if (!['edge', 'chrome', 'brave'].includes(b)) err(where, `extensionIds.${b} is not edge/chrome/brave`);
      if (typeof id !== 'string' || !isIdOrPlaceholder(id)) err(where, `extensionIds.${b} must be a 32-letter id or a placeholder`);
      if (b === 'edge' && id === CHROME_PLACEHOLDER) err(where, 'extensionIds.edge must be <EDGE_ADDONS_ID>');
      if (b !== 'edge' && id === EDGE_PLACEHOLDER) err(where, `extensionIds.${b} must be <CHROME_WEB_STORE_ID>`);
    }
  }
  checkPolicyObject(cfg.policy, schema, `${where} policy`);
}

// ---------------------------------------------------------------------------

const schemaText = readFileSync(join(ROOT, 'policy', 'managed_schema.json'), 'utf8');
let schema: JsonObject = {};
try {
  schema = JSON.parse(schemaText) as JsonObject;
} catch (e) {
  err('policy/managed_schema.json', `not valid JSON: ${(e as Error).message}`);
}
checkTopLevel(schema, 'policy/managed_schema.json');
compareSchemaToTypes(schema, managedPolicyFromTypes());

const examples = join(ROOT, 'policy', 'examples');
for (const f of readdirSync(examples).sort()) {
  const p = join(examples, f);
  if (f.endsWith('.reg')) checkRegFile(p, schema);
  else if (f.endsWith('.mobileconfig')) checkMobileconfig(p, schema);
  else if (f.endsWith('.json')) checkConfigJson(readFileSync(p, 'utf8'), schema, `policy/examples/${f}`);
}
checkPowerShell(examples, schema);

for (const w of warnings) console.warn(`warning: ${w}`);
if (errors.length > 0) {
  for (const e of errors) console.error(`error: ${e}`);
  console.error(`\n${errors.length} error(s).`);
  process.exit(1);
}
console.log(`Policy schema and examples OK (${Object.keys((schema.properties as JsonObject) ?? {}).length} keys, ${warnings.length} warning(s)).`);
