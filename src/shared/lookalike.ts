// Bastion Shield — nerd mode lookalike-domain detection (pure, no DOM/chrome).
//
// findLookalike(host, protectedDomains) answers "does this hostname imitate
// one of the protected registrable domains?" for the top frame. Three checks,
// in this order (the first hit wins):
//   homoglyph  the registrable label, punycode-decoded and mapped to a
//              confusable skeleton (Cyrillic/Greek lookalikes, diacritics,
//              0->o, 1->l, 5->s, rn->m, vv->w, cl->d), equals the protected
//              label's skeleton (or is one edit away for an IDN label)
//   typo       Damerau-Levenshtein distance 1 between the second-level
//              labels (2 for labels of 9+ characters)
//   combo      the protected label is a whole hyphen/dot token next to a
//              phishing word (paypal-login-secure.com,
//              microsoft.account-verify.net), or the protected domain is
//              spelled out inside a foreign host (paypal.com.evil.net,
//              post-ch-paket.com)
// False positives are kept low on purpose: the protected domain and its
// subdomains never match, the same label under another TLD (google.ch for
// google.com) is legitimate, labels shorter than 5 characters get no typo
// check, 5-character labels only insertions and transpositions (twin.com is
// not twint.ch, apply.com is not apple.com), plurals are not typos, and
// everyday words (live, office) are only matched when written together with
// their TLD. The public suffix is approximated with registrableDomain
// (hash.ts), so "brand.evil.co.uk" is judged on "evil".
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { isIpAddress, registrableDomain, siteKeyOf } from './hash.ts';
import type { LookalikeHit } from './types.ts';

/** Built-in protected domains checked in addition to the user's and the policy's. */
export const DEFAULT_PROTECTED: readonly string[] = [
  // Identity, mail and cloud accounts
  'microsoft.com',
  'microsoftonline.com',
  'live.com',
  'office.com',
  'outlook.com',
  'google.com',
  'gmail.com',
  'apple.com',
  'icloud.com',
  'facebook.com',
  'instagram.com',
  // Payments and shopping
  'paypal.com',
  'amazon.com',
  'netflix.com',
  'twint.ch',
  // Swiss banks, post and telco
  'ubs.com',
  'postfinance.ch',
  'raiffeisen.ch',
  'zkb.ch',
  'post.ch',
  'swisscom.ch',
];

// ---------------------------------------------------------------------------
// Punycode (RFC 3492), decode only
// ---------------------------------------------------------------------------

const PC_BASE = 36;
const PC_TMIN = 1;
const PC_TMAX = 26;
const PC_SKEW = 38;
const PC_DAMP = 700;
const PC_INITIAL_BIAS = 72;
const PC_INITIAL_N = 128;
const MAX_LABEL = 63;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / PC_DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((PC_BASE - PC_TMIN) * PC_TMAX) >> 1) {
    d = Math.floor(d / (PC_BASE - PC_TMIN));
    k += PC_BASE;
  }
  return k + Math.floor(((PC_BASE - PC_TMIN + 1) * d) / (d + PC_SKEW));
}

function digitOf(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 22; // 0-9 -> 26-35
  if (c >= 0x41 && c <= 0x5a) return c - 0x41; // A-Z
  if (c >= 0x61 && c <= 0x7a) return c - 0x61; // a-z
  return PC_BASE;
}

/** Decode the part after "xn--" of one label (RFC 3492 section 6.2). Null for malformed input. */
export function punycodeDecode(input: string): string | null {
  if (input.length > MAX_LABEL * 4) return null;
  const out: number[] = [];
  const b = input.lastIndexOf('-');
  for (let j = 0; j < b; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    out.push(c);
  }
  let n = PC_INITIAL_N;
  let bias = PC_INITIAL_BIAS;
  let i = 0;
  for (let pos = b < 0 ? 0 : b + 1; pos < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = PC_BASE; ; k += PC_BASE) {
      if (pos >= input.length) return null;
      const digit = digitOf(input.charCodeAt(pos++));
      if (digit >= PC_BASE) return null;
      if (digit > Math.floor((0x7fffffff - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? PC_TMIN : k >= bias + PC_TMAX ? PC_TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(0x7fffffff / (PC_BASE - t))) return null;
      w *= PC_BASE - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    if (Math.floor(i / len) > 0x10ffff - n) return null;
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    out.splice(i, 0, n);
    i++;
    if (out.length > MAX_LABEL) return null;
  }
  return String.fromCodePoint(...out);
}

/** Unicode form of a (possibly punycode) label; the label itself when not IDN or malformed. */
export function decodeLabel(label: string): string {
  if (!label.startsWith('xn--')) return label;
  return punycodeDecode(label.slice(4)) ?? label;
}

// ---------------------------------------------------------------------------
// Confusable skeleton
// ---------------------------------------------------------------------------

/**
 * Single code points that render like a Latin letter or digit in common URL
 * bar fonts (a practical subset of Unicode's confusables.txt: Cyrillic,
 * Greek, Armenian and a few Latin letters that NFKD does not reduce).
 */
const CONFUSABLES: Readonly<Record<string, string>> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'ё': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j',
  'к': 'k', 'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'ѕ': 's', 'т': 't', 'у': 'y',
  'ӯ': 'y', 'х': 'x', 'ԝ': 'w', 'ь': 'b', 'ү': 'y', 'п': 'n', 'г': 'r',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
  'υ': 'u', 'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j', 'γ': 'y',
  // Armenian
  'օ': 'o', 'ս': 'u', 'ց': 'g', 'հ': 'h', 'ո': 'n', 'զ': 'q',
  // Latin letters and IPA without a decomposition
  'ı': 'i', 'ł': 'l', 'ƚ': 'l', 'ɩ': 'i', 'ɪ': 'i', 'ʟ': 'l', 'ɑ': 'a', 'ɒ': 'a', 'ø': 'o', 'ɵ': 'o',
  'đ': 'd', 'ħ': 'h', 'ŧ': 't', 'ƅ': 'b', 'ɡ': 'g', 'ß': 'ss', 'æ': 'ae', 'œ': 'oe',
  // Digits that pass for letters in a hostname
  '0': 'o', '1': 'l', '5': 's',
};

/** Multi-character lookalikes, applied after the per-character map. */
const SEQUENCES: readonly [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
];

/**
 * Confusable skeleton of a (Unicode) label: diacritics stripped, lookalike
 * characters mapped to ASCII, hyphens kept. Two labels with the same
 * skeleton look alike in the address bar.
 */
export function skeleton(label: string): string {
  let s = label.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
  let out = '';
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  s = out;
  for (const [re, to] of SEQUENCES) s = s.replace(re, to);
  return s;
}

// ---------------------------------------------------------------------------
// Edit distance
// ---------------------------------------------------------------------------

/**
 * Optimal-string-alignment Damerau-Levenshtein distance, capped: anything
 * above `max` is reported as max + 1 (with an early exit once a whole row
 * exceeds it).
 */
export function editDistance(a: string, b: string, max = 2): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const m = a.length;
  const n = b.length;
  let prev2: number[] = new Array<number>(n + 1).fill(0);
  let prev: number[] = Array.from({ length: n + 1 }, (_, j) => j);
  let cur: number[] = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    let rowMin = i;
    for (let j = 1; j <= n; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a.charCodeAt(i - 1) === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    const t = prev2;
    prev2 = prev;
    prev = cur;
    cur = t;
  }
  return Math.min(prev[n], max + 1);
}

/** True when `a` and `b` have the same length and differ in exactly one position. */
function isSubstitution(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) if (a.charCodeAt(i) !== b.charCodeAt(i) && ++diff > 1) return false;
  return diff === 1;
}

// ---------------------------------------------------------------------------
// Protected list
// ---------------------------------------------------------------------------

/** Words phishing hosts put next to a brand (en/de/fr/it, plus parcel lures). */
const COMBO_WORDS: ReadonlySet<string> = new Set([
  'login', 'logon', 'signin', 'signon', 'sign', 'secure', 'security', 'verify', 'verification', 'verified',
  'account', 'accounts', 'support', 'update', 'auth', 'authenticate', 'authentication', 'wallet', 'billing',
  'payment', 'payments', 'invoice', 'refund', 'recovery', 'recover', 'unlock', 'confirm', 'confirmation',
  'alert', 'alerts', 'helpdesk', 'password', '2fa', 'mfa', 'sso', 'id', 'ebanking', 'banking', 'portal',
  // de / fr / it
  'konto', 'kunden', 'sicherheit', 'anmelden', 'anmeldung', 'verifizierung', 'bestaetigung', 'passwort',
  'compte', 'connexion', 'securite', 'verifica', 'accesso', 'sicurezza', 'conto',
  // parcel and customs lures (Post, Amazon)
  'paket', 'sendung', 'zustellung', 'zoll', 'delivery', 'tracking', 'parcel', 'colis', 'pacco', 'customs',
]);

/** Protected labels that are everyday words: no typo check, combo only when spelled with their TLD (live.com.evil.net). */
const COMMON_WORD_LABELS: ReadonlySet<string> = new Set(['live', 'office']);

/** One edit away from a protected label but well-known names of their own. */
const KNOWN_DISTINCT: ReadonlySet<string> = new Set(['paypay', 'cloud']);

interface Protected {
  domain: string;
  label: string;
  /** Everything after the label ("com", "co.uk"). */
  suffix: string;
  skel: string;
}

function splitRegistrable(reg: string): { label: string; suffix: string } {
  const dot = reg.indexOf('.');
  if (dot <= 0) return { label: reg, suffix: '' };
  return { label: reg.slice(0, dot), suffix: reg.slice(dot + 1) };
}

// The service worker passes a fresh array on every call: cache the prepared
// list by content.
let cacheKey = '';
let cacheList: Protected[] = [];

function prepare(domains: readonly string[]): Protected[] {
  const key = domains.join(',');
  if (key === cacheKey) return cacheList;
  const seen = new Set<string>();
  const out: Protected[] = [];
  for (const raw of domains) {
    if (typeof raw !== 'string') continue;
    const h = siteKeyOf(raw.trim());
    if (h === '' || h.indexOf('.') === -1 || isIpAddress(h)) continue;
    const domain = registrableDomain(h);
    if (seen.has(domain)) continue;
    seen.add(domain);
    const { label, suffix } = splitRegistrable(domain);
    if (label.length < 2) continue;
    out.push({ domain, label, suffix, skel: skeleton(decodeLabel(label)) });
  }
  cacheKey = key;
  cacheList = out;
  return out;
}

function isSameOrSub(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/** Typo rule for two plain labels (see the header). */
function typoHit(cand: string, p: Protected): boolean {
  const prot = p.label;
  const len = prot.length;
  if (len < 5 || cand.length < 4 || COMMON_WORD_LABELS.has(prot) || KNOWN_DISTINCT.has(cand)) return false;
  if (cand === prot + 's') return false; // plural, not a typo
  const max = len >= 9 ? 2 : 1;
  const d = editDistance(cand, prot, max);
  if (d === 0 || d > max) return false;
  // Five-letter brands: a dropped or substituted letter too often gives a real word.
  if (len === 5 && (cand.length < len || isSubstitution(cand, prot))) return false;
  return true;
}

/** `label` followed by its suffix tokens somewhere before the host's own registrable domain ("paypal","com","evil","net"). */
function spelledWithTld(tokens: readonly string[], p: Protected): boolean {
  if (p.suffix === '') return false;
  const suffixTokens = p.suffix.split('.');
  for (let i = 0; i + suffixTokens.length + 1 < tokens.length; i++) {
    if (tokens[i] !== p.label) continue;
    let ok = true;
    for (let k = 0; k < suffixTokens.length && ok; k++) ok = tokens[i + 1 + k] === suffixTokens[k];
    if (ok) return true;
  }
  return false;
}

function comboHit(tokens: readonly string[], p: Protected): boolean {
  if (p.label.length < 3) return false;
  if (spelledWithTld(tokens, p)) return true;
  if (COMMON_WORD_LABELS.has(p.label)) return false;
  let brand = false;
  let word = false;
  const L = p.label.length;
  for (const t of tokens) {
    if (t === p.label) {
      brand = true;
    } else if (t.length > L && t.startsWith(p.label) && COMBO_WORDS.has(t.slice(L))) {
      brand = word = true; // glued: paypallogin
    } else if (t.length > L && t.endsWith(p.label) && COMBO_WORDS.has(t.slice(0, t.length - L))) {
      brand = word = true; // glued: secureubs
    } else if (COMBO_WORDS.has(t)) {
      word = true;
    }
  }
  return brand && word;
}

/**
 * Whether `host` imitates one of `protectedDomains` (never for the domain
 * itself or its subdomains).
 */
export function findLookalike(host: string, protectedDomains: readonly string[]): LookalikeHit | null {
  if (typeof host !== 'string' || !Array.isArray(protectedDomains)) return null;
  // `visited` is reported (www. kept); the checks use the site key.
  let visited = host.trim().toLowerCase();
  if (visited.endsWith('.')) visited = visited.slice(0, -1);
  const h = siteKeyOf(visited);
  if (h === '' || h.length > 253 || h.indexOf('.') === -1 || isIpAddress(h)) return null;
  const list = prepare(protectedDomains);
  if (list.length === 0) return null;
  for (const p of list) if (isSameOrSub(h, p.domain)) return null;

  const { label: rawLabel } = splitRegistrable(registrableDomain(h));
  const uLabel = decodeLabel(rawLabel);
  const idn = uLabel !== rawLabel;
  const skel = skeleton(uLabel);

  // 1. Homoglyphs: same look, different characters.
  for (const p of list) {
    if (uLabel === p.label) continue; // same label under another TLD: legitimate
    if (skel === p.skel) return { host: visited, target: p.domain, reason: 'homoglyph' };
    if (idn && p.label.length >= 5 && editDistance(skel, p.skel, 1) === 1) return { host: visited, target: p.domain, reason: 'homoglyph' };
  }

  // 2. Typos of the second-level label (IDN labels were judged above).
  if (!idn) {
    for (const p of list) {
      if (rawLabel !== p.label && typoHit(rawLabel, p)) return { host: visited, target: p.domain, reason: 'typo' };
    }
  }

  // 3. Combo-squatting over the whole hostname. A host whose own label is
  // the brand (google.com.au, accounts.google.co.uk) is the brand's site
  // under another suffix, not a combo.
  const tokens = h.split(/[.-]+/).filter((t) => t !== '').map(decodeLabel);
  for (const p of list) {
    if (uLabel !== p.label && comboHit(tokens, p)) return { host: visited, target: p.domain, reason: 'combo' };
  }
  return null;
}
