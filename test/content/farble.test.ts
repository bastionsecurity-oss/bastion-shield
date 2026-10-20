// Unit tests for src/main/farble.ts (fingerprint noise core).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import {
  audioFactor,
  audioKey,
  deriveSiteKey,
  FARBLE_KDF_INFO,
  farbleBytes,
  farbleConcurrency,
  farbleDeviceMemory,
  farbleFloats,
  farblePixels,
  flipThreshold,
  fmix32,
  hmacSha256,
  keyedWord,
  MAX_FARBLE_PIXELS,
  MAX_SEED_WORDS,
  MIN_FLIPS,
  normalizeSeeds,
  Prng,
  PURPOSE,
  sha256,
  shuffleInPlace,
  utf8Bytes,
} from '../../src/main/farble.ts';
import type { PixelRegion } from '../../src/main/farble.ts';
import { SEED_FILES_PER_SET, SEED_SETS } from '../../src/shared/constants.ts';

const SEEDS = [0x12345678, 0x9abcdef0, 0x0badf00d, 0xdeadbeef];
/** A full session seed: one word per seed set. */
const SEEDS16 = Array.from({ length: SEED_SETS }, (_, i) => fmix32((i * 0x01000193 + 0x2545f491) >>> 0));
const KEY = deriveSiteKey(SEEDS, 'example.com');

/** A deterministic "drawing": opaque gradient with a translucent band and a transparent corner. */
function image(w: number, h: number, seed = 1): Uint8ClampedArray {
  const d = new Uint8ClampedArray(w * h * 4);
  let s = seed;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      s = fmix32((s + 0x9e3779b9) >>> 0);
      d[i] = (x * 7 + (s & 3)) & 255;
      d[i + 1] = (y * 11) & 255;
      d[i + 2] = (x * y) & 255;
      d[i + 3] = x < 4 && y < 4 ? 0 : y % 5 === 0 ? 128 : 255;
      if (d[i + 3] === 0) d[i] = d[i + 1] = d[i + 2] = 0;
    }
  }
  return d;
}

function region(data: Uint8Array | Uint8ClampedArray, w: number, h: number, extra: Partial<PixelRegion> = {}): PixelRegion {
  return { data, offset: 0, width: w, height: h, rowStride: w * 4, x0: 0, y0: 0, ...extra };
}

function diffPixels(a: ArrayLike<number>, b: ArrayLike<number>): number[] {
  const out: number[] = [];
  for (let i = 0; i < a.length; i += 4) {
    if (a[i] !== b[i] || a[i + 1] !== b[i + 1] || a[i + 2] !== b[i + 2] || a[i + 3] !== b[i + 3]) out.push(i / 4);
  }
  return out;
}

test('fmix32 is a 32-bit bijection-style mixer', () => {
  assert.equal(fmix32(0), 0);
  const seen = new Set<number>();
  for (let i = 0; i < 10000; i++) {
    const v = fmix32(i);
    assert.ok(v >= 0 && v <= 0xffffffff && Number.isInteger(v));
    seen.add(v);
  }
  assert.equal(seen.size, 10000);
});

test('normalizeSeeds keeps every word and rejects short, sparse or non-numeric input', () => {
  assert.deepEqual(Array.from(normalizeSeeds([1, 2, 3, 4])!), [1, 2, 3, 4]);
  assert.deepEqual(Array.from(normalizeSeeds([-1, 2 ** 32 + 5, 3, 4])!), [0xffffffff, 5, 3, 4]);
  assert.equal(normalizeSeeds([1, 2, 3]), null);
  assert.equal(normalizeSeeds([1, 2, 3, NaN]), null);
  assert.equal(normalizeSeeds([1, 2, 3, '4']), null);
  assert.equal(normalizeSeeds(null), null);
  assert.equal(normalizeSeeds('1234'), null);
  // All words are kept (no folding into 4 slots).
  assert.deepEqual(Array.from(normalizeSeeds([1, 2, 3, 4, 5])!), [1, 2, 3, 4, 5]);
  assert.deepEqual(Array.from(normalizeSeeds(SEEDS16)!), SEEDS16);
  assert.deepEqual(Array.from(normalizeSeeds(new Uint32Array([7, 8, 9, 10]))!), [7, 8, 9, 10]);
  assert.equal(normalizeSeeds(new Array(MAX_SEED_WORDS + 1).fill(1)), null);
  assert.equal(normalizeSeeds({ length: 4.5, 0: 1, 1: 2, 2: 3, 3: 4 }), null);
  // privacy.ts requires all SEED_SETS words: 4 (old registrations) is rejected.
  assert.equal(normalizeSeeds([1, 2, 3, 4], SEED_SETS), null);
  assert.equal(normalizeSeeds(SEEDS16.slice(0, SEED_SETS - 1), SEED_SETS), null);
  assert.equal(normalizeSeeds(SEEDS16, SEED_SETS)!.length, SEED_SETS);
  // A seed file that did not run leaves a hole: rejected.
  const sparse: number[] = [];
  sparse[0] = 1;
  sparse[2] = 3;
  sparse[3] = 4;
  sparse[4] = 5;
  assert.equal(normalizeSeeds(sparse), null);
});

test('deriveSiteKey is deterministic and separates sites and sessions', () => {
  const a = deriveSiteKey(SEEDS, 'example.com');
  assert.deepEqual(Array.from(a), Array.from(deriveSiteKey(SEEDS, 'example.com')));
  assert.notDeepEqual(Array.from(a), Array.from(deriveSiteKey(SEEDS, 'example.org')));
  assert.notDeepEqual(Array.from(a), Array.from(deriveSiteKey([1, 2, 3, 4], 'example.com')));
  // A one-bit seed change changes every key word.
  const b = deriveSiteKey([SEEDS[0] ^ 1, SEEDS[1], SEEDS[2], SEEDS[3]], 'example.com');
  for (let i = 0; i < 4; i++) assert.notEqual(a[i], b[i]);
  assert.notEqual(keyedWord(a, PURPOSE.CORES), keyedWord(a, PURPOSE.MEMORY));
});

// ---------------------------------------------------------------------------
// SEC-1: key derivation is a keyed PRF over all seed words + site
// ---------------------------------------------------------------------------

test('sha256 and hmacSha256 match node:crypto (known answers)', () => {
  const cases: [Uint8Array, Uint8Array][] = [];
  const rnd = (n: number, s: number): Uint8Array => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s = fmix32((s + 0x9e3779b9) >>> 0);
      out[i] = s & 255;
    }
    return out;
  };
  // Lengths around every padding boundary (55/56/63/64/65 bytes), keys
  // shorter than, equal to and longer than the 64-byte block.
  for (const ml of [0, 1, 3, 31, 55, 56, 57, 63, 64, 65, 119, 120, 128, 200, 1000]) {
    for (const kl of [0, 16, 32, 63, 64, 65, 256]) cases.push([rnd(kl, kl * 7 + 1), rnd(ml, ml * 13 + 5)]);
  }
  for (const [k, m] of cases) {
    assert.equal(Buffer.from(sha256(m)).toString('hex'), createHash('sha256').update(m).digest('hex'), `sha256 len ${m.length}`);
    assert.equal(
      Buffer.from(hmacSha256(k, m)).toString('hex'),
      createHmac('sha256', k).update(m).digest('hex'),
      `hmac key ${k.length} msg ${m.length}`,
    );
  }
  // FIPS 180-2 "abc" and RFC 4231 test case 2.
  assert.equal(
    Buffer.from(sha256(new Uint8Array([0x61, 0x62, 0x63]))).toString('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
  assert.equal(
    Buffer.from(hmacSha256(utf8Bytes('Jefe'), utf8Bytes('what do ya want for nothing?'))).toString('hex'),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  );
});

test('utf8Bytes matches Buffer for ASCII, IDN, astral and lone surrogates', () => {
  for (const s of ['', 'example.com', 'zürich.ch', 'xn--zrich-kva.ch', '日本.jp', 'a\u{1f600}b', 'x\ud800y', '\udc00', 'z\ud83d']) {
    assert.deepEqual(Buffer.from(utf8Bytes(s)), Buffer.from(s, 'utf8'), JSON.stringify(s));
  }
});

test('deriveSiteKey is HMAC-SHA-256(seed words LE, info + site), first 16 bytes LE', () => {
  for (const site of ['example.com', 'bank.ch', '', 'zürich.ch']) {
    const kb = Buffer.alloc(SEEDS16.length * 4);
    SEEDS16.forEach((w, i) => kb.writeUInt32LE(w >>> 0, i * 4));
    const mac = createHmac('sha256', kb).update(Buffer.from(FARBLE_KDF_INFO + site, 'utf8')).digest();
    const expected = [0, 1, 2, 3].map((i) => mac.readUInt32LE(i * 4));
    assert.deepEqual(Array.from(deriveSiteKey(SEEDS16, site)), expected, site);
  }
  assert.equal(FARBLE_KDF_INFO, 'bastion-farble-v1\u0000');
});

test('every key word differs between sites (regression: h cancelled out of key[0])', () => {
  const sites = ['example.com', 'bank.ch', 'tracker.net', 'example.org', 'a.b'];
  for (const seeds of [SEEDS, SEEDS16, [0x11111111, 0x22222222, 0x33333333, 0x44444444]]) {
    const keys = sites.map((s) => deriveSiteKey(seeds, s));
    for (let i = 0; i < keys.length; i++) {
      for (let j = i + 1; j < keys.length; j++) {
        for (let w = 0; w < 4; w++) assert.notEqual(keys[i][w], keys[j][w], `${sites[i]} vs ${sites[j]} word ${w}`);
      }
    }
  }
});

/** Every value a page can observe, as derived from one site key. */
function observables(key: Uint32Array): Record<string, unknown> {
  const w = 64;
  const h = 64;
  const canvas = image(w, h, 21);
  farblePixels(region(canvas, w, h), key, { minAlpha: 1, threshold: flipThreshold(w * h), minFlips: MIN_FLIPS });
  const gl = image(w, h, 22);
  for (let i = 3; i < gl.length; i += 4) gl[i] = 255;
  farblePixels(region(gl, w, h, { yFlip: h - 1 }), key, { minAlpha: 255, threshold: flipThreshold(w * h), minFlips: MIN_FLIPS });
  const samples = new Float32Array(64).fill(0.5);
  farbleFloats(samples, audioKey(key, 0), 0);
  const analyser = new Float32Array(64).fill(-30);
  farbleFloats(analyser, audioKey(key, 1000), 0);
  const bytes = new Uint8Array(256).map((_, i) => i);
  farbleBytes(bytes, audioKey(key, 1000), 0);
  const rng = new Prng(key, PURPOSE.DEVICES);
  return {
    canvas: Buffer.from(canvas).toString('hex'),
    webgl: Buffer.from(gl).toString('hex'),
    audio: Array.from(samples).join(','),
    analyser: Array.from(analyser).join(','),
    analyserBytes: Buffer.from(bytes).toString('hex'),
    coresWord: keyedWord(key, PURPOSE.CORES),
    memoryWord: keyedWord(key, PURPOSE.MEMORY),
    devices: [rng.next(), rng.next(), rng.next()].join(','),
    sentinel: keyedWord(key, PURPOSE.SENTINEL),
  };
}

test('changing any single seed word changes every key word and every derived observable', () => {
  const base = deriveSiteKey(SEEDS16, 'example.com');
  const baseObs = observables(base);
  for (let i = 0; i < SEEDS16.length; i++) {
    for (const delta of [1, 0x80000000, 0x01000000]) {
      const seeds = SEEDS16.slice();
      seeds[i] = (seeds[i] ^ delta) >>> 0;
      const key = deriveSiteKey(seeds, 'example.com');
      for (let w = 0; w < 4; w++) assert.notEqual(key[w], base[w], `seed ${i} ^ ${delta.toString(16)}: key word ${w} unchanged`);
      const obs = observables(key);
      for (const name of Object.keys(baseObs)) {
        assert.notDeepEqual(obs[name], baseObs[name], `seed ${i} ^ ${delta.toString(16)}: ${name} unchanged`);
      }
    }
  }
});

test('canvas noise depends on all four key words', () => {
  const w = 64;
  const orig = image(w, w, 31);
  const ref = orig.slice();
  farblePixels(region(ref, w, w), KEY, { minAlpha: 1, threshold: flipThreshold(w * w), minFlips: MIN_FLIPS });
  for (let k = 0; k < 4; k++) {
    const key = KEY.slice();
    key[k] ^= 1;
    const d = orig.slice();
    farblePixels(region(d, w, w), key, { minAlpha: 1, threshold: flipThreshold(w * w), minFlips: MIN_FLIPS });
    assert.notDeepEqual(d, ref, `key word ${k} does not affect the canvas`);
  }
});

/**
 * Port of the security review's attack (scratchpad/review/security/attack.js)
 * against a 16x16 public seed pool. The attack solved the seed set by set:
 * guess set 0 alone, predict the canvas flips, keep the matches, go on with
 * set 1. With an HMAC over all words that stage cannot run: the key (and so
 * every flip) changes when any other set changes, so a set-0 guess has no
 * testable prediction.
 */
test('the set-by-set seed recovery attack cannot narrow candidates', () => {
  const SETS = SEED_SETS;
  const PER = SEED_FILES_PER_SET;
  assert.equal(SETS, 16);
  assert.equal(PER, 16);
  // The public pool (every install of a build ships the same words).
  const pool: number[][] = [];
  for (let s = 0; s < SETS; s++) pool.push(Array.from({ length: PER }, (_, n) => fmix32((s * 7919 + n * 104729 + 1) >>> 0)));
  const pick = Array.from({ length: SETS }, (_, s) => (s * 5 + 3) % PER); // the victim's session pick
  const seedsOf = (files: number[]): number[] => files.map((n, s) => pool[s][n]);
  const site = 'example.com';
  const truthKey = deriveSiteKey(seedsOf(pick), site);

  // Victim observation: a 64x64 opaque canvas of attacker-chosen pixels.
  const W = 64;
  const truth = new Uint8ClampedArray(W * W * 4);
  for (let i = 0; i < W * W; i++) {
    const v = fmix32((i + 12345) >>> 0) & 0xffffff;
    truth.set([v & 255, (v >>> 8) & 255, (v >>> 16) & 255, 255], i * 4);
  }
  const opts = { minAlpha: 1, threshold: flipThreshold(W * W), minFlips: MIN_FLIPS };
  const flipsOf = (key: Uint32Array): string => {
    const d = truth.slice();
    farblePixels(region(d, W, W), key, opts);
    return diffPixels(truth, d).join(',');
  };
  const observed = flipsOf(truthKey);
  assert.ok(observed.length > 0, 'the canvas is farbled');

  // Stage 2 precondition of the old attack: key[0] must be a function of
  // set 0 alone. It is not: changing only the last seed word changes it.
  const other = pick.slice();
  other[SETS - 1] = (other[SETS - 1] + 1) % PER;
  assert.notEqual(deriveSiteKey(seedsOf(other), site)[0], truthKey[0], 'key[0] must depend on seeds[15]');

  // The old single-set search: for each set, try its 16 words while every
  // other set stays at the attacker's best guess (file 0). No candidate of
  // any set reproduces the observation, so nothing is narrowed.
  for (let s = 0; s < SETS; s++) {
    let matches = 0;
    for (let n = 0; n < PER; n++) {
      const guess = new Array(SETS).fill(0);
      guess[s] = n;
      if (flipsOf(deriveSiteKey(seedsOf(guess), site)) === observed) matches++;
    }
    assert.equal(matches, 0, `set ${s}: a single-set guess matched`);
  }
  // Stage 2 of attack.js verbatim: k0 from set 0 (h cancelled), k1 from
  // set 1, raw k0/k1 in the per-pixel hash, compared with the observed flip
  // set. No (set 0, set 1) pair is consistent any more.
  const imul = Math.imul;
  const fnv = (str: string): number => {
    let x = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) x = imul(x ^ str.charCodeAt(i), 0x01000193);
    return x >>> 0;
  };
  const hs = fnv(site);
  const observedSet = new Set(observed.split(',').map(Number));
  const hvOf = (k0: number, k1: number, i: number): number => {
    const x = i % W;
    const y = (i / W) | 0;
    const rgba = truth[i * 4] | (truth[i * 4 + 1] << 8) | (truth[i * 4 + 2] << 16) | (255 << 24);
    let hv = imul(imul(x, 0x9e3779b1) ^ (imul(y, 0x85ebca77) ^ k0) ^ rgba, 0xcc9e2d51);
    hv ^= hv >>> 15;
    hv = imul(hv ^ k1, 0x1b873593);
    return (hv ^ (hv >>> 13)) >>> 0;
  };
  let abCandidates = 0;
  for (let a = 0; a < PER; a++) {
    const k0 = fmix32((pool[0][a] ^ hs ^ hs ^ imul(1, 0x9e3779b9)) >>> 0);
    for (let b = 0; b < PER; b++) {
      const k1 = fmix32((pool[1][b] ^ hs ^ k0 ^ imul(2, 0x9e3779b9)) >>> 0);
      const pred = new Set<number>();
      const rest: [number, number][] = [];
      let ok = true;
      for (let i = 0; i < W * W && ok; i++) {
        const hv = hvOf(k0 | 0, k1 | 0, i);
        if (hv >>> 24 < opts.threshold) {
          pred.add(i);
          if (!observedSet.has(i)) ok = false;
        } else {
          rest.push([hv, i]);
        }
      }
      if (!ok) continue;
      if (pred.size < MIN_FLIPS) {
        rest.sort((p, q) => p[0] - q[0]);
        for (let j = 0; pred.size < MIN_FLIPS && j < rest.length; j++) pred.add(rest[j][1]);
      }
      if (pred.size === observedSet.size && [...observedSet].every((i) => pred.has(i))) abCandidates++;
    }
  }
  assert.equal(abCandidates, 0, 'stage 2 of the old attack still narrows candidates');
  // Sanity: the oracle itself works, only the full 16-set pick (2^64) matches.
  assert.equal(flipsOf(deriveSiteKey(seedsOf(pick), site)), observed);
  // Cross-site: the same seed gives unrelated keys on another site.
  const otherSite = deriveSiteKey(seedsOf(pick), 'example.net');
  for (let w = 0; w < 4; w++) assert.notEqual(otherSite[w], truthKey[w]);
});

test('Prng is deterministic per key and purpose and below() stays in range', () => {
  const p1 = new Prng(KEY, 1);
  const p2 = new Prng(KEY, 1);
  const p3 = new Prng(KEY, 2);
  const s1 = Array.from({ length: 32 }, () => p1.next());
  const s2 = Array.from({ length: 32 }, () => p2.next());
  const s3 = Array.from({ length: 32 }, () => p3.next());
  assert.deepEqual(s1, s2);
  assert.notDeepEqual(s1, s3);
  for (const v of s1) assert.ok(Number.isInteger(v) && v >= 0 && v <= 0xffffffff);
  const rng = new Prng(KEY, 9);
  const counts = new Array(7).fill(0);
  for (let i = 0; i < 7000; i++) {
    const v = rng.below(7);
    assert.ok(v >= 0 && v < 7);
    counts[v]++;
  }
  for (const c of counts) assert.ok(c > 800 && c < 1200, `skewed bucket ${c}`);
  assert.equal(rng.below(1), 0);
  assert.equal(rng.below(0), 0);
  // All-zero key must not stall the generator.
  const z = new Prng([0, 0, 0, 0], 0);
  assert.notEqual(z.next() | z.next() | z.next(), 0);
});

test('flipThreshold scales with canvas size', () => {
  assert.equal(flipThreshold(240 * 60), 1);
  assert.equal(flipThreshold(4096), 1);
  assert.equal(flipThreshold(1024), 4);
  assert.equal(flipThreshold(256), 16);
  assert.equal(flipThreshold(16), 64);
  assert.equal(flipThreshold(0), 1);
  assert.equal(flipThreshold(NaN), 1);
});

test('farblePixels is deterministic, sparse and never touches alpha or transparent pixels', () => {
  const w = 240;
  const h = 60;
  const orig = image(w, h);
  const a = orig.slice();
  const b = orig.slice();
  const opts = { minAlpha: 1, threshold: flipThreshold(w * h), minFlips: MIN_FLIPS };
  const n1 = farblePixels(region(a, w, h), KEY, opts);
  const n2 = farblePixels(region(b, w, h), KEY, opts);
  assert.equal(n1, n2);
  assert.deepEqual(a, b);
  const changed = diffPixels(orig, a);
  assert.equal(changed.length, n1);
  assert.ok(n1 >= MIN_FLIPS, 'some pixels change');
  assert.ok(n1 < (w * h) / 64, `too dense: ${n1}`);
  for (const p of changed) {
    const i = p * 4;
    assert.equal(a[i + 3], orig[i + 3], 'alpha untouched');
    assert.notEqual(orig[i + 3], 0, 'transparent pixels untouched');
    const d = Math.abs(a[i] - orig[i]) + Math.abs(a[i + 1] - orig[i + 1]) + Math.abs(a[i + 2] - orig[i + 2]);
    assert.equal(d, 1, 'exactly one LSB of one channel');
  }
  // Another site or session gives different noise.
  const c = orig.slice();
  farblePixels(region(c, w, h), deriveSiteKey(SEEDS, 'other.org'), opts);
  assert.notDeepEqual(a, c);
});

test('farblePixels leaves blank and uniform regions alone', () => {
  const blank = new Uint8ClampedArray(64 * 64 * 4);
  assert.equal(farblePixels(region(blank, 64, 64), KEY, { minAlpha: 1, minFlips: 3 }), 0);
  assert.ok(blank.every((v) => v === 0));
  const white = new Uint8ClampedArray(64 * 64 * 4).fill(255);
  assert.equal(farblePixels(region(white, 64, 64), KEY, { minAlpha: 1, minFlips: 3 }), 0);
  assert.ok(white.every((v) => v === 255));
});

test('minFlips guarantees noise on sparse canvases only when requested', () => {
  // One opaque 3x3 blob on a transparent 32x32 canvas.
  const w = 32;
  const make = () => {
    const d = new Uint8ClampedArray(w * w * 4);
    for (let y = 10; y < 13; y++) for (let x = 10; x < 13; x++) d.set([200, 100 + x, 50 + y, 255], (y * w + x) * 4);
    return d;
  };
  const withMin = make();
  const n = farblePixels(region(withMin, w, w), KEY, { minAlpha: 1, threshold: 1, minFlips: MIN_FLIPS });
  assert.equal(n, MIN_FLIPS);
  const without = make();
  const m = farblePixels(region(without, w, w), KEY, { minAlpha: 1, threshold: 1 });
  assert.ok(m <= 1, 'natural rate on 9 pixels is ~0');
});

test('tile reads agree with the full read (same canvas threshold, no fallback)', () => {
  const w = 128;
  const h = 64;
  const orig = image(w, h, 7);
  const threshold = flipThreshold(w * h);
  const full = orig.slice();
  farblePixels(region(full, w, h), KEY, { minAlpha: 1, threshold });
  for (const [tx, ty, tw, th] of [[0, 0, 16, 16], [37, 11, 9, 23], [100, 40, 28, 24]]) {
    const tile = new Uint8ClampedArray(tw * th * 4);
    for (let y = 0; y < th; y++) tile.set(orig.subarray(((ty + y) * w + tx) * 4, ((ty + y) * w + tx + tw) * 4), y * tw * 4);
    farblePixels(region(tile, tw, th, { x0: tx, y0: ty }), KEY, { minAlpha: 1, threshold });
    for (let y = 0; y < th; y++) {
      for (let x = 0; x < tw * 4; x++) {
        assert.equal(tile[y * tw * 4 + x], full[((ty + y) * w + tx) * 4 + x], `tile ${tx},${ty} mismatch`);
      }
    }
  }
});

test('word and byte paths give identical results; strides and yFlip are honoured', () => {
  const w = 50;
  const h = 40;
  const orig = image(w, h, 3);
  // Aligned (word path).
  const aligned = new Uint8Array(orig.length);
  aligned.set(orig);
  farblePixels(region(aligned, w, h), KEY, { minAlpha: 1, threshold: 8 });
  // Misaligned by one byte (byte path).
  const backing = new Uint8Array(orig.length + 1);
  const mis = backing.subarray(1);
  mis.set(orig);
  farblePixels(region(mis, w, h), KEY, { minAlpha: 1, threshold: 8 });
  assert.deepEqual(Array.from(mis), Array.from(aligned));

  // Padded rows (WebGL PACK_ALIGNMENT=8 with odd width): padding bytes untouched.
  const pw = 5;
  const stride = 24;
  const padded = new Uint8Array(stride * 30).fill(255);
  for (let y = 0; y < 30; y++) for (let x = 0; x < pw; x++) padded.set([x * 40, y * 8, 77, 255], y * stride + x * 4);
  const before = padded.slice();
  farblePixels({ data: padded, offset: 0, width: pw, height: 30, rowStride: stride, x0: 0, y0: 0 }, KEY, { minAlpha: 255, threshold: 64 });
  for (let y = 0; y < 30; y++) for (let k = pw * 4; k < stride; k++) assert.equal(padded[y * stride + k], before[y * stride + k]);

  // yFlip: bottom-up rows map to the same canvas positions as a top-down read.
  const td = image(16, 16, 5);
  const bu = new Uint8ClampedArray(td.length);
  for (let y = 0; y < 16; y++) bu.set(td.subarray(y * 64, y * 64 + 64), (15 - y) * 64);
  farblePixels(region(td, 16, 16), KEY, { minAlpha: 1, threshold: 64 });
  farblePixels(region(bu, 16, 16, { yFlip: 15 }), KEY, { minAlpha: 1, threshold: 64 });
  for (let y = 0; y < 16; y++) assert.deepEqual(Array.from(bu.subarray((15 - y) * 64, (15 - y) * 64 + 64)), Array.from(td.subarray(y * 64, y * 64 + 64)));
});

test('minAlpha 255 (WebGL) only touches opaque pixels', () => {
  const w = 64;
  const orig = image(w, w, 11);
  const d = orig.slice();
  farblePixels(region(d, w, w), KEY, { minAlpha: 255, threshold: 64, minFlips: 3 });
  for (const p of diffPixels(orig, d)) assert.equal(orig[p * 4 + 3], 255);
});

test('farblePixels refuses out-of-bounds or oversized regions', () => {
  const d = new Uint8ClampedArray(10 * 10 * 4);
  d[5] = 9;
  assert.equal(farblePixels(region(d, 11, 10), KEY, { minAlpha: 1 }), 0);
  assert.equal(farblePixels({ data: d, offset: 8, width: 10, height: 10, rowStride: 40, x0: 0, y0: 0 }, KEY, { minAlpha: 1 }), 0);
  assert.equal(farblePixels(region(d, 10, 10, { rowStride: 20 }), KEY, { minAlpha: 1 }), 0);
  assert.equal(farblePixels(region(d, 0, 10), KEY, { minAlpha: 1 }), 0);
  const side = Math.ceil(Math.sqrt(MAX_FARBLE_PIXELS)) + 1;
  assert.equal(farblePixels(region(new Uint8Array(4), side, side), KEY, { minAlpha: 1 }), 0);
});

test('onChange reports the canvas coordinates of every changed pixel', () => {
  const w = 40;
  const h = 30;
  const orig = image(w, h, 2);
  const d = orig.slice();
  const seen: string[] = [];
  const n = farblePixels(region(d, w, h, { x0: 100, y0: 200 }), KEY, { minAlpha: 1, threshold: 32, minFlips: 3 }, (x, y) => seen.push(`${x},${y}`));
  assert.equal(seen.length, n);
  const expected = diffPixels(orig, d).map((p) => `${100 + (p % w)},${200 + Math.floor(p / w)}`);
  assert.deepEqual(seen.sort(), expected.sort());
});

test('audio factor is 0.999 plus tiny per-sample noise and index-addressable', () => {
  const k = audioKey(KEY, 0);
  for (let i = 0; i < 1000; i++) {
    const f = audioFactor(k, i);
    assert.ok(f >= 0.999 && f < 0.9991);
  }
  assert.notEqual(audioFactor(k, 1), audioFactor(k, 2));
  assert.notEqual(audioKey(KEY, 0), audioKey(KEY, 1));
  const long = new Float32Array(600).map((_, i) => Math.sin(i / 3));
  const tail = long.slice(100);
  farbleFloats(long, k, 0);
  farbleFloats(tail, k, 100);
  assert.deepEqual(Array.from(tail), Array.from(long.subarray(100)));
  const special = new Float32Array([0, NaN, Infinity, -Infinity, 0.5]);
  farbleFloats(special, k, 0);
  assert.equal(special[0], 0);
  assert.ok(Number.isNaN(special[1]));
  assert.equal(special[2], Infinity);
  assert.equal(special[3], -Infinity);
  assert.ok(special[4] < 0.5 && special[4] > 0.4994);
  // Partial ranges.
  const part = new Float32Array([1, 1, 1, 1]);
  farbleFloats(part, k, 0, 1, 3);
  assert.equal(part[0], 1);
  assert.equal(part[3], 1);
  assert.ok(part[1] < 1 && part[2] < 1);
});

test('farbleBytes moves a sparse subset one step toward the center', () => {
  const k = audioKey(KEY, 1000);
  const freq = new Uint8Array(2048).map((_, i) => i % 256);
  const orig = freq.slice();
  farbleBytes(freq, k, 0);
  let moved = 0;
  for (let i = 0; i < freq.length; i++) {
    if (orig[i] === 0) assert.equal(freq[i], 0);
    const d = orig[i] - freq[i];
    assert.ok(d === 0 || d === 1);
    if (d) moved++;
  }
  assert.ok(moved > 100 && moved < 500, `moved ${moved}`);
  const time = new Uint8Array([128, 0, 255, 127, 129, 128]);
  for (let r = 0; r < 50; r++) farbleBytes(time, fmix32(r), 128);
  assert.equal(time[0], 128);
  assert.equal(time[5], 128);
  assert.ok(time[1] >= 0 && time[1] <= 128 && time[2] >= 128 && time[2] <= 255);
});

test('hardwareConcurrency stays in [2, real] (standard keeps half)', () => {
  for (let w = 0; w < 200; w++) {
    const s = farbleConcurrency(16, fmix32(w), false);
    assert.ok(s >= 8 && s <= 16, `standard ${s}`);
    const t = farbleConcurrency(16, fmix32(w), true);
    assert.ok(t >= 2 && t <= 16, `strict ${t}`);
    const four = farbleConcurrency(4, fmix32(w), false);
    assert.ok(four >= 2 && four <= 4);
  }
  assert.equal(farbleConcurrency(2, 12345, true), 2);
  assert.equal(farbleConcurrency(1, 12345, true), 1);
  assert.ok(Number.isNaN(farbleConcurrency(NaN, 1, false)));
  const values = new Set(Array.from({ length: 64 }, (_, w) => farbleConcurrency(16, fmix32(w), false)));
  assert.ok(values.size > 4, 'uses the range');
});

test('deviceMemory is a power-of-two bucket at or below the real value', () => {
  for (let w = 0; w < 100; w++) {
    const s = farbleDeviceMemory(8, fmix32(w), false);
    assert.ok(s === 8 || s === 4, `standard ${s}`);
    const t = farbleDeviceMemory(8, fmix32(w), true);
    assert.ok([1, 2, 4, 8].includes(t), `strict ${t}`);
    assert.equal(farbleDeviceMemory(1, fmix32(w), true), 1);
  }
  assert.equal(farbleDeviceMemory(0.5, 3, true), 0.5);
  assert.equal(farbleDeviceMemory(0.25, 3, false), 0.25);
  assert.equal(farbleDeviceMemory(2, 0, false), 2);
  assert.equal(farbleDeviceMemory(2, 1, false), 1);
});

test('shuffleInPlace is a deterministic permutation', () => {
  const a = Array.from({ length: 10 }, (_, i) => i);
  const b = a.slice();
  shuffleInPlace(a, new Prng(KEY, PURPOSE.DEVICES));
  shuffleInPlace(b, new Prng(KEY, PURPOSE.DEVICES));
  assert.deepEqual(a, b);
  assert.deepEqual(a.slice().sort((x, y) => x - y), Array.from({ length: 10 }, (_, i) => i));
  const c = Array.from({ length: 10 }, (_, i) => i);
  shuffleInPlace(c, new Prng(deriveSiteKey(SEEDS, 'other.example'), PURPOSE.DEVICES));
  assert.notDeepEqual(a, c);
});
