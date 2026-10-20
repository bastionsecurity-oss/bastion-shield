// Bastion Shield — fingerprint "farbling" core: seed handling, the per-site
// key derivation (HMAC-SHA-256), a small PRNG and the noise functions used by
// main/privacy.ts. Pure and DOM-free so it can be unit-tested under Node;
// privacy.ts feeds it typed arrays it got from the browser. Everything here
// is deterministic per (session seed, site, input), which mirrors Brave's
// farbling: a page sees stable values within a session, two sites see
// unrelated values, and nothing is random per call.
//
// Security model (ARCHITECTURE §9): the session seed is one public word per
// seed set (SEED_SETS sets of SEED_FILES_PER_SET files, 2^64 combinations).
// The per-site key is HMAC-SHA-256 over ALL seed words, so no observable
// depends on a subset of the seed and the sets cannot be solved one by one;
// recovering a site key (e.g. by inverting the non-cryptographic per-pixel
// hash) strips the noise on that site only and reveals nothing about the
// seed or any other site's key.
//
// The module captures the few built-ins it needs at load time. In the MAIN
// world it is evaluated (bundled into privacy.js) before any page script, so
// later prototype tampering by the page cannot reach into the noise code.
// The hash core uses operators and typed arrays only (no crypto.subtle: it is
// asynchronous and page-patchable).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const imul = Math.imul;
const mathFloor = Math.floor;
const mathCeil = Math.ceil;
const mathMax = Math.max;
const mathMin = Math.min;
const U8 = Uint8Array;
const U32 = Uint32Array;
const I32 = Int32Array;
const reflectApply = Reflect.apply;
const strCharCodeAt = String.prototype.charCodeAt;
// %TypedArray%.prototype.length is a configurable accessor a page could
// redefine; read it through the original getter.
const TypedArrayProto = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(TypedArrayProto, 'length')!.get as (this: ArrayBufferView) => number;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(TypedArrayProto, 'buffer')!.get as (this: ArrayBufferView) => ArrayBufferLike;
const typedArrayByteOffset = Object.getOwnPropertyDescriptor(TypedArrayProto, 'byteOffset')!.get as (this: ArrayBufferView) => number;
/** RGBA bytes read as one little-endian word give exactly the value the byte path composes. */
const LITTLE_ENDIAN = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;

/** Length of a typed array without trusting the (page-mutable) prototype chain. */
export function lengthOf(ta: ArrayBufferView): number {
  return reflectApply(typedArrayLength, ta, []) as number;
}

// ---------------------------------------------------------------------------
// Hashing / seeding
// ---------------------------------------------------------------------------

/** MurmurHash3 32-bit finalizer: a fast bijective avalanche on 32 bits. */
export function fmix32(h: number): number {
  h ^= h >>> 16;
  h = imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

/** Most seed words accepted (the seed files deliver SEED_SETS words). */
export const MAX_SEED_WORDS = 64;

/**
 * Validate the session seed words delivered by the seed files
 * (self.__bastionSeeds): all of them, as uint32. Returns null unless there
 * are between `minWords` (at least 4) and MAX_SEED_WORDS finite numbers; a
 * sparse array (a seed file that did not run) is rejected too.
 */
export function normalizeSeeds(raw: unknown, minWords = 4): Uint32Array | null {
  if (raw === null || typeof raw !== 'object') return null;
  const arr = raw as ArrayLike<unknown>;
  const n = typeof arr.length === 'number' ? arr.length : 0;
  const min = minWords > 4 ? minWords : 4;
  if (!(n >= min) || n > MAX_SEED_WORDS || n !== mathFloor(n)) return null;
  const out = new U32(n);
  for (let i = 0; i < n; i++) {
    const v = arr[i];
    if (typeof v !== 'number' || v !== v || v === Infinity || v === -Infinity) return null;
    out[i] = v >>> 0;
  }
  return out;
}

// ---------------------------------------------------------------------------
// SHA-256 / HMAC-SHA-256 (FIPS 180-4, RFC 2104), synchronous and self-contained
// ---------------------------------------------------------------------------

const SHA256_K = new U32([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256 digest (32 bytes) of `msg`. Inputs here are a few hundred bytes at most. */
export function sha256(msg: Uint8Array): Uint8Array {
  const len = lengthOf(msg);
  const total = (((len + 8) >>> 6) + 1) << 6; // message + 0x80 + 64-bit length, padded to 64
  const buf = new U8(total);
  for (let i = 0; i < len; i++) buf[i] = msg[i];
  buf[len] = 0x80;
  const bitsHi = mathFloor(len / 0x20000000);
  const bitsLo = (len << 3) >>> 0;
  buf[total - 8] = bitsHi >>> 24;
  buf[total - 7] = (bitsHi >>> 16) & 255;
  buf[total - 6] = (bitsHi >>> 8) & 255;
  buf[total - 5] = bitsHi & 255;
  buf[total - 4] = bitsLo >>> 24;
  buf[total - 3] = (bitsLo >>> 16) & 255;
  buf[total - 2] = (bitsLo >>> 8) & 255;
  buf[total - 1] = bitsLo & 255;

  const w = new I32(64);
  let h0 = 0x6a09e667 | 0, h1 = 0xbb67ae85 | 0, h2 = 0x3c6ef372 | 0, h3 = 0xa54ff53a | 0;
  let h4 = 0x510e527f | 0, h5 = 0x9b05688c | 0, h6 = 0x1f83d9ab | 0, h7 = 0x5be0cd19 | 0;
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4;
      w[t] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
    }
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15];
      const y = w[t - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[t] + w[t]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }
  const out = new U8(32);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i++) {
    const v = hs[i];
    out[i * 4] = v >>> 24;
    out[i * 4 + 1] = (v >>> 16) & 255;
    out[i * 4 + 2] = (v >>> 8) & 255;
    out[i * 4 + 3] = v & 255;
  }
  return out;
}

/** HMAC-SHA-256(key, msg), 32 bytes. */
export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const k = lengthOf(key) > 64 ? sha256(key) : key;
  const klen = lengthOf(k);
  const mlen = lengthOf(msg);
  const inner = new U8(64 + mlen);
  const outer = new U8(64 + 32);
  for (let i = 0; i < 64; i++) {
    const v = i < klen ? k[i] : 0;
    inner[i] = v ^ 0x36;
    outer[i] = v ^ 0x5c;
  }
  for (let i = 0; i < mlen; i++) inner[64 + i] = msg[i];
  const ih = sha256(inner);
  for (let i = 0; i < 32; i++) outer[64 + i] = ih[i];
  return sha256(outer);
}

/** UTF-8 bytes of `s` (lone surrogates become U+FFFD, as with TextEncoder). */
export function utf8Bytes(s: string): Uint8Array {
  const n = s.length;
  const tmp = new U8(n * 3);
  let j = 0;
  for (let i = 0; i < n; i++) {
    let c = reflectApply(strCharCodeAt, s, [i]) as number;
    if (c >= 0xd800 && c < 0xe000) {
      const d = i + 1 < n ? (reflectApply(strCharCodeAt, s, [i + 1]) as number) : 0;
      if (c < 0xdc00 && d >= 0xdc00 && d < 0xe000) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else {
        c = 0xfffd;
      }
    }
    if (c < 0x80) {
      tmp[j++] = c;
    } else if (c < 0x800) {
      tmp[j++] = 0xc0 | (c >>> 6);
      tmp[j++] = 0x80 | (c & 63);
    } else if (c < 0x10000) {
      tmp[j++] = 0xe0 | (c >>> 12);
      tmp[j++] = 0x80 | ((c >>> 6) & 63);
      tmp[j++] = 0x80 | (c & 63);
    } else {
      tmp[j++] = 0xf0 | (c >>> 18);
      tmp[j++] = 0x80 | ((c >>> 12) & 63);
      tmp[j++] = 0x80 | ((c >>> 6) & 63);
      tmp[j++] = 0x80 | (c & 63);
    }
  }
  const out = new U8(j);
  for (let i = 0; i < j; i++) out[i] = tmp[i];
  return out;
}

/** Domain-separation prefix of the key derivation message (bump on any format change). */
export const FARBLE_KDF_INFO = 'bastion-farble-v1\u0000';

/**
 * Per-site 128-bit key: the first 16 bytes, read as 4 little-endian uint32
 * words, of HMAC-SHA-256(key = every seed word as 4 little-endian bytes,
 * message = FARBLE_KDF_INFO + site). Every key word depends on every seed
 * word and on the site (ARCHITECTURE §9).
 */
export function deriveSiteKey(seeds: ArrayLike<number>, site: string): Uint32Array {
  const len = seeds.length;
  const n = len > 0 ? (len < MAX_SEED_WORDS ? len : MAX_SEED_WORDS) : 0;
  const kb = new U8(n * 4);
  for (let i = 0; i < n; i++) {
    const v = seeds[i] >>> 0;
    kb[i * 4] = v & 255;
    kb[i * 4 + 1] = (v >>> 8) & 255;
    kb[i * 4 + 2] = (v >>> 16) & 255;
    kb[i * 4 + 3] = v >>> 24;
  }
  const mac = hmacSha256(kb, utf8Bytes(FARBLE_KDF_INFO + site));
  const key = new U32(4);
  for (let i = 0; i < 4; i++) {
    key[i] = (mac[i * 4] | (mac[i * 4 + 1] << 8) | (mac[i * 4 + 2] << 16) | (mac[i * 4 + 3] << 24)) >>> 0;
  }
  return key;
}

/** One 32-bit value derived from the key for a given purpose (e.g. "cores"). */
export function keyedWord(key: ArrayLike<number>, purpose: number): number {
  let h = fmix32((key[0] ^ imul(purpose | 0, 0x9e3779b1)) >>> 0);
  h = fmix32((h ^ key[1]) >>> 0);
  h = fmix32((h ^ key[2] ^ imul(purpose | 0, 0x85ebca77)) >>> 0);
  return fmix32((h ^ key[3]) >>> 0);
}

/** Purpose tags for keyedWord / Prng so independent features never share a stream. */
export const PURPOSE = {
  CORES: 1,
  MEMORY: 2,
  AUDIO: 3,
  DEVICES: 4,
  /** Also SENTINEL + 64 and SENTINEL + 128 (privacy.ts). */
  SENTINEL: 5,
  /** Canvas/WebGL pixel noise: row key, pixel key, channel key. */
  CANVAS_ROW: 6,
  CANVAS_PIXEL: 7,
  CANVAS_CHANNEL: 8,
} as const;

/**
 * xoshiro128** — small, fast, well distributed. Seeded from the site key and
 * a purpose tag; never all-zero.
 */
export class Prng {
  private s0: number;
  private s1: number;
  private s2: number;
  private s3: number;

  constructor(key: ArrayLike<number>, purpose: number) {
    this.s0 = fmix32((key[0] ^ imul(purpose, 0x9e3779b9)) >>> 0);
    this.s1 = fmix32((key[1] ^ imul(purpose, 0x85ebca6b)) >>> 0);
    this.s2 = fmix32((key[2] ^ imul(purpose, 0xc2b2ae35)) >>> 0);
    this.s3 = fmix32((key[3] ^ imul(purpose, 0x27d4eb2f)) >>> 0);
    if ((this.s0 | this.s1 | this.s2 | this.s3) === 0) this.s0 = 1;
    for (let i = 0; i < 4; i++) this.next();
  }

  /** Next uint32. */
  next(): number {
    const result = imul(rotl(imul(this.s1, 5), 7), 9) >>> 0;
    const t = this.s1 << 9;
    this.s2 ^= this.s0;
    this.s3 ^= this.s1;
    this.s1 ^= this.s2;
    this.s0 ^= this.s3;
    this.s2 ^= t;
    this.s3 = rotl(this.s3, 11);
    return result;
  }

  /** Uniform integer in [0, n) for 1 <= n <= 2^32 (rejection sampling, no modulo bias). */
  below(n: number): number {
    if (!(n > 1)) return 0;
    const limit = 4294967296 - (4294967296 % n);
    for (let i = 0; i < 64; i++) {
      const v = this.next();
      if (v < limit) return v % n;
    }
    return this.next() % n;
  }
}

function rotl(x: number, k: number): number {
  return (x << k) | (x >>> (32 - k));
}

// ---------------------------------------------------------------------------
// Canvas / WebGL pixel noise
// ---------------------------------------------------------------------------

/**
 * A rectangle of RGBA8 pixels inside a byte array (ImageData.data, or the
 * Uint8Array a WebGL readPixels call filled).
 */
export interface PixelRegion {
  data: Uint8Array | Uint8ClampedArray;
  /** Byte index of the first pixel of the first row. */
  offset: number;
  width: number;
  height: number;
  /** Bytes from one row to the next (>= width * 4). */
  rowStride: number;
  /** Canvas coordinates of the first pixel: noise is keyed by position. */
  x0: number;
  y0: number;
  /**
   * WebGL rows are bottom-up. When set (>= 0), the canvas y of row r is
   * yFlip - (y0 + r), so readPixels and toDataURL agree on positions.
   */
  yFlip?: number;
}

export interface FarbleOptions {
  /**
   * Pixels with alpha below this are never touched. 1 for 2D canvases (skip
   * fully transparent pixels, whose RGB is always 0 in real canvases); 255
   * for WebGL, whose read-back is premultiplied, so only opaque pixels can
   * change without producing impossible values.
   */
  minAlpha: number;
  /**
   * Flip rate in 1/256 units (see flipThreshold). Derive it from the size of
   * the whole canvas, not of the read, so every read of a canvas agrees.
   * Default 1 (1 in 256 eligible pixels).
   */
  threshold?: number;
  /**
   * Guarantee at least this many flips (the pixels with the smallest hashes).
   * Only for reads of the whole canvas: a fallback on a partial read would
   * disagree with the full read. Default 0, at most MIN_FLIPS.
   */
  minFlips?: number;
}

// Which pixels change depends on the key, the pixel's canvas position and its
// own RGBA value: reads of overlapping regions agree (reading a canvas tile by
// tile gives the same noise as one full read), and noise learnt from a known
// test image does not transfer to a different rendering.

/** Aim for about this many flips on a fully drawn canvas, whatever its size. */
export const TARGET_FLIPS = 16;
/** Whole-canvas reads always get at least this many flips so small canvases change too. */
export const MIN_FLIPS = 3;
/** Regions larger than this are passed through untouched (cost; never seen in fingerprinting). */
export const MAX_FARBLE_PIXELS = 4096 * 4096;

/**
 * Flip threshold for a canvas of `area` pixels: 1/256 (0.4 % of eligible
 * pixels) for canvases of 4096 pixels and more, rising for smaller canvases
 * so they still get about TARGET_FLIPS flips, capped at 64/256.
 */
export function flipThreshold(area: number): number {
  if (!(area > 0)) return 1;
  const t = mathCeil((256 * TARGET_FLIPS) / area);
  return t < 1 ? 1 : t > 64 ? 64 : t;
}

/**
 * Farble a pixel region in place. Never touches alpha, never touches pixels
 * with alpha < minAlpha, and leaves the region alone when every pixel is
 * identical (fully transparent / blank / solid-fill canvases), so "is the
 * canvas blank?" checks keep working. Returns the number of changed pixels;
 * onChange receives the canvas coordinates of each changed pixel.
 */
export function farblePixels(
  r: PixelRegion,
  key: ArrayLike<number>,
  opts: FarbleOptions,
  onChange?: (x: number, y: number) => void,
): number {
  const data = r.data;
  const w = r.width | 0;
  const h = r.height | 0;
  const stride = r.rowStride | 0;
  const base = r.offset | 0;
  if (w <= 0 || h <= 0 || stride < w * 4 || base < 0) return 0;
  if (w * h > MAX_FARBLE_PIXELS) return 0;
  if (base + stride * (h - 1) + w * 4 > lengthOf(data)) return 0;
  const words = wordView(data, base, w, h, stride);
  if (words !== null ? isUniformWords(words, w, h, stride >> 2) : isUniform(data, base, w, h, stride)) return 0;

  const minAlpha = opts.minAlpha < 1 ? 1 : opts.minAlpha | 0;
  const t = opts.threshold;
  const threshold = typeof t === 'number' && t >= 1 ? mathMin(256, t | 0) : 1;
  const mf = opts.minFlips;
  const minFlips = typeof mf === 'number' && mf > 0 ? mathMin(MIN_FLIPS, mf | 0) : 0;
  // Sub-keys over the whole 128-bit key (not raw key words), so canvas output
  // depends on every key word and shares no key material with other features.
  const k0 = keyedWord(key, PURPOSE.CANVAS_ROW) | 0;
  const k1 = keyedWord(key, PURPOSE.CANVAS_PIXEL) | 0;
  const k2 = keyedWord(key, PURPOSE.CANVAS_CHANNEL) | 0;
  const flipY = typeof r.yFlip === 'number' && r.yFlip >= 0;
  const x0 = r.x0 | 0;
  const y0 = r.y0 | 0;

  // The MIN_FLIPS smallest hashes seen, as fallback flips for sparse canvases.
  const bestH = new U32(MIN_FLIPS);
  const bestI = new I32(MIN_FLIPS);
  const bestX = new I32(MIN_FLIPS);
  const bestY = new I32(MIN_FLIPS);
  for (let j = 0; j < MIN_FLIPS; j++) {
    bestH[j] = 0xffffffff;
    bestI[j] = -1;
  }
  let flips = 0;

  const wordStride = stride >> 2;
  for (let row = 0; row < h; row++) {
    const y = flipY ? (r.yFlip as number) - (y0 + row) : y0 + row;
    const yh = imul(y, 0x85ebca77) ^ k0;
    let i = base + row * stride;
    let wi = row * wordStride;
    for (let col = 0; col < w; col++, i += 4, wi++) {
      let rgba: number;
      if (words !== null) {
        rgba = words[wi];
        if (rgba >>> 24 < minAlpha) continue;
      } else {
        const a = data[i + 3];
        if (a < minAlpha) continue;
        rgba = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (a << 24);
      }
      const x = x0 + col;
      let hv = imul(imul(x, 0x9e3779b1) ^ yh ^ rgba, 0xcc9e2d51);
      hv ^= hv >>> 15;
      hv = imul(hv ^ k1, 0x1b873593);
      hv = (hv ^ (hv >>> 13)) >>> 0;
      if (hv >>> 24 < threshold) {
        flipChannel(data, i, hv, k2);
        flips++;
        if (onChange !== undefined) onChange(x, y);
        continue;
      }
      if (hv < bestH[MIN_FLIPS - 1]) {
        // Insertion into the tiny sorted "best" list.
        let j = MIN_FLIPS - 1;
        while (j > 0 && bestH[j - 1] > hv) {
          bestH[j] = bestH[j - 1];
          bestI[j] = bestI[j - 1];
          bestX[j] = bestX[j - 1];
          bestY[j] = bestY[j - 1];
          j--;
        }
        bestH[j] = hv;
        bestI[j] = i;
        bestX[j] = x;
        bestY[j] = y;
      }
    }
  }

  for (let j = 0; j < MIN_FLIPS && flips < minFlips; j++) {
    if (bestI[j] < 0) break;
    flipChannel(data, bestI[j], bestH[j], k2);
    flips++;
    if (onChange !== undefined) onChange(bestX[j], bestY[j]);
  }
  return flips;
}

function flipChannel(data: Uint8Array | Uint8ClampedArray, i: number, hv: number, k2: number): void {
  // Channel 0..2 (R, G, B) — alpha is never modified.
  const c = (fmix32((hv ^ k2) >>> 0) >>> 8) % 3;
  data[i + c] ^= 1;
}

/**
 * A Uint32 view over the region (4x fewer loads), or null when the platform
 * is big-endian or the region is not word-aligned (exotic readPixels offsets).
 */
function wordView(data: Uint8Array | Uint8ClampedArray, base: number, w: number, h: number, stride: number): Uint32Array | null {
  if (!LITTLE_ENDIAN || (stride & 3) !== 0) return null;
  try {
    const off = (reflectApply(typedArrayByteOffset, data, []) as number) + base;
    if ((off & 3) !== 0) return null;
    return new U32(reflectApply(typedArrayBuffer, data, []) as ArrayBuffer, off, (stride * (h - 1) + w * 4) >> 2);
  } catch {
    return null;
  }
}

function isUniformWords(words: Uint32Array, w: number, h: number, wordStride: number): boolean {
  const v0 = words[0];
  for (let row = 0; row < h; row++) {
    let k = row * wordStride;
    for (let col = 0; col < w; col++, k++) {
      if (words[k] !== v0) return false;
    }
  }
  return true;
}

function isUniform(data: Uint8Array | Uint8ClampedArray, base: number, w: number, h: number, stride: number): boolean {
  const r0 = data[base];
  const g0 = data[base + 1];
  const b0 = data[base + 2];
  const a0 = data[base + 3];
  for (let row = 0; row < h; row++) {
    let i = base + row * stride;
    for (let col = 0; col < w; col++, i += 4) {
      if (data[i] !== r0 || data[i + 1] !== g0 || data[i + 2] !== b0 || data[i + 3] !== a0) return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Web Audio noise
// ---------------------------------------------------------------------------

/** Buffers longer than this (samples per channel) are left alone: cost, and never used for fingerprinting. */
export const MAX_AUDIO_SAMPLES = 1 << 22;

/** Audio key for one channel of one feature (channels must not share noise). */
export function audioKey(key: ArrayLike<number>, channel: number): number {
  return fmix32((keyedWord(key, PURPOSE.AUDIO) ^ imul((channel | 0) + 1, 0x27d4eb2f)) >>> 0);
}

/**
 * Multiplier for sample `index`: 0.999 + up to 0.0001 of per-sample noise
 * (Brave uses 0.999 + a per-site fudge). About -0.009 dB: inaudible, but it
 * changes every non-zero float, so audio fingerprints do not match across
 * sites. Indexed (not sequential) so copyFromChannel at any offset agrees
 * with getChannelData.
 */
export function audioFactor(akey: number, index: number): number {
  const h = fmix32((akey ^ imul(index + 1, 0x9e3779b1)) >>> 0);
  return 0.999 + (h / 4294967296) * 0.0001;
}

/** Scale floats in [start, end) of arr; `indexBase` is the sample index of arr[0]. */
export function farbleFloats(
  arr: Float32Array,
  akey: number,
  indexBase: number,
  start = 0,
  end = Infinity,
): void {
  const n = mathMin(end, lengthOf(arr));
  for (let i = mathMax(0, start); i < n; i++) {
    const v = arr[i];
    // Zero, NaN and infinities stay as they are (silence must stay silent).
    if (v === 0 || v !== v || v === Infinity || v === -Infinity) continue;
    arr[i] = v * audioFactor(akey, indexBase + i);
  }
}

/**
 * Byte variants (getByteFrequencyData: center 0, getByteTimeDomainData:
 * center 128): about 1 in 8 non-center values moves one step toward the
 * center, mirroring the < 1 multiplier of the float path. Never overflows.
 */
export function farbleBytes(arr: Uint8Array | Uint8ClampedArray, akey: number, center: number): void {
  const n = lengthOf(arr);
  for (let i = 0; i < n; i++) {
    const v = arr[i];
    if (v === center) continue;
    const h = fmix32((akey ^ imul(i + 1, 0x9e3779b1) ^ imul(v + 1, 0x85ebca77)) >>> 0);
    if ((h & 7) !== 0) continue;
    arr[i] = v > center ? v - 1 : v + 1;
  }
}

// ---------------------------------------------------------------------------
// Navigator values
// ---------------------------------------------------------------------------

/**
 * navigator.hardwareConcurrency in [lo, real]: Standard keeps at least half
 * the real cores (apps size worker pools from it), Strict allows down to 2.
 * Always within ARCHITECTURE's [2, real].
 */
export function farbleConcurrency(real: number, word: number, strict: boolean): number {
  if (typeof real !== 'number' || !(real >= 2) || real > 4096) return real;
  const top = mathFloor(real);
  const lo = strict ? 2 : mathMax(2, mathCeil(top / 2));
  return lo + ((word >>> 0) % (top - lo + 1));
}

/**
 * navigator.deviceMemory: a power-of-two bucket at or below the real value.
 * Standard picks between real and real/2 (never below 1 GiB), Strict any
 * bucket in [1, real]. Values below 1 are reported unchanged.
 */
export function farbleDeviceMemory(real: number, word: number, strict: boolean): number {
  if (typeof real !== 'number' || !(real >= 1) || real > 1024) return real;
  let top = 1;
  while (top * 2 <= real) top *= 2;
  let count = 1; // number of candidate buckets, counting down from top
  if (strict) {
    for (let b = top; b > 1; b /= 2) count++;
  } else if (top >= 2) {
    count = 2;
  }
  const pick = (word >>> 0) % count;
  let v = top;
  for (let i = 0; i < pick; i++) v /= 2;
  return v;
}

/** Deterministic Fisher-Yates shuffle of arr in place. */
export function shuffleInPlace<T>(arr: { length: number; [i: number]: T }, rng: Prng): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = rng.below(i + 1);
    const t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
  }
}
