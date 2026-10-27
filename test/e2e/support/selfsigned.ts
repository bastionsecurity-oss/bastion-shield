// Bastion Shield e2e — throw-away self-signed TLS certificate for the local
// fixture server. Hand-rolled DER so the tests need neither openssl nor an npm
// dependency; Chromium runs with --ignore-certificate-errors, so the
// certificate only has to be well-formed, not trusted.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';

function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const seq = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
const NULL = Buffer.from([0x05, 0x00]);

function integer(bytes: Buffer): Buffer {
  // DER integers are signed: prefix 0x00 when the high bit is set.
  const b = bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
  return tlv(0x02, b);
}

function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const out: number[] = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const chunk: number[] = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, '0');
  const body =
    pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds()) + 'Z';
  // RFC 5280: UTCTime through 2049, GeneralizedTime from 2050.
  return d.getUTCFullYear() < 2050
    ? tlv(0x17, Buffer.from(String(d.getUTCFullYear()).slice(2) + body, 'ascii'))
    : tlv(0x18, Buffer.from(String(d.getUTCFullYear()) + body, 'ascii'));
}

function toPem(label: string, der: Buffer): string {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64.replace(/\n$/, '')}\n-----END ${label}-----\n`;
}

export interface SelfSigned {
  key: string;
  cert: string;
}

/** RSA-2048 / SHA-256 certificate for the given DNS names (wildcards allowed). */
export function createSelfSigned(dnsNames: string[], commonName = 'Bastion Shield e2e'): SelfSigned {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const sha256WithRsa = seq(oid('1.2.840.113549.1.1.11'), NULL);
  const name = seq(set(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(commonName, 'utf8')))));
  // Positive and minimally encoded: a leading 0x00 byte followed by a byte
  // below 0x80 is DER "illegal padding", which OpenSSL rejects.
  const serial = randomBytes(16);
  serial[0] = (serial[0] & 0x7f) | 0x40;
  const now = Date.now();
  const validity = seq(time(new Date(now - 24 * 3600_000)), time(new Date(now + 365 * 24 * 3600_000)));
  const san = seq(
    oid('2.5.29.17'),
    tlv(0x04, seq(...dnsNames.map((n) => tlv(0x82, Buffer.from(n, 'ascii'))))),
  );
  const basicConstraints = seq(oid('2.5.29.19'), tlv(0x04, seq()));
  const tbs = seq(
    tlv(0xa0, integer(Buffer.from([2]))), // v3
    integer(serial),
    sha256WithRsa,
    name,
    validity,
    name,
    spki,
    tlv(0xa3, seq(san, basicConstraints)),
  );
  const signature = sign('sha256', tbs, privateKey);
  const certDer = seq(tbs, sha256WithRsa, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const cert = toPem('CERTIFICATE', certDer);
  // Parse once so a DER mistake fails loudly here instead of as a TLS alert.
  new X509Certificate(cert);
  const key = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { key, cert };
}
