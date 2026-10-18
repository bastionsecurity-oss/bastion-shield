// Bastion Shield — CRX3 packaging for self-hosted (Intune) deployments.
// Format (components/crx_file/crx3.proto):
//
//   "Cr24" | uint32le 3 | uint32le header_size | CrxFileHeader | ZIP
//   CrxFileHeader { repeated AsymmetricKeyProof sha256_with_rsa = 2;
//                   bytes signed_header_data = 10000 }  // = SignedData { bytes crx_id = 1 }
//   AsymmetricKeyProof { bytes public_key = 1 (SPKI DER); bytes signature = 2 }
//   signature = RSASSA-PKCS1-v1_5/SHA-256 over
//     "CRX3 SignedData\x00" | uint32le len(signed_header_data) | signed_header_data | ZIP
//
// The extension id is the first 16 bytes of SHA-256(SPKI DER) written as
// hex with digits mapped 0-f -> a-p (components/crx_file/id_util.cc).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { createHash, createPublicKey, createSign, createVerify, type KeyObject } from 'node:crypto';

const MAGIC = Buffer.from('Cr24', 'ascii');
const SIGNED_DATA_PREFIX = Buffer.from('CRX3 SignedData\x00', 'binary');

// --- protobuf (just the wire types we need) --------------------------------

function varint(n: number): Buffer {
  const out: number[] = [];
  let v = n;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return Buffer.from(out);
}

/** Length-delimited field (wire type 2). */
function pbBytes(field: number, data: Uint8Array): Buffer {
  return Buffer.concat([varint(field * 8 + 2), varint(data.length), Buffer.from(data)]);
}

function readVarint(buf: Buffer, pos: number): [number, number] {
  let result = 0;
  let mul = 1;
  for (let i = 0; i < 10; i++) {
    const b = buf[pos++];
    if (b === undefined) throw new Error('truncated varint');
    result += (b & 0x7f) * mul;
    if ((b & 0x80) === 0) return [result, pos];
    mul *= 128;
  }
  throw new Error('varint too long');
}

/** Parse length-delimited fields only (all CRX3 fields are bytes / messages). */
export function pbParse(buf: Buffer): { field: number; data: Buffer }[] {
  const out: { field: number; data: Buffer }[] = [];
  let p = 0;
  while (p < buf.length) {
    const [tag, p1] = readVarint(buf, p);
    const wire = tag & 7;
    const field = Math.floor(tag / 8);
    if (wire === 2) {
      const [len, p2] = readVarint(buf, p1);
      out.push({ field, data: buf.subarray(p2, p2 + len) });
      p = p2 + len;
    } else if (wire === 0) {
      p = readVarint(buf, p1)[1];
    } else if (wire === 5) {
      p = p1 + 4;
    } else if (wire === 1) {
      p = p1 + 8;
    } else {
      throw new Error(`unsupported wire type ${wire}`);
    }
  }
  return out;
}

// --- ids ---------------------------------------------------------------------

export function spkiDer(key: KeyObject | string | Buffer): Buffer {
  const pub = createPublicKey(key);
  return pub.export({ type: 'spki', format: 'der' }) as Buffer;
}

/** First 16 bytes of SHA-256 of the SPKI DER. */
export function crxIdBytes(spki: Uint8Array): Buffer {
  return createHash('sha256').update(spki).digest().subarray(0, 16);
}

/** Chromium extension id ("a"-"p" alphabet) from raw id bytes. */
export function idFromBytes(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(97 + (b >> 4), 97 + (b & 15));
  return s;
}

export function extensionIdFromSpki(spki: Uint8Array): string {
  return idFromBytes(crxIdBytes(spki));
}

/** For manifest "key" / CWS public keys given as base64 SPKI. */
export function extensionIdFromBase64Key(b64: string): string {
  return extensionIdFromSpki(Buffer.from(b64, 'base64'));
}

// --- CRX3 ----------------------------------------------------------------------

export function createCrx3(zip: Uint8Array, privateKeyPem: string | Buffer): { crx: Buffer; id: string; publicKeyBase64: string } {
  const spki = spkiDer(privateKeyPem);
  const crxId = crxIdBytes(spki);
  const signedHeaderData = pbBytes(1, crxId); // SignedData { crx_id }
  const len = Buffer.alloc(4);
  len.writeUInt32LE(signedHeaderData.length, 0);
  const signer = createSign('sha256');
  signer.update(SIGNED_DATA_PREFIX);
  signer.update(len);
  signer.update(signedHeaderData);
  signer.update(zip);
  const signature = signer.sign(privateKeyPem);
  const proof = Buffer.concat([pbBytes(1, spki), pbBytes(2, signature)]);
  const header = Buffer.concat([pbBytes(2, proof), pbBytes(10000, signedHeaderData)]);
  const fixed = Buffer.alloc(12);
  MAGIC.copy(fixed, 0);
  fixed.writeUInt32LE(3, 4);
  fixed.writeUInt32LE(header.length, 8);
  return { crx: Buffer.concat([fixed, header, Buffer.from(zip)]), id: idFromBytes(crxId), publicKeyBase64: spki.toString('base64') };
}

export interface CrxVerification {
  id: string;
  zip: Buffer;
}

/** Verify a CRX3 the way Chromium does for a developer-signed file. Throws on failure. */
export function verifyCrx3(crx: Buffer): CrxVerification {
  if (crx.length < 12 || !crx.subarray(0, 4).equals(MAGIC)) throw new Error('not a CRX file (magic)');
  if (crx.readUInt32LE(4) !== 3) throw new Error(`unsupported CRX version ${crx.readUInt32LE(4)}`);
  const headerSize = crx.readUInt32LE(8);
  const header = crx.subarray(12, 12 + headerSize);
  const zip = crx.subarray(12 + headerSize);
  const fields = pbParse(header);
  const signed = fields.find((f) => f.field === 10000)?.data;
  if (!signed) throw new Error('missing signed_header_data');
  const crxId = pbParse(signed).find((f) => f.field === 1)?.data;
  if (!crxId || crxId.length !== 16) throw new Error('missing crx_id');
  const len = Buffer.alloc(4);
  len.writeUInt32LE(signed.length, 0);
  let idMatched = false;
  for (const f of fields.filter((x) => x.field === 2)) {
    const parts = pbParse(f.data);
    const pk = parts.find((x) => x.field === 1)?.data;
    const sig = parts.find((x) => x.field === 2)?.data;
    if (!pk || !sig) throw new Error('incomplete RSA proof');
    const v = createVerify('sha256');
    v.update(SIGNED_DATA_PREFIX);
    v.update(len);
    v.update(signed);
    v.update(zip);
    const key = createPublicKey({ key: pk, format: 'der', type: 'spki' });
    if (!v.verify(key, sig)) throw new Error('RSA signature does not verify');
    if (crxIdBytes(pk).equals(crxId)) idMatched = true;
  }
  if (!idMatched) throw new Error('no proof matches crx_id');
  return { id: idFromBytes(crxId), zip: Buffer.from(zip) };
}

/** gupdate manifest served at update_url (Chrome / Edge self-hosting). */
export function updateXml(opts: { id: string; version: string; codebase: string; minChromeVersion?: string }): string {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const min = opts.minChromeVersion ? ` prodversionmin='${esc(opts.minChromeVersion)}'` : '';
  return (
    `<?xml version='1.0' encoding='UTF-8'?>\n` +
    `<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n` +
    `  <app appid='${esc(opts.id)}'>\n` +
    `    <updatecheck codebase='${esc(opts.codebase)}' version='${esc(opts.version)}'${min} />\n` +
    `  </app>\n` +
    `</gupdate>\n`
  );
}
