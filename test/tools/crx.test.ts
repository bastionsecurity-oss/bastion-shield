// Tests for tools/lib/crx.ts: extension-id derivation (known vector), CRX3
// signing/verification round trip, tamper detection and update.xml output.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  createCrx3,
  crxIdBytes,
  extensionIdFromBase64Key,
  extensionIdFromSpki,
  idFromBytes,
  pbParse,
  spkiDer,
  updateXml,
  verifyCrx3,
} from '../../tools/lib/crx.ts';
import { createZip, readZip } from '../../tools/lib/zip.ts';

// Public key of Brave's "Local Data Files Updater" component, whose id
// afalakplffnnnlkncjhbmahjfjhmlkal is hard-coded in brave-core
// (local_data_files_service: kLocalDataFilesComponentId). The key ships in
// brave/brave-core-crx-packager manifests/local-data-files-updater.
const BRAVE_LOCAL_DATA_FILES_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4TIQXRCftLpGmQZxmm6AU8pqGKLoDyi537HGQyRKcK7j/CSXCf3vwJr7xkV72p7bayutuzyNZ3740QxBPiesfBOp8bBb8d2VgTHP3b+SuNmK/rsSRsMRhT05x8AAr/7ab6U3rW0Gsalm2653xnnQS8vt0s62xQTmC+UMXowaSLUZ0Be/TOu6lHZhOeo0NBMKc6PkOu0R1EEfP7dJR6SM/v4dBUBZ1HXcuziVbCXVyU51opZCMjlxyUlQR9pTGk+Zh5sDn1Vw1MwLnWiEfQ4EGL1V7GeI4vgLoOLgq7tmhEratHGCfC1IHm9luMACRr/ybMI6DQJOvgBvecb292FxQIDAQAB';

test('extension id from a known public key (Brave component vector)', () => {
  assert.equal(extensionIdFromBase64Key(BRAVE_LOCAL_DATA_FILES_KEY), 'afalakplffnnnlkncjhbmahjfjhmlkal');
});

test('id alphabet maps nibbles 0-f to a-p', () => {
  assert.equal(idFromBytes(Buffer.from('00ff0123456789abcdef', 'hex')), 'aappabcdefghijklmnop');
  assert.equal(idFromBytes(new Uint8Array(16)).length, 32);
});

// A CRX produced by Chromium 156.0.8078.4 itself (`chrome --pack-extension`)
// for a two-file extension, signed with a throwaway key whose private part was
// discarded. tools/lib/crx.ts re-signing the same archive with that key gave a
// byte-identical file (checked when this fixture was made); here we verify that
// our reader/verifier accepts genuine Chromium output and derives the same id.
const CHROMIUM_PACKED_CRX =
  'Q3IyNAMAAABFAgAAEqwECqYCMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzFK7U30MQQYUD2oft0dOAy7QyH9heyUS' +
  'own6JaQJ7XGhzmEoVwxCMudrm5+5c0jHRf8Ln9rU8k9t8VEbKED5ZV3QWsMR6Y6e++HybIm/lKbfwqrGidr4tT+8yoD5nlGzEoGo' +
  '7EEBHg6knoIEyeAX2OsLf5lf5TmTz1C52keXyV7D2linKoAHVUjYUTl5Y+EoqTkkSAqTJjPEW7CBvlRfRcdf8t1UOdO0tH6Fk8Ia' +
  'xTBLbdcroftpi5V+wvznSb6TztdFrdofNV5MEAGFxNd2v7jVWHDOApZi3PXMc0WK45QlwbnJ5jz3mr7ISo6xQ8C7Ai5MZoDMF6I/' +
  'zg+sR5YPMwIDAQABEoACM5ybTMZO/Iyq3+smWaqIzXEXAzfYkb93idiakvYw5pIXOwgBu4trgoxMfS12LYYh96ZmIWwMpOF7Xdqe' +
  'ibDHGcOqZEk1KMYSNcuOTWVB9F6sixFeZNNa0+MkuETkANsBjQAvtZjo8vwmmv+N0agWqu9NgGm4GIB3Ty7T1o3UTDJIsQ1hDa4h' +
  'mZHH0/GtrGetgfOl1YlU+MoqWlJR7PmRqjLv99cBF0ehMyNqfglk/pl9alq0YBc5q0aKvIIr7XiG/2L+yYUbO1Hkmy9CwKMA6Y02' +
  'iQxXunmKGooxQ/RIeXvHb55hnpptBFEp2NxWvcl217yehzcKaxxsM5gzZhCKXoLxBBIKEDRyPvlhANdZchTaZwoioyNQSwMELQAA' +
  'CAgADGFSXXp6b+0FAAAAAwAAAAUAFABhLnR4dAEAEAAAAAAAAAAAAAAAAAAAAAAAy8jkAgBQSwMELQAACAgADGFSXfLq24UsAAAA' +
  'MQAAAA0AFABtYW5pZmVzdC5qc29uAQAQAAAAAAAAAAAAAAAAAAAAAACrVspNzMtMSy0uiS9LLSrOzM9TsjLWUcpLzE1VslIqUdJR' +
  'ggsrGeoZKNUCAFBLAQIAABQAAAgIAAxhUl16em/tBQAAAAMAAAAFAAAAAAAAAAEAAAAAAAAAAABhLnR4dFBLAQIAABQAAAgIAAxh' +
  'Ul3y6tuFLAAAADEAAAANAAAAAAAAAAEAAAAAADwAAABtYW5pZmVzdC5qc29uUEsFBgAAAAACAAIAbgAAAKcAAAAAAA==';

test('verifies a CRX3 packed by Chromium itself', () => {
  const v = verifyCrx3(Buffer.from(CHROMIUM_PACKED_CRX, 'base64'));
  assert.equal(v.id, 'dehcdopjgbaanhfjhcbenkghakcckdcd');
  const files = readZip(v.zip);
  assert.deepEqual([...files.keys()].sort(), ['a.txt', 'manifest.json']);
  assert.equal(files.get('a.txt')!.toString().trim(), 'hi');
  // The id is also derivable from the embedded public key.
  const crx = Buffer.from(CHROMIUM_PACKED_CRX, 'base64');
  const header = pbParse(crx.subarray(12, 12 + crx.readUInt32LE(8)));
  const proof = pbParse(header.find((f) => f.field === 2)!.data);
  assert.equal(extensionIdFromSpki(proof.find((f) => f.field === 1)!.data), v.id);
});

function rsaKey(): { pem: string } {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  return { pem: privateKey };
}

test('CRX3 round trip: header layout, signature, id, embedded zip', () => {
  const { pem } = rsaKey();
  const zip = createZip([
    { name: 'manifest.json', data: Buffer.from('{"manifest_version":3,"name":"t","version":"1.0"}') },
    { name: 'a/b.txt', data: Buffer.from('hello hello hello hello') },
  ]);
  const { crx, id, publicKeyBase64 } = createCrx3(zip, pem);
  assert.equal(crx.subarray(0, 4).toString('ascii'), 'Cr24');
  assert.equal(crx.readUInt32LE(4), 3);
  const headerLen = crx.readUInt32LE(8);
  assert.ok(crx.subarray(12 + headerLen).equals(zip), 'archive follows the header unchanged');

  // Header: one sha256_with_rsa proof (field 2) + signed_header_data (field 10000).
  const fields = pbParse(crx.subarray(12, 12 + headerLen));
  assert.deepEqual(fields.map((f) => f.field), [2, 10000]);
  const signed = pbParse(fields[1].data);
  assert.equal(signed[0].field, 1);
  assert.equal(signed[0].data.length, 16);
  const spki = spkiDer(pem);
  assert.ok(signed[0].data.equals(crxIdBytes(spki)), 'crx_id = sha256(SPKI)[0..16)');
  // Tag for field 10000, wire type 2 is the varint 80002 = 82 f1 04.
  const header = crx.subarray(12, 12 + headerLen);
  assert.ok(header.includes(Buffer.from([0x82, 0xf1, 0x04])));

  assert.equal(id, extensionIdFromSpki(spki));
  assert.equal(extensionIdFromBase64Key(publicKeyBase64), id);
  const v = verifyCrx3(crx);
  assert.equal(v.id, id);
  assert.equal(readZip(v.zip).get('a/b.txt')?.toString(), 'hello hello hello hello');
});

test('CRX3 verification rejects a modified archive', () => {
  const { pem } = rsaKey();
  const zip = createZip([{ name: 'manifest.json', data: Buffer.from('{}') }]);
  const { crx } = createCrx3(zip, pem);
  const tampered = Buffer.from(crx);
  tampered[tampered.length - 30] ^= 0xff;
  assert.throws(() => verifyCrx3(tampered), /signature/);
  assert.throws(() => verifyCrx3(Buffer.from('PK\x03\x04')), /magic/);
});

test('update.xml uses the gupdate format and escapes attributes', () => {
  const xml = updateXml({ id: 'abcdefghijklmnopabcdefghijklmnop', version: '0.1.0.2900', codebase: "https://u.example/x.crx?a=1&b='2'", minChromeVersion: '128' });
  assert.match(xml, /^<\?xml version='1.0' encoding='UTF-8'\?>/);
  assert.match(xml, /<gupdate xmlns='http:\/\/www.google.com\/update2\/response' protocol='2.0'>/);
  assert.match(xml, /<app appid='abcdefghijklmnopabcdefghijklmnop'>/);
  assert.match(xml, /codebase='https:\/\/u.example\/x.crx\?a=1&amp;b=&apos;2&apos;'/);
  assert.match(xml, /version='0.1.0.2900' prodversionmin='128'/);
});
