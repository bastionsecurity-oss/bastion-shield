// Uploads and submits a release package to the Chrome Web Store (API v2) or
// to Microsoft Edge Add-ons (Update REST API v1.1). Used by release.yml; can
// also be run by hand. Credentials come from the environment only and are
// never printed.
//
//   node .github/scripts/store-publish.ts cws  --zip <file> [--skip-review true|false] [--dry-run]
//   node .github/scripts/store-publish.ts edge --zip <file> [--notes <text>] [--dry-run]
//
// CWS:  CWS_CLIENT_ID, CWS_CLIENT_SECRET, CWS_REFRESH_TOKEN, CWS_PUBLISHER_ID, CWS_ITEM_ID
//       https://developer.chrome.com/docs/webstore/using-api
// Edge: EDGE_CLIENT_ID, EDGE_API_KEY, EDGE_PRODUCT_ID
//       https://learn.microsoft.com/microsoft-edge/extensions/update/api/using-addons-api
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFileSync, statSync } from 'node:fs';

const CWS_API = 'https://chromewebstore.googleapis.com';
const EDGE_API = 'https://api.addons.microsoftedge.microsoft.com';
const POLL_INTERVAL_MS = 10_000;
const POLL_TIMEOUT_MS = 15 * 60_000;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`environment variable ${name} is not set`);
  return v;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** fetch with a timeout and a few retries on network errors, 429 and 5xx. */
async function request(url: string, init: RequestInit, what: string): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(120_000) });
      if (res.status !== 429 && res.status < 500) return res;
      lastError = new Error(`${what}: HTTP ${res.status} ${await safeText(res)}`);
    } catch (e) {
      lastError = e;
    }
    if (attempt < 4) {
      const wait = 2 ** attempt * 1000;
      console.warn(`${what} failed (attempt ${attempt}), retrying in ${wait / 1000}s`);
      await sleep(wait);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 2000);
  } catch {
    return '';
  }
}

async function expectOk(res: Response, what: string): Promise<unknown> {
  const text = await safeText(res);
  if (!res.ok) throw new Error(`${what}: HTTP ${res.status} ${text}`);
  try {
    return text ? (JSON.parse(text) as unknown) : {};
  } catch {
    return { raw: text };
  }
}

function readZip(path: string): Uint8Array {
  const size = statSync(path).size;
  if (size === 0) throw new Error(`${path} is empty`);
  console.log(`Package ${path} (${(size / 1024 / 1024).toFixed(2)} MB)`);
  return new Uint8Array(readFileSync(path));
}

// ---------------------------------------------------------------------------
// Chrome Web Store, API v2
// ---------------------------------------------------------------------------

async function cwsToken(): Promise<string> {
  const body = new URLSearchParams({
    client_id: env('CWS_CLIENT_ID'),
    client_secret: env('CWS_CLIENT_SECRET'),
    refresh_token: env('CWS_REFRESH_TOKEN'),
    grant_type: 'refresh_token',
  });
  const res = await request('https://oauth2.googleapis.com/token', { method: 'POST', body }, 'OAuth token');
  const json = (await expectOk(res, 'OAuth token')) as { access_token?: string };
  if (!json.access_token) throw new Error('OAuth token response has no access_token');
  return json.access_token;
}

interface CwsUpload {
  uploadState?: string;
  crxVersion?: string;
}

async function publishCws(zipPath: string, skipReview: boolean, dryRun: boolean): Promise<void> {
  const name = `publishers/${env('CWS_PUBLISHER_ID')}/items/${env('CWS_ITEM_ID')}`;
  const zip = readZip(zipPath);
  if (dryRun) {
    console.log(`[dry run] would upload to ${name} and publish (skipReview=${skipReview})`);
    return;
  }
  const token = await cwsToken();
  const auth = { Authorization: `Bearer ${token}` };

  const up = await request(`${CWS_API}/upload/v2/${name}:upload`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/zip' }, body: zip }, 'CWS upload');
  let state = (await expectOk(up, 'CWS upload')) as CwsUpload;
  console.log(`CWS upload state: ${state.uploadState ?? '?'} ${state.crxVersion ?? ''}`);
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  // The docs name the pending state both IN_PROGRESS and UPLOAD_IN_PROGRESS.
  while (state.uploadState === 'IN_PROGRESS' || state.uploadState === 'UPLOAD_IN_PROGRESS') {
    if (Date.now() > deadline) throw new Error('CWS upload still in progress after 15 minutes');
    await sleep(POLL_INTERVAL_MS);
    const st = await request(`${CWS_API}/v2/${name}:fetchStatus`, { headers: auth }, 'CWS fetchStatus');
    const json = (await expectOk(st, 'CWS fetchStatus')) as { lastAsyncUploadState?: string };
    state = { uploadState: json.lastAsyncUploadState };
    console.log(`CWS upload state: ${state.uploadState ?? '?'}`);
  }
  if (state.uploadState !== 'SUCCEEDED') throw new Error(`CWS upload ended in state ${state.uploadState ?? 'unknown'}`);

  const publish = async (skip: boolean): Promise<Response> =>
    request(`${CWS_API}/v2/${name}:publish`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ publishType: 'DEFAULT_PUBLISH', skipReview: skip }) }, 'CWS publish');

  let res = await publish(skipReview);
  if (!res.ok && skipReview && res.status >= 400 && res.status < 500) {
    // The store validates eligibility itself; fall back to a normal review.
    console.warn(`CWS rejected skipReview (HTTP ${res.status}: ${await safeText(res)}); submitting for normal review`);
    res = await publish(false);
  }
  const result = (await expectOk(res, 'CWS publish')) as { state?: string; warningInfo?: { warnings?: { reason?: string; description?: string }[] } };
  console.log(`CWS submission state: ${result.state ?? '?'}`);
  for (const w of result.warningInfo?.warnings ?? []) console.warn(`CWS warning ${w.reason ?? ''}: ${w.description ?? ''}`);
}

// ---------------------------------------------------------------------------
// Microsoft Edge Add-ons, Update REST API v1.1
// ---------------------------------------------------------------------------

function operationId(res: Response): string {
  const loc = res.headers.get('location') ?? '';
  // Documented as "Location: {operationID}"; accept a full URL too.
  const id = loc.split('/').filter(Boolean).pop();
  if (!id) throw new Error('Edge API response has no Location header with an operation id');
  return id;
}

/** Polls an Edge operation until it succeeds, or fails with one of the tolerated error codes. */
async function edgePoll(url: string, headers: Record<string, string>, what: string, tolerated: string[] = []): Promise<{ status?: string; errorCode?: string }> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    const res = await request(url, { headers }, what);
    const json = (await expectOk(res, what)) as { status?: string; message?: string; errorCode?: string; errors?: unknown };
    console.log(`${what}: ${json.status ?? '?'} ${json.message ?? ''}`);
    if (json.status === 'Succeeded') return json;
    if (json.status === 'Failed' && json.errorCode && tolerated.includes(json.errorCode)) return json;
    if (json.status === 'Failed') throw new Error(`${what} failed: ${json.errorCode ?? ''} ${json.message ?? ''} ${JSON.stringify(json.errors ?? null)}`);
    if (Date.now() > deadline) throw new Error(`${what} still in progress after 15 minutes`);
    await sleep(POLL_INTERVAL_MS);
  }
}

async function publishEdge(zipPath: string, notes: string, dryRun: boolean): Promise<void> {
  const product = env('EDGE_PRODUCT_ID');
  const zip = readZip(zipPath);
  if (dryRun) {
    console.log(`[dry run] would upload to Edge product ${product} and submit for certification`);
    return;
  }
  const headers = { Authorization: `ApiKey ${env('EDGE_API_KEY')}`, 'X-ClientID': env('EDGE_CLIENT_ID') };
  const base = `${EDGE_API}/v1/products/${product}/submissions`;

  const up = await request(`${base}/draft/package`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/zip' }, body: zip }, 'Edge upload');
  if (up.status !== 202) throw new Error(`Edge upload: HTTP ${up.status} ${await safeText(up)}`);
  await edgePoll(`${base}/draft/package/operations/${operationId(up)}`, headers, 'Edge package upload');

  const pub = await request(base, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ notes }) }, 'Edge publish');
  if (pub.status !== 202) throw new Error(`Edge publish: HTTP ${pub.status} ${await safeText(pub)}`);
  // Certification can take longer than our weekly cadence. If the previous
  // version is still in review, this package stays as the draft and the next
  // run submits a newer one: expected, not an error.
  const result = await edgePoll(`${base}/operations/${operationId(pub)}`, headers, 'Edge submission', ['InProgressSubmission']);
  if (result.errorCode === 'InProgressSubmission') {
    console.log('::warning::Edge Add-ons: the previous submission is still in certification; this package stays as draft and the next release supersedes it.');
    return;
  }
  console.log('Edge: submitted for certification (Microsoft documents up to 7 business days).');
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const store = process.argv[2];
  const zip = arg('--zip');
  const dryRun = process.argv.includes('--dry-run');
  if ((store !== 'cws' && store !== 'edge') || !zip) {
    console.error('usage: node .github/scripts/store-publish.ts cws|edge --zip <file> [--skip-review true|false] [--notes <text>] [--dry-run]');
    process.exit(2);
  }
  if (store === 'cws') await publishCws(zip, arg('--skip-review') === 'true', dryRun);
  else {
    const notes = arg('--notes') ?? 'Automated weekly update of the bundled filter lists. Source code and build inputs: https://github.com/bastion-security/bastion-shield';
    await publishEdge(zip, notes, dryRun);
  }
}

main().catch((e: unknown) => {
  console.error(`::error::${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
