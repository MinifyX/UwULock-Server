// Moving in from Vaultwarden, for real: a Vaultwarden filled the way people fill it — Bitwarden's
// own CLI for items, folders, attachments and Sends, the API for what the CLI cannot do
// (registering, an organisation, two-step login, emergency access) — then, after
// `uwulock-server import-vaultwarden`, the same accounts against UwULock: a device's old refresh
// token still works, the CLI logs in with the old password and finds everything as it was.
//
//   node scripts/e2e/vaultwarden.mjs seed  <vaultwarden url> <state file>
//   node scripts/e2e/vaultwarden.mjs check <uwulock url>     <state file>
//
// Needs `bw` on the PATH (or its path in BW: the newest CLI may want more than Vaultwarden has) and, for a certificate from a test CA, NODE_EXTRA_CA_CERTS.

import { execFileSync } from 'node:child_process';
import {
  constants,
  createCipheriv,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  pbkdf2Sync,
  publicEncrypt,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [phase, server, stateFile] = process.argv.slice(2);
if (!stateFile || !['seed', 'check'].includes(phase)) {
  console.error('usage: vaultwarden.mjs seed|check <server> <state file>');
  process.exit(2);
}

const ITERATIONS = 600000;
const step = (text) => console.log(`== ${text}`);
function fail(text) {
  console.error(`FAILED: ${text}`);
  process.exit(1);
}

// ── Bitwarden's crypto, with Node's own ─────────────────
function masterKey(email, password) {
  return pbkdf2Sync(password, email.trim().toLowerCase(), ITERATIONS, 32, 'sha256');
}
const passwordHash = (key, password) => pbkdf2Sync(key, password, 1, 32, 'sha256').toString('base64');
const expand = (key, info) =>
  createHmac('sha256', key).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();

function encrypt(plain, key) {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  const mac = createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, data])).digest();
  return `2.${iv.toString('base64')}|${data.toString('base64')}|${mac.toString('base64')}`;
}

function wrapFor(publicDer, key) {
  const publicKey = createPublicKey({ key: Buffer.from(publicDer, 'base64'), format: 'der', type: 'spki' });
  const wrapped = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, key);
  return `4.${wrapped.toString('base64')}`;
}

function keyPair(under) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    encryptedPrivateKey: encrypt(privateKey.export({ type: 'pkcs8', format: 'der' }), under),
  };
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(bytes) {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return bits.match(/.{1,5}/g).map((chunk) => BASE32[parseInt(chunk.padEnd(5, '0'), 2)]).join('');
}
function unbase32(text) {
  const bits = [...text].map((char) => BASE32.indexOf(char).toString(2).padStart(5, '0')).join('');
  return Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
}
function totp(secret, step = Math.floor(Date.now() / 30000)) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', unbase32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// ── The API ─────────────────────────────────────────────
async function api(method, path, token, body) {
  const response = await fetch(`${server}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  if (!response.ok) fail(`${method} ${path}: HTTP ${response.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

async function token(form) {
  const response = await fetch(`${server}/identity/connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const text = await response.text();
  if (!response.ok) fail(`token (${form.grant_type}): HTTP ${response.status} ${text}`);
  return JSON.parse(text);
}

const login = (account, device) =>
  token({
    grant_type: 'password',
    username: account.email,
    password: account.hash,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: device,
    deviceName: 'e2e',
  });

async function register(email, password) {
  const key = masterKey(email, password);
  const userKey = randomBytes(64);
  const keys = keyPair(userKey);
  const response = await fetch(`${server}/identity/accounts/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email.split('@')[0],
      masterPasswordHash: passwordHash(key, password),
      masterPasswordHint: null,
      key: encrypt(userKey, Buffer.concat([expand(key, 'enc'), expand(key, 'mac')])),
      kdf: 0,
      kdfIterations: ITERATIONS,
      keys,
    }),
  });
  if (!response.ok) fail(`registering ${email}: HTTP ${response.status} ${await response.text()}`);
  return { email, password, hash: passwordHash(key, password), userKey: userKey.toString('base64'), publicKey: keys.publicKey };
}

// ── Bitwarden's CLI ─────────────────────────────────────
function cli() {
  const home = mkdtempSync(join(tmpdir(), 'bw-'));
  const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: home };
  const bw = (...args) => execFileSync(process.env.BW || 'bw', ['--nointeraction', ...args], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  bw('config', 'server', server);
  return {
    bw,
    login(email, password, ...extra) {
      env.BW_SESSION = bw('login', email, password, '--raw', ...extra);
      bw('sync');
    },
    json: (...args) => JSON.parse(bw(...args)),
    create: (kind, value) => JSON.parse(bw('create', kind, Buffer.from(JSON.stringify(value)).toString('base64'))),
    done: () => rmSync(home, { recursive: true, force: true }),
  };
}

function item(fields) {
  return {
    organizationId: null,
    collectionIds: null,
    folderId: null,
    type: 1,
    notes: null,
    favorite: false,
    fields: [],
    login: null,
    secureNote: null,
    card: null,
    identity: null,
    reprompt: 0,
    ...fields,
  };
}

// ── Filling Vaultwarden ─────────────────────────────────
async function seed() {
  step('two accounts');
  const nyu = await register('nyu@example.com', 'correct horse battery staple');
  const mio = await register('mio@example.com', 'purple monkey dishwasher');
  const device = randomUUID();
  const session = await login(nyu, device);
  // Kept for later: after the move, this device should still be logged in with it.
  nyu.device = device;
  nyu.refreshToken = session.refresh_token;

  step('an organisation with a collection');
  const orgKey = randomBytes(64);
  const org = await api('POST', '/api/organizations', session.access_token, {
    name: 'Familie',
    billingEmail: nyu.email,
    collectionName: encrypt(Buffer.from('Gemeinsam'), orgKey),
    key: wrapFor(nyu.publicKey, orgKey),
    keys: keyPair(orgKey),
    planType: 0,
  });

  step('two-step login for the second account');
  mio.totp = base32(randomBytes(20));
  const mioSession = await login(mio, randomUUID());
  await api('POST', '/api/two-factor/authenticator', mioSession.access_token, {
    key: mio.totp,
    token: totp(mio.totp),
    masterPasswordHash: mio.hash,
  });

  step('emergency access from one to the other');
  await api('POST', '/api/emergency-access/invite', session.access_token, { email: mio.email, type: 0, waitTimeDays: 7 });
  const [trusted] = (await api('GET', '/api/emergency-access/trusted', session.access_token)).data;
  // Without mail, Vaultwarden takes the invitation as accepted at once.
  if (trusted.status !== 1) fail(`the emergency access is ${trusted.status}, not accepted`);
  await api('POST', `/api/emergency-access/${trusted.id}/confirm`, session.access_token, {
    key: wrapFor(mio.publicKey, Buffer.from(nyu.userKey, 'base64')),
  });

  step("items, a folder, an attachment and Sends, with Bitwarden's CLI");
  const { bw, login: cliLogin, json, create, done } = cli();
  const files = mkdtempSync(join(tmpdir(), 'vw-files-'));
  try {
    cliLogin(nyu.email, nyu.password);
    const folder = create('folder', { name: 'Arbeit' });
    const router = create(
      'item',
      item({
        name: 'Router',
        folderId: folder.id,
        favorite: true,
        notes: 'im Keller',
        login: { username: 'admin', password: 'hunter2', totp: null, uris: [{ uri: 'https://router.example.com', match: null }] },
      }),
    );
    create('item', item({ type: 2, name: 'Notiz', notes: 'geheim', secureNote: { type: 0 } }));
    const [collection] = json('list', 'org-collections', '--organizationid', org.id);
    const shared = create(
      'item',
      item({
        name: 'WLAN',
        organizationId: org.id,
        collectionIds: [collection.id],
        login: { username: 'gast', password: 'wlan-passwort', totp: null, uris: [] },
      }),
    );
    writeFileSync(join(files, 'anhang.txt'), 'Anhang aus Vaultwarden ✧\n');
    bw('create', 'attachment', '--file', join(files, 'anhang.txt'), '--itemid', router.id);
    const text = JSON.parse(bw('send', '-n', 'Grüße', '--password', 'miau', 'Hallo aus Vaultwarden')).accessUrl;
    writeFileSync(join(files, 'datei.txt'), 'Eine Datei per Send\n');
    const file = JSON.parse(bw('send', '-n', 'Datei', '-f', join(files, 'datei.txt'))).accessUrl;
    bw('sync');
    const count = json('list', 'items').length;
    writeFileSync(
      stateFile,
      JSON.stringify(
        { nyu, mio, org: org.id, folder: folder.id, router: router.id, shared: shared.id, count, sends: { text, file }, source: server },
        null,
        2,
      ),
    );
  } finally {
    done();
    rmSync(files, { recursive: true, force: true });
  }
  console.log(`seeded ${server}`);
}

// ── After the move ──────────────────────────────────────
async function check() {
  const state = JSON.parse(readFileSync(stateFile, 'utf8'));
  const { nyu, mio } = state;

  step("a device stays logged in with Vaultwarden's refresh token");
  const refreshed = await token({ grant_type: 'refresh_token', client_id: 'web', refresh_token: nyu.refreshToken });
  if (!refreshed.access_token || refreshed.refresh_token === nyu.refreshToken) fail('a new token for the old one');
  const sync = await api('GET', '/api/sync', refreshed.access_token);
  const organizations = sync.profile.organizations;
  if (organizations.length !== 1 || organizations[0].id !== state.org || !organizations[0].key) fail('the organisation');
  if (sync.collections.length !== 1) fail('the collection');
  if (sync.ciphers.length !== state.count) fail(`${sync.ciphers.length} items, not ${state.count}`);
  if (sync.sends.length !== 2) fail('the Sends');
  const router = sync.ciphers.find((cipher) => cipher.id === state.router);
  if (!router?.favorite || router.folderId !== state.folder || router.attachments?.length !== 1) fail('the router');
  const shared = sync.ciphers.find((cipher) => cipher.id === state.shared);
  if (shared?.organizationId !== state.org || shared.collectionIds?.length !== 1) fail('the shared item');
  const trusted = (await api('GET', '/api/emergency-access/trusted', refreshed.access_token)).data;
  if (trusted.length !== 1 || trusted[0].status !== 2) fail('the emergency access');

  step("Bitwarden's CLI, with the old password");
  const { bw, login: cliLogin, json, done } = cli();
  const files = mkdtempSync(join(tmpdir(), 'uwu-files-'));
  try {
    cliLogin(nyu.email, nyu.password);
    if (json('list', 'items').length !== state.count) fail('the items, in the CLI');
    const item = json('get', 'item', state.router);
    if (item.login.password !== 'hunter2' || item.notes !== 'im Keller') fail('the router, decrypted');
    if (json('get', 'folder', state.folder).name !== 'Arbeit') fail('the folder, decrypted');
    if (json('get', 'item', state.shared).login.password !== 'wlan-passwort') fail('the shared item, decrypted');
    bw('get', 'attachment', 'anhang.txt', '--itemid', state.router, '--output', join(files, 'anhang.txt'));
    if (readFileSync(join(files, 'anhang.txt'), 'utf8') !== 'Anhang aus Vaultwarden ✧\n') fail('the attachment');

    step('the Sends, at their new address');
    const moved = (url) => url.replace(state.source, server);
    if (bw('receive', '--password', 'miau', moved(state.sends.text)) !== 'Hallo aus Vaultwarden') fail('the text Send');
    bw('receive', moved(state.sends.file), '--output', join(files, 'datei.txt'));
    if (readFileSync(join(files, 'datei.txt'), 'utf8') !== 'Eine Datei per Send\n') fail('the file Send');

    step('again, now that the password is hashed anew');
    bw('logout');
    cliLogin(nyu.email, nyu.password);
  } finally {
    done();
    rmSync(files, { recursive: true, force: true });
  }

  step('two-step login came along');
  const second = cli();
  try {
    let refused = false;
    try {
      second.bw('login', mio.email, mio.password, '--raw');
    } catch {
      refused = true;
    }
    if (!refused) fail('a login without the second step');
    // The step Vaultwarden saw is used up; the next one is as good as the current one.
    second.login(mio.email, mio.password, '--method', '0', '--code', totp(mio.totp, Math.floor(Date.now() / 30000) + 1));
  } finally {
    second.done();
  }
  console.log('everything came over');
}

await (phase === 'seed' ? seed() : check());
