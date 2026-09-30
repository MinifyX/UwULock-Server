// What Stufe 6's second part brought, in a real browser, against a running UwULock Server with a
// registered admin account: a send domain (`send.localhost`, which Chromium sends to this machine
// like `localhost`) added in the admin portal, a text and a file Send whose links use it and open
// there, and masked addresses from a UwUMail server this script plays — connecting through OAuth,
// an address made in the web vault, a key for the Bitwarden apps' generator used the way they use
// it, and disconnecting.
//
//   node scripts/e2e/domains.mjs <origin> <email> <password> [screenshot directory]
//
// The origin has to be on `localhost`: the send domain is `send.localhost` on the same port.
// Leaves the server as it found it: no send domain, no UwUMail server listed.

import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import http from 'node:http';
import { chromium } from 'playwright';
import { checkA11y } from './axe.mjs';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: domains.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });
const main = new URL(origin);
if (main.hostname !== 'localhost') {
  console.error('domains.mjs needs the server on localhost, for send.localhost beside it');
  process.exit(2);
}
const sendHost = `send.localhost${main.port ? `:${main.port}` : ''}`;

/**
 * A UwUMail server with the `maskedemail` scope, as far as the Lock server uses it: discovery,
 * registration of public clients, the code flow with PKCE (the person agrees at once), rotating
 * refresh tokens, revocation, and JMAP `MaskedEmail/get` and `/set`.
 */
function uwumail() {
  let base = '';
  const clients = new Set();
  const codes = new Map();
  const access = new Set();
  const refresh = new Set();
  const addresses = [];
  const revoked = [];
  let next = 0;
  const id = (prefix) => `${prefix}${++next}`;
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const tokens = () => {
    const pair = { access_token: id('access-'), refresh_token: id('refresh-') };
    access.add(pair.access_token);
    refresh.add(pair.refresh_token);
    return { ...pair, token_type: 'Bearer', expires_in: 3600, scope: 'maskedemail' };
  };
  const bearer = (req) => access.has((req.headers.authorization ?? '').replace(/^Bearer /, ''));
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      const url = new URL(req.url, base);
      const form = () => Object.fromEntries(new URLSearchParams(raw));
      if (url.pathname === '/.well-known/oauth-authorization-server') {
        return json(res, 200, {
          issuer: base,
          authorization_endpoint: `${base}/oauth/authorize`,
          token_endpoint: `${base}/oauth/token`,
          registration_endpoint: `${base}/oauth/register`,
          revocation_endpoint: `${base}/oauth/revoke`,
          scopes_supported: ['openid', 'mail', 'maskedemail'],
          code_challenge_methods_supported: ['S256'],
        });
      }
      if (url.pathname === '/oauth/register') {
        const client = id('client-');
        clients.add(client);
        return json(res, 201, { client_id: client, token_endpoint_auth_method: 'none' });
      }
      if (url.pathname === '/oauth/authorize') {
        const q = Object.fromEntries(url.searchParams);
        if (!clients.has(q.client_id) || q.scope !== 'maskedemail' || q.code_challenge_method !== 'S256') {
          return json(res, 400, { error: 'invalid_request' });
        }
        const code = id('code-');
        codes.set(code, q);
        const back = new URL(q.redirect_uri);
        back.search = new URLSearchParams({ code, state: q.state, iss: base }).toString();
        res.writeHead(302, { location: back.toString() });
        return res.end();
      }
      if (url.pathname === '/oauth/token') {
        const f = form();
        if (!clients.has(f.client_id)) return json(res, 401, { error: 'invalid_client' });
        if (f.grant_type === 'authorization_code') {
          const asked = codes.get(f.code);
          codes.delete(f.code);
          const challenge = createHash('sha256').update(f.code_verifier ?? '').digest('base64url');
          if (!asked || asked.code_challenge !== challenge || asked.redirect_uri !== f.redirect_uri) {
            return json(res, 400, { error: 'invalid_grant' });
          }
          return json(res, 200, tokens());
        }
        if (f.grant_type === 'refresh_token' && refresh.delete(f.refresh_token)) return json(res, 200, tokens());
        return json(res, 400, { error: 'invalid_grant' });
      }
      if (url.pathname === '/oauth/revoke') {
        revoked.push(form().token);
        refresh.delete(form().token);
        res.writeHead(200);
        return res.end();
      }
      if (url.pathname === '/jmap/session') {
        if (!bearer(req)) return json(res, 401, {});
        const capability = 'https://www.fastmail.com/dev/maskedemail';
        return json(res, 200, {
          capabilities: { 'urn:ietf:params:jmap:core': {}, [capability]: {} },
          accounts: {
            a1: {
              name: 'nyu@example.com',
              accountCapabilities: {
                [capability]: { domains: ['masked.example.com', 'example.com'], defaultDomain: 'masked.example.com' },
              },
            },
          },
          primaryAccounts: { [capability]: 'a1' },
          username: 'nyu@example.com',
          apiUrl: `${base}/jmap/api`,
          state: 's1',
        });
      }
      if (url.pathname === '/jmap/api') {
        if (!bearer(req)) return json(res, 401, {});
        const [method, args] = JSON.parse(raw).methodCalls[0];
        let answer = { accountId: 'a1' };
        if (method === 'MaskedEmail/get') {
          answer.list = args.ids ? addresses.filter((a) => args.ids.includes(a.id)) : [...addresses].reverse();
          answer.notFound = [];
        } else if (method === 'MaskedEmail/set') {
          for (const [key, create] of Object.entries(args.create ?? {})) {
            const address = {
              id: id('x'),
              email: `quiet.otter${next}@${create.domain ?? 'masked.example.com'}`,
              state: create.state ?? 'pending',
              forDomain: create.forDomain ?? '',
              description: create.description ?? '',
              url: create.url ?? null,
              createdAt: new Date().toISOString(),
              lastMessageAt: null,
              createdBy: 'OAuth:UwULock',
            };
            addresses.push(address);
            answer.created = { ...answer.created, [key]: address };
          }
          for (const [key, patch] of Object.entries(args.update ?? {})) {
            const address = addresses.find((a) => a.id === key);
            if (address) Object.assign(address, patch);
            answer.updated = { ...answer.updated, [key]: null };
          }
        } else {
          return json(res, 200, { methodResponses: [['error', { type: 'forbidden' }, '0']] });
        }
        return json(res, 200, { methodResponses: [[method, answer, '0']], sessionState: 's1' });
      }
      json(res, 404, { error: 'not_found' });
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve({ url: base, addresses, revoked, close: () => server.close() });
    }),
  );
}

const fake = await uwumail();
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(' ') : [],
});
const problems = [];

async function open(name) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 800 },
    locale: 'de-DE',
    permissions: ['clipboard-read', 'clipboard-write'],
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => problems.push(`${name}: page error: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
      problems.push(`${name}: console: ${message.text()}`);
    }
  });
  return page;
}

let shot = 0;
const snap = async (page, name) => {
  if (shots) await page.screenshot({ path: `${shots}/d${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

const nyu = await open('nyu');

/** Log in or unlock on the page as it is, and wait for the vault. */
async function unlockHere() {
  await nyu.getByRole('heading', { name: /Anmelden|gesperrt/ }).first().waitFor({ timeout: 30000 });
  if (await nyu.getByLabel('E-Mail-Adresse').isVisible()) await nyu.getByLabel('E-Mail-Adresse').fill(email);
  await nyu.locator('input[type=password]').first().fill(password);
  await nyu.keyboard.press('Enter');
  await nyu.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

async function unlock() {
  await nyu.goto(origin);
  await unlockHere();
}

async function copiedLink(page) {
  await page.getByRole('button', { name: 'Link kopieren' }).click();
  return page.evaluate(() => navigator.clipboard.readText());
}

async function downloaded(page, click) {
  const [file] = await Promise.all([page.waitForEvent('download'), click()]);
  const chunks = [];
  for await (const chunk of await file.createReadStream()) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

/** The admin portal's list of UwUMail servers: the fake one, or none. */
async function maskedServer(on) {
  await nyu.goto(`${origin}/admin#/vault/masked`);
  await nyu.getByRole('heading', { name: 'UwUMail-Server für maskierte Adressen' }).waitFor({ timeout: 30000 });
  if (on) {
    await nyu.getByRole('button', { name: 'UwUMail-Server hinzufügen' }).click();
    const card = nyu.locator('.channel-card').filter({ has: nyu.getByLabel('Name, wie ihn Nutzer sehen') }).last();
    await card.getByLabel('Adresse', { exact: true }).fill(fake.url);
    await card.getByLabel('Name, wie ihn Nutzer sehen').fill('UwUMail Test');
    await card.getByRole('button', { name: 'Prüfen' }).click();
    await nyu.getByText('In Ordnung ✧ Konten können sich damit verbinden.').waitFor();
  } else {
    const remove = nyu
      .locator('.channel-card')
      .filter({ has: nyu.getByLabel('Name, wie ihn Nutzer sehen') })
      .getByRole('button', { name: 'Entfernen' });
    await remove.first().waitFor({ timeout: 5000 }).catch(() => undefined);
    if (!(await remove.count())) return;
    while (await remove.count()) await remove.first().click();
  }
  // Changed settings wait in the bar at the foot of the page.
  await nyu.getByRole('region', { name: 'Ungespeicherte Änderungen' }).getByRole('button', { name: 'Speichern' }).click();
  await nyu.getByText(/Gespeichert/).first().waitFor();
}

try {
  step('a send domain in the admin portal');
  await unlock();
  await nyu.goto(`${origin}/admin#/vault/send-domains`);
  await nyu.getByRole('heading', { name: 'Send-Domain hinzufügen' }).waitFor({ timeout: 30000 });
  await nyu.getByPlaceholder('send.example.com').fill('https://Send.localhost/');
  await nyu.getByText('Wird als send.localhost gespeichert.').waitFor();
  await nyu.getByRole('radio', { name: 'Proxy davor' }).click();
  await nyu.getByRole('button', { name: 'Hinzufügen' }).click();
  await nyu.getByText('TLS macht der Proxy davor.').waitFor();
  await snap(nyu, 'send-domains');
  await checkA11y(nyu, 'send domains');

  step('a text Send whose link is on the send domain');
  await unlock();
  const sidebar = nyu.getByRole('navigation', { name: 'Tresor' });
  await sidebar.getByRole('button', { name: 'Sends' }).click();
  await nyu.getByRole('button', { name: 'Text', exact: true }).click();
  const editor = nyu.locator('.modal');
  await editor.getByLabel('Name', { exact: true }).fill('Paket');
  await editor.getByLabel('Text', { exact: true }).fill('Abholcode 4711');
  await editor.getByLabel('Adresse des Links').selectOption({ label: sendHost });
  await nyu.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.getByText(/Send angelegt/).waitFor();
  const textLink = await copiedLink(nyu);
  if (!textLink.startsWith(`${main.protocol}//${sendHost}/`) || !textLink.includes('#')) {
    throw new Error(`the link is ${textLink}`);
  }
  const friend = await open('friend');
  await friend.goto(textLink);
  await friend.getByText('Abholcode 4711').waitFor({ timeout: 30000 });
  await snap(friend, 'send-on-domain');
  await checkA11y(friend, 'Send page on a send domain');

  step('a file Send, downloaded from the send domain');
  await nyu.getByRole('button', { name: 'Datei', exact: true }).click();
  await editor.getByLabel('Name', { exact: true }).fill('Zettel');
  await nyu.locator('.modal input[type=file]').setInputFiles({
    name: 'zettel.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Milch, Katzenfutter'),
  });
  await editor.getByLabel('Adresse des Links').selectOption({ label: sendHost });
  await nyu.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.getByText(/Send angelegt/).waitFor({ timeout: 30000 });
  const fileLink = await copiedLink(nyu);
  if (!fileLink.startsWith(`${main.protocol}//${sendHost}/`)) throw new Error(`the link is ${fileLink}`);
  await friend.goto(fileLink);
  const file = await downloaded(friend, () => friend.getByRole('button', { name: 'Herunterladen' }).click());
  if (file !== 'Milch, Katzenfutter') throw new Error(`the Send's file came back as ${file}`);
  // The send domain is no web vault.
  const vault = await friend.goto(`${main.protocol}//${sendHost}/`);
  if (vault?.status() !== 404) throw new Error(`the send domain's / answered ${vault?.status()}`);
  await friend.context().close();

  step('masked addresses: connecting to UwUMail');
  await maskedServer(true);
  await nyu.goto(`${origin}/#/settings/masked`);
  await unlockHere();
  await nyu.getByRole('button', { name: 'Mit UwUMail verbinden' }).click();
  // UwUMail agrees at once and sends the browser back, which then unlocks again.
  await nyu.waitForURL(/result=connected|#\/?$/, { timeout: 30000 }).catch(() => undefined);
  await unlockHere();
  await nyu.getByText('Mit UwUMail verbunden ✧').waitFor({ timeout: 30000 });
  await nyu.getByText('Verbunden ✧', { exact: true }).waitFor({ timeout: 30000 });
  await snap(nyu, 'masked-connected');
  await checkA11y(nyu, 'masked addresses');

  step('an address made in the web vault');
  await nyu.getByRole('button', { name: 'Neue Adresse …' }).click();
  const dialog = nyu.locator('.modal').last();
  await dialog.getByLabel('Für die Website (freiwillig)').fill('https://shop.example.com/login');
  await dialog.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.locator('.settings-content').getByText(/quiet\.otter\d+@masked\.example\.com/).first().waitFor();
  if (fake.addresses.at(-1)?.forDomain !== 'https://shop.example.com') {
    throw new Error(`UwUMail got ${JSON.stringify(fake.addresses.at(-1))}`);
  }
  if (fake.addresses.at(-1)?.state !== 'enabled') throw new Error('the address is not enabled');

  step('a key for the Bitwarden apps, used like addy.io');
  await nyu.getByRole('button', { name: 'Erstellen …' }).click();
  const prompt = nyu.locator('.modal').last();
  await prompt.getByLabel('Name', { exact: true }).fill('Firefox');
  await prompt.locator('input[type=password]').fill(password);
  await prompt.getByRole('button', { name: 'Erstellen' }).click();
  const key = await nyu.locator('.modal').last().locator('code').first().textContent();
  if (!key?.startsWith('uwulock_ma_')) throw new Error(`the key is ${key}`);
  await nyu.getByRole('button', { name: 'Fertig' }).click();
  const made = await fetch(`${origin}/uwu/v1/masked/addy//api/v1/aliases`, {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ domain: 'example.com', description: 'Website: forum.example.org. Generated by Bitwarden.' }),
  });
  const alias = await made.json();
  if (made.status !== 201 || !alias.data?.email?.endsWith('@example.com')) {
    throw new Error(`addy.io answered ${made.status} ${JSON.stringify(alias)}`);
  }

  step('disconnecting');
  await nyu.getByRole('button', { name: 'Trennen …' }).click();
  await nyu.locator('.modal').last().getByRole('button', { name: 'Trennen' }).click();
  await nyu.getByText('Getrennt.').waitFor();
  await nyu.getByRole('button', { name: 'Mit UwUMail verbinden' }).waitFor();
  if (fake.revoked.length !== 1) throw new Error(`UwUMail saw ${fake.revoked.length} revocations`);
} catch (error) {
  await snap(nyu, 'failed').catch(() => undefined);
  problems.push(String(error?.stack ?? error));
} finally {
  // As it was: no UwUMail server, no send domain.
  try {
    await maskedServer(false);
    await nyu.goto(`${origin}/admin#/vault/send-domains`);
    await nyu.getByRole('heading', { name: 'Send-Domain hinzufügen' }).waitFor({ timeout: 30000 });
    const remove = nyu.getByRole('button', { name: 'Löschen …' });
    await remove.first().waitFor({ timeout: 5000 }).catch(() => undefined);
    if (await remove.count()) {
      await remove.first().click();
      await nyu.locator('.modal').last().getByRole('button', { name: 'Löschen', exact: true }).click();
      await nyu.getByText('Noch keine Send-Domains.').waitFor();
    }
  } catch (error) {
    problems.push(`cleaning up: ${error?.message ?? error}`);
  }
  await browser.close();
  fake.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('send domains and masked addresses: all good');
