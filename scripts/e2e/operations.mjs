// What Stufe 4b part B brought, in a real browser, against a running UwULock Server with the
// account web.mjs made: a file request — made by its owner, filled in by somebody with nothing
// but the link (in another browser), read and taken over into an item — the emergency sheet as a
// PDF, backups to a folder off-site from the admin portal, with the recovery key shown once, and
// file requests switched off in the Features tab (gone from the vault, 404 for the link) and on
// again, and a refused login on the failed-logins page with an address blocked and lifted.
//
//   node scripts/e2e/operations.mjs <origin> <email> <password> <backup folder> [screenshot directory]
//
// The backup folder must exist, be writable for the server, and lie outside its data directory.

import { mkdirSync, readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { checkA11y } from './axe.mjs';

const [origin, email, password, folder, shots] = process.argv.slice(2);
if (!origin || !email || !password || !folder) {
  console.error('usage: operations.mjs <origin> <email> <password> <backup folder> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

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
    acceptDownloads: true,
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
  if (shots) await page.screenshot({ path: `${shots}/o${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

async function login(page) {
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await page.locator('input[type=password]').first().fill(password);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

/** The text of a download. */
async function downloaded(page, trigger) {
  const [download] = await Promise.all([page.waitForEvent('download'), trigger()]);
  return readFileSync(await download.path());
}

const owner = await open('owner');
try {
  step('log in');
  await login(owner);

  step('a file request, with a password');
  await owner.locator('.sidebar').getByRole('button', { name: 'Datei-Anfragen' }).click();
  await owner.getByRole('button', { name: 'Neu', exact: true }).click();
  await owner.getByLabel('Name (nur für dich)').fill('Ausweis für die Bank');
  await owner.getByLabel('Titel für den Absender').fill('Ausweis-Scan');
  await owner.getByLabel('Hinweis für den Absender (freiwillig)').fill('Bitte beide Seiten.');
  await owner.getByLabel('Passwort (freiwillig)').fill('katzen');
  await owner.getByRole('button', { name: 'Anlegen' }).click();
  await owner.getByRole('heading', { name: 'Ausweis für die Bank' }).waitFor();
  const link = (await owner.locator('.send-link').first().innerText()).trim();
  if (!link.startsWith(`${origin}/#/request/`)) throw new Error(`the link: ${link}`);
  await snap(owner, 'request');
  await checkA11y(owner, 'file requests view');

  step('somebody without an account, with the link on a send domain’s path');
  const [, accessId, secret] = link.match(/#\/request\/([^/]+)\/([^/]+)$/);
  const uploader = await open('uploader');
  await uploader.goto(`${origin}/r/${accessId}#${secret}`);
  await uploader.getByRole('heading', { name: 'Passwort nötig' }).waitFor({ timeout: 30000 });
  await uploader.locator('input[type=password]').fill('falsch');
  await uploader.getByRole('button', { name: 'Öffnen' }).click();
  await uploader.getByText('Das Passwort stimmt nicht.').waitFor();
  await checkA11y(uploader, 'file request page, wrong password');
  await uploader.locator('input[type=password]').fill('katzen');
  await uploader.getByRole('button', { name: 'Öffnen' }).click();
  await uploader.getByRole('heading', { name: 'Ausweis-Scan' }).waitFor();
  await uploader.getByText('Bitte beide Seiten.').waitFor();
  await checkA11y(uploader, 'file request page');
  await uploader.locator('input[type=file]').setInputFiles([
    { name: 'vorne.txt', mimeType: 'text/plain', buffer: Buffer.from('die Vorderseite') },
    { name: 'hinten.txt', mimeType: 'text/plain', buffer: Buffer.from('die Rückseite') },
  ]);
  await uploader.getByLabel('Nachricht (freiwillig)').fill('Hier, wie besprochen.');
  await uploader.getByLabel('Dein Name (freiwillig)').fill('Mika');
  await uploader.getByRole('button', { name: 'Verschlüsselt senden' }).click();
  await uploader.getByRole('heading', { name: 'Angekommen ✧' }).waitFor({ timeout: 30000 });
  await snap(uploader, 'uploaded');
  await uploader.context().close();

  step('the owner reads it, and takes it over into an item');
  // A reload locks the vault: the keys never leave the page's memory.
  await owner.reload();
  await owner.locator('input[type=password]').first().fill(password);
  await owner.keyboard.press('Enter');
  await owner.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
  await owner.locator('.sidebar').getByRole('button', { name: 'Datei-Anfragen' }).click();
  await owner.getByText('Hier, wie besprochen.').waitFor({ timeout: 30000 });
  await owner.getByText(/Absender \(nicht geprüft\): Mika/).first().waitFor();
  const front = await downloaded(owner, () =>
    owner.locator('.detail-row', { hasText: 'vorne.txt' }).getByRole('button', { name: 'Herunterladen' }).click(),
  );
  if (front.toString() !== 'die Vorderseite') throw new Error(`the file: ${front}`);
  await snap(owner, 'arrived');
  await owner.getByRole('button', { name: 'Als Eintrag übernehmen' }).click();
  await owner.getByText('Noch nichts. Du bekommst eine Mail, wenn etwas ankommt.').waitFor({ timeout: 30000 });
  await owner.locator('.sidebar').getByRole('button', { name: 'Alle Einträge' }).click();
  await owner.getByText(/Ausweis-Scan – /).first().click();
  await owner.getByText('hinten.txt').waitFor({ timeout: 30000 });
  await snap(owner, 'taken-over');

  step('the emergency sheet');
  await owner.getByRole('button', { name: /Einstellungen/ }).first().click();
  await owner.getByRole('button', { name: 'Notfallzugriff' }).click();
  await owner.getByRole('button', { name: 'Notfallblatt erstellen' }).click();
  await owner.locator('.modal input[type=password]').fill(password);
  const pdf = await downloaded(owner, () => owner.getByRole('button', { name: 'PDF erstellen' }).click());
  const text = pdf.toString('latin1');
  if (!text.startsWith('%PDF-1.4') || !text.includes(`(${email})`)) throw new Error('the sheet is no PDF of this account');
  await owner.keyboard.press('Escape');

  step('off-site backups to a folder, from the admin portal');
  await owner.goto(`${origin}/admin#/backups/offsite`);
  const card = owner.locator('.offsite');
  await card.waitFor({ timeout: 30000 });
  await card.getByRole('radio', { name: 'Ordner' }).click();
  await card.getByLabel('Ordner (eingehängt, außerhalb der Daten)').fill(folder);
  await card.getByRole('switch', { name: 'Backups außer Haus an' }).click();
  await card.getByRole('button', { name: 'Speichern' }).click();
  // Where the database goes is decided with the master password.
  await owner.locator('.modal input[type=password]').fill(password);
  await owner.locator('.modal').getByRole('button', { name: 'Speichern' }).click();
  const key = (await owner.locator('.recovery-key').innerText({ timeout: 30000 })).trim();
  if (!/^[A-Z2-7]{4}(-[A-Z2-7]{1,4})+$/.test(key)) throw new Error(`the recovery key: ${key}`);
  await snap(owner, 'recovery-key');
  await owner.getByRole('button', { name: 'Ich habe ihn sicher aufgehoben' }).click();
  await card.getByRole('button', { name: 'Verbindung testen' }).click();
  await card.getByText(/Verbindung steht/).waitFor({ timeout: 30000 });
  await card.getByRole('button', { name: 'Jetzt sichern' }).click();
  await card.getByText(/Zuletzt gelungen/).waitFor({ timeout: 60000 });
  await card.getByRole('button', { name: 'Stände am Ziel zeigen' }).click();
  await card.getByRole('button', { name: 'Zurückspielen' }).first().waitFor({ timeout: 30000 });
  await snap(owner, 'offsite');

  step('file requests switched off in the Features tab, and on again');
  await owner.goto(`${origin}/admin#/vault`);
  const requests = owner.getByRole('switch', { name: 'Datei-Anfragen' });
  await requests.waitFor({ timeout: 30000 });
  await checkA11y(owner, 'features tab');
  await requests.click();
  // It is in use: the portal asks first.
  await owner.locator('.modal').getByRole('button', { name: 'Ausschalten' }).click();
  await owner.getByText('„Datei-Anfragen“ ist aus. Nichts wurde gelöscht.').waitFor({ timeout: 30000 });
  await snap(owner, 'features-off');
  const off = await fetch(`${origin}/uwu/v1/public/file-requests/${accessId}`);
  const body = await off.json().catch(() => ({}));
  if (off.status !== 404 || body.code !== 'feature_off') throw new Error(`switched off: ${off.status} ${JSON.stringify(body)}`);
  const info = await (await fetch(`${origin}/uwu/v1/info`)).json();
  if (info.switches?.['file-requests'] !== false) throw new Error(`info: ${JSON.stringify(info.switches)}`);
  const stranger = await open('stranger');
  await stranger.goto(link);
  await stranger.getByRole('heading', { name: 'Nicht auf diesem Server' }).waitFor({ timeout: 30000 });
  await stranger.context().close();
  await owner.goto(origin);
  await owner.locator('input[type=password]').first().fill(password);
  await owner.keyboard.press('Enter');
  await owner.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
  if (await owner.locator('.sidebar').getByRole('button', { name: 'Datei-Anfragen' }).count()) {
    throw new Error('the vault still shows file requests');
  }
  await owner.goto(`${origin}/admin#/vault`);
  await owner.getByRole('switch', { name: 'Datei-Anfragen' }).click();
  await owner.getByText('„Datei-Anfragen“ ist an ✧').waitFor({ timeout: 30000 });
  const on = await fetch(`${origin}/uwu/v1/public/file-requests/${accessId}`);
  if (on.status === 404 && (await on.json().catch(() => ({}))).code === 'feature_off') throw new Error('still off');

  step('a refused login on the failed-logins page, and an address blocked and lifted');
  const refused = await fetch(`${origin}/identity/connect/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'bitwarden-client-name': 'cli',
      'bitwarden-client-version': '2026.9.0',
    },
    body: new URLSearchParams({
      grant_type: 'password',
      username: 'nobody@example.com',
      password: 'd3Jvbmc=',
      scope: 'api offline_access',
      client_id: 'cli',
      deviceType: '8',
      deviceIdentifier: 'e2e-device',
      deviceName: 'e2e-laptop',
    }),
  });
  if (refused.status !== 400) throw new Error(`a wrong login answered ${refused.status}`);
  await owner.goto(`${origin}/admin#/`);
  await owner.locator('.stat-link').click();
  await owner.getByRole('heading', { name: 'Sicherheit & Anmeldung' }).waitFor({ timeout: 30000 });
  const row = owner.locator('tr', { hasText: 'nobody@example.com' }).first();
  await row.getByText('Konto existiert nicht').waitFor({ timeout: 30000 });
  await row.getByRole('button', { name: 'Details' }).click();
  await owner.getByText('e2e-laptop').waitFor();
  await owner.getByText('cli 2026.9.0').waitFor();
  await checkA11y(owner, 'failed logins');
  await snap(owner, 'failed-logins');
  await owner.getByRole('button', { name: 'IP sperren …' }).first().click();
  const dialog = owner.locator('.modal');
  await dialog.getByRole('button', { name: 'Adresse sperren' }).click();
  await dialog.getByText('du würdest dich selbst aussperren').waitFor({ timeout: 30000 });
  await dialog.getByLabel('IP-Adresse oder Netz').fill('203.0.113.9');
  await dialog.getByRole('button', { name: 'Adresse sperren' }).click();
  await dialog.waitFor({ state: 'detached', timeout: 30000 });
  await owner.getByRole('tab', { name: 'Gesperrte Adressen' }).click();
  const blocked = owner.locator('tr', { hasText: '203.0.113.9' });
  await blocked.waitFor({ timeout: 30000 });
  await checkA11y(owner, 'blocked addresses');
  await snap(owner, 'blocked-addresses');
  await blocked.getByRole('button', { name: /Aufheben/ }).click();
  await blocked.waitFor({ state: 'detached', timeout: 30000 });
} catch (error) {
  await snap(owner, 'failed').catch(() => undefined);
  console.error(error);
  problems.push(String(error));
} finally {
  await browser.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('ok');
