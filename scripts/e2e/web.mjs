// The web vault and the admin portal in a real browser, against a running UwULock Server:
// register from an invitation link, save an item, reload and unlock, set up two-step login and
// log in with a code, then the admin portal — invite, users, settings, events, log, backups.
//
//   node scripts/e2e/web.mjs <invitation link> [screenshot directory]
//
// Needs `playwright` (npm) and a Chromium it can start. The server's certificate may be one no
// browser trusts: this test does not check it.

import { createHmac } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const [link, shots] = process.argv.slice(2);
if (!link) {
  console.error('usage: web.mjs <invitation link> [screenshot directory]');
  process.exit(2);
}
const origin = new URL(link).origin;
const email = new URL(link.replace('/#/', '/')).searchParams.get('email');
const password = 'correct horse battery staple';
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width: 1280, height: 800 },
  locale: 'de-DE',
  permissions: ['clipboard-read', 'clipboard-write'],
});
const page = await context.newPage();
const problems = [];
page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
// A refused request shows up in the console too; the ones this test causes on purpose (a login
// that asks for its second step) are not problems.
page.on('console', (message) => {
  if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
    problems.push(`console: ${message.text()}`);
  }
});

let shot = 0;
const snap = async (name) => {
  if (shots) await page.screenshot({ path: `${shots}/${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

/** The authenticator code of `key` for the 30-second step `offset` steps from now. */
function totp(key, offset = 0) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of key.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const secret = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const hash = createHmac('sha1', secret).update(counter).digest();
  const at = hash[hash.length - 1] & 0xf;
  return String((hash.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

async function unlockOrLogin() {
  const passwordField = page.locator('input[type=password]').first();
  await passwordField.waitFor();
  await passwordField.fill(password);
  await page.keyboard.press('Enter');
}

try {
  step('register from the invitation link');
  await page.goto(link);
  await page.getByRole('heading', { name: 'Konto anlegen' }).waitFor();
  await page.getByLabel('Name', { exact: true }).fill('Nyu');
  const fields = page.locator('input[type=password]');
  await fields.nth(0).fill(password);
  await fields.nth(1).fill(password);
  await snap('register');
  await page.getByRole('button', { name: 'Konto anlegen' }).click();
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
  await snap('empty-vault');

  step('a login item');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Login' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Router');
  await page.getByLabel('Benutzername').fill('admin');
  await page.getByLabel('Passwort', { exact: true }).fill('hunter2');
  await snap('editor');
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.item-list').getByText('Router').first().waitFor();
  await snap('item-saved');

  step('reload: the vault is locked, and opens again');
  await page.reload();
  await page.getByRole('heading', { name: /gesperrt/ }).waitFor();
  await snap('locked');
  await unlockOrLogin();
  await page.locator('.item-list').getByText('Router').first().waitFor({ timeout: 30000 });

  step('the settings');
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  for (const section of ['Konto', 'Geräte', 'Import & Export', 'Zwei-Schritt-Anmeldung']) {
    await page.getByRole('navigation').getByRole('button', { name: section }).click();
    await page.waitForTimeout(300);
    await snap(`settings-${section.toLowerCase().replace(/\W+/g, '-')}`);
  }

  step('two-step login with an authenticator app');
  await page.getByRole('button', { name: 'Einrichten …' }).first().click();
  await page.locator('.modal input[type=password]').fill(password);
  await page.getByRole('button', { name: 'Weiter' }).click();
  const key = (await page.locator('.secret-key').innerText()).replace(/\s/g, '');
  await page.getByLabel('Code aus der App').fill(totp(key));
  await snap('authenticator');
  await page.getByRole('button', { name: 'Einschalten' }).click();
  await page.getByText('Die Authenticator-App ist eingerichtet').waitFor();
  await page.keyboard.press('Escape');

  step('log out, and in again with a code');
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await page.getByRole('navigation').getByRole('button', { name: 'Konto' }).click();
  await page.getByRole('button', { name: 'Abmelden', exact: true }).click();
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor();
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await unlockOrLogin();
  await page.getByRole('heading', { name: 'Zweistufige Anmeldung' }).waitFor({ timeout: 30000 });
  await page.getByLabel('Code').fill(totp(key, 1));
  await snap('two-factor-prompt');
  await page.getByRole('button', { name: 'Weiter' }).click();
  await page.locator('.item-list').getByText('Router').first().waitFor({ timeout: 30000 });

  step('two-step login off again');
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await page.getByRole('navigation').getByRole('button', { name: 'Zwei-Schritt-Anmeldung' }).click();
  await page.getByRole('button', { name: 'Ausschalten …' }).first().click();
  await page.locator('.modal input[type=password]').fill(password);
  await page.getByRole('button', { name: 'Ausschalten', exact: true }).click();
  await page.getByText('Ausgeschaltet.').waitFor();
  await page.keyboard.press('Escape');

  step('the admin portal');
  await page.goto(`${origin}/admin`);
  await page.getByRole('heading', { name: 'Übersicht' }).waitFor({ timeout: 30000 });
  await snap('admin-overview');
  await page.getByRole('button', { name: 'Einladungen' }).click();
  await page.getByLabel('E-Mail-Adresse').fill('mika@example.com');
  await page.getByRole('button', { name: 'Einladen' }).click();
  await page.locator('.invite-link').waitFor();
  await snap('admin-invited');
  for (const name of ['Nutzer', 'Einstellungen', 'Ereignisse', 'Log', 'Backups']) {
    await page.getByRole('navigation').getByRole('button', { name }).click();
    await page.getByRole('heading', { name, exact: true }).waitFor();
    await page.waitForTimeout(400);
    await snap(`admin-${name.toLowerCase()}`);
  }
  await page.getByRole('button', { name: 'Jetzt ein Backup schreiben' }).click();
  await page.getByRole('button', { name: 'Herunterladen' }).first().waitFor();

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('web vault and admin portal: all good');
} catch (error) {
  await snap('failed');
  console.error(`FAILED: ${error.message}`);
  if (problems.length) console.error(problems.join('\n'));
  process.exitCode = 1;
} finally {
  await browser.close();
}
