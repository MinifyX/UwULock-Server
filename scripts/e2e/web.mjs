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
import { checkA11y } from './axe.mjs';

const [link, shots] = process.argv.slice(2);
if (!link) {
  console.error('usage: web.mjs <invitation link> [screenshot directory]');
  process.exit(2);
}
const origin = new URL(link).origin;
const email = new URL(link.replace('/#/', '/')).searchParams.get('email');
const password = 'correct horse battery staple';
if (shots) mkdirSync(shots, { recursive: true });

// CHROMIUM_ARGS can make the browser trust a test certificate for real (for WebAuthn, which
// refuses a site whose certificate is only waved through): --ignore-certificate-errors-spki-list.
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(' ') : [],
});
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
  await checkA11y(page, 'register page');
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
  await checkA11y(page, 'vault with an item selected');

  step('the keyboard: shortcut overview, the new-item menu, the list');
  await page.locator('.item-list').focus();
  await page.keyboard.press('?');
  await page.getByRole('dialog', { name: 'Tastenkürzel' }).waitFor();
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'detached' });
  if (!(await page.locator('.item-list').evaluate((list) => list === document.activeElement)))
    throw new Error('focus did not come back to the list after the overview');
  await page.keyboard.press('n');
  await page.getByRole('menuitem', { name: 'Login' }).waitFor();
  await page.keyboard.press('Escape');
  await page.getByRole('menu').waitFor({ state: 'detached' });
  if (!(await page.locator('.item-list').evaluate((list) => list === document.activeElement)))
    throw new Error('focus did not come back to the list after the menu');

  step('reload: the vault is locked, and opens again');
  await page.reload();
  await page.getByRole('heading', { name: /gesperrt/ }).waitFor();
  await snap('locked');
  await unlockOrLogin();
  await page.locator('.item-list').getByText('Router').first().waitFor({ timeout: 30000 });

  step('several items at once: archive and back');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Sichere Notiz' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Notiz');
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.item-list').getByText('Notiz').first().waitFor();
  // Ticked with the mouse (the box on the row) and with the keyboard (Space in the list).
  await page.locator('.item-row', { hasText: 'Router' }).locator('.item-check').click();
  await page.locator('.item-list').focus();
  await page.locator('.item-row', { hasText: 'Notiz' }).click();
  await page.locator('.item-list').press('Space');
  await page.getByText('2 ausgewählt').waitFor();
  await snap('bulk-selected');
  await page.getByRole('toolbar').getByRole('button', { name: 'Archivieren' }).click();
  const sidebar = page.getByRole('navigation', { name: 'Tresor' });
  await sidebar.getByRole('button', { name: /^Archiv/ }).click();
  for (const name of ['Router', 'Notiz'])
    await page.locator('.item-row', { hasText: name }).locator('.item-check').click();
  await page.getByRole('toolbar').getByRole('button', { name: 'Aus dem Archiv holen' }).click();
  await sidebar.getByRole('button', { name: /^Alle Einträge/ }).click();
  await page.locator('.item-list').getByText('Router').first().waitFor();

  step('the settings');
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await checkA11y(page, 'settings dialog');
  // Once in the light theme too, then back.
  await page.getByRole('radio', { name: 'Hell' }).click();
  await page.locator('html[data-theme="light"]').waitFor({ state: 'attached' });
  await checkA11y(page, 'settings dialog, light theme');
  await page.getByRole('radio', { name: 'Dunkel' }).click();
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
  await checkA11y(page, 'login page');
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
  // Both switches are security notices now, under Sicherheit.
  await page.getByRole('navigation').getByRole('button', { name: /^Sicherheit/ }).click();
  await page.getByText(/Zwei-Schritt-Anmeldung ausgeschaltet/).first().waitFor();
  await page.getByText(/Zwei-Schritt-Anmeldung eingeschaltet/).first().waitFor();
  await snap('security-notices');
  await page.keyboard.press('Escape');

  step('the admin portal');
  await page.goto(`${origin}/admin`);
  await page.getByRole('heading', { name: 'Übersicht' }).waitFor({ timeout: 30000 });
  await snap('admin-overview');
  await checkA11y(page, 'admin overview');
  await page.getByRole('button', { name: 'Einladungen' }).click();
  await page.getByLabel('E-Mail-Adresse').fill('mika@example.com');
  await page.getByRole('button', { name: 'Einladen' }).click();
  await page.locator('.invite-link').waitFor();
  await snap('admin-invited');
  for (const name of ['Nutzer', 'Einstellungen', 'Benachrichtigungen', 'Ereignisse', 'Log', 'Backups']) {
    await page.getByRole('navigation').getByRole('button', { name }).click();
    await page.getByRole('heading', { name, exact: true }).waitFor();
    await page.waitForTimeout(400);
    await snap(`admin-${name.toLowerCase()}`);
    if (name === 'Nutzer' || name === 'Einstellungen') await checkA11y(page, `admin ${name}`);
  }

  step('the admin portal by keyboard, and in high contrast');
  // "6" is the sixth page of the bar: Aussehen, the branding.
  await page.keyboard.press('6');
  await page.getByRole('heading', { name: 'Aussehen', exact: true }).waitFor();
  if (!page.url().endsWith('#/branding')) throw new Error(`6 led to ${page.url()}`);
  await page.getByRole('button', { name: 'Darstellung' }).click();
  await page.getByRole('radio', { name: 'Hoch' }).click();
  await page.locator('html[data-contrast="high"]').waitFor({ state: 'attached' });
  await page.keyboard.press('Escape');
  await checkA11y(page, 'admin branding, high contrast');
  await snap('admin-branding-high-contrast');
  await page.getByRole('button', { name: 'Darstellung' }).click();
  await page.getByRole('radiogroup', { name: 'Kontrast' }).getByRole('radio', { name: 'System' }).click();
  await page.keyboard.press('Escape');
  // Back to the backups: the ninth page.
  await page.keyboard.press('9');
  await page.getByRole('heading', { name: 'Backups', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Jetzt ein Backup schreiben' }).click();
  await page.getByRole('button', { name: 'Herunterladen' }).first().click();
  // A backup is the whole database: it takes the master password, and a wrong one gets nothing.
  await page.locator('.modal input[type=password]').fill('not the password');
  await page.locator('.modal').getByRole('button', { name: 'Herunterladen' }).click();
  await page.locator('.modal .form-error').waitFor();
  await page.locator('.modal input[type=password]').fill(password);
  const [backup] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('.modal').getByRole('button', { name: 'Herunterladen' }).click(),
  ]);
  if (!/^uwulock-.*\.db$/.test(backup.suggestedFilename()))
    throw new Error(`the backup came as ${backup.suggestedFilename()}`);

  step('the diagnosis, with the browser checks against this server');
  await page.getByRole('navigation').getByRole('button', { name: 'Diagnose' }).click();
  await page.getByRole('button', { name: 'Diagnose starten' }).click();
  // The WebSocket goes through, and 16 MB are taken: no proxy is in front here.
  for (const id of ['proxy.websocket', 'proxy.uploadLimit']) {
    await page
      .locator(`.check-card[data-status="ok"]`)
      .filter({ hasText: id === 'proxy.websocket' ? 'WebSockets' : 'Upload' })
      .first()
      .waitFor({ timeout: 60000 });
  }
  await snap('admin-diagnosis');

  step('a backup goes back while the server runs');
  await page.getByRole('navigation').getByRole('button', { name: 'Einladungen' }).click();
  await page.getByLabel('E-Mail-Adresse').fill('later@example.com');
  await page.getByRole('button', { name: 'Einladen' }).click();
  await page.locator('.admin-table').getByText('later@example.com').waitFor();
  await page.getByRole('navigation').getByRole('button', { name: 'Backups' }).click();
  await page.getByRole('button', { name: 'Zurückspielen' }).first().click();
  await page.locator('.modal input[type=password]').fill(password);
  await page.locator('.modal').getByRole('button', { name: 'Zurückspielen' }).click();
  // Every session ends with it, this one too: the sessions in the backup may have been taken
  // back since.
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await snap('admin-restored');
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await unlockOrLogin();
  // Back where it was, on the backups.
  await page.getByText(/vor dem Zurückspielen/).first().waitFor({ timeout: 30000 });
  await page.getByRole('navigation').getByRole('button', { name: 'Einladungen' }).click();
  await page.locator('.admin-table').getByText('mika@example.com').waitFor();
  if (await page.locator('.admin-table').getByText('later@example.com').count())
    throw new Error('the invitation made after the backup is still there');

  step('on a phone');
  const phone = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
    locale: 'de-DE',
  });
  const mobile = await phone.newPage();
  mobile.on('pageerror', (error) => problems.push(`phone: page error: ${error.message}`));
  const phoneSnap = async (name) => {
    if (shots) await mobile.screenshot({ path: `${shots}/${String(++shot).padStart(2, '0')}-phone-${name}.png` });
  };
  const noSideways = async (where) => {
    const wide = await mobile.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (wide > 0) throw new Error(`${where}: ${wide}px wider than the phone`);
  };
  await mobile.goto(origin);
  await mobile.getByLabel('E-Mail-Adresse').fill(email);
  await mobile.locator('input[type=password]').first().fill(password);
  await mobile.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await mobile.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
  if (await mobile.locator('.sidebar').isVisible()) throw new Error('the sidebar takes the phone');
  await mobile.locator('.bottom-nav').waitFor();
  await noSideways('the list');
  await phoneSnap('list');
  await mobile.locator('.item-row').first().click();
  await mobile.locator('.detail-pane .detail').waitFor();
  if (await mobile.locator('.list-pane').isVisible()) throw new Error('list and item at once');
  await noSideways('an item');
  await phoneSnap('item');
  await mobile.getByRole('button', { name: 'Zurück' }).click();
  await mobile.locator('.list-pane').waitFor();
  await mobile.locator('.bottom-nav').getByRole('button', { name: 'Mehr' }).click();
  await mobile.locator('.sidebar').waitFor();
  await phoneSnap('menu');
  await mobile.locator('.bottom-nav').getByRole('button', { name: 'Sends' }).click();
  await mobile.locator('.list-pane').getByText('Sends').first().waitFor();
  await mobile.locator('.bottom-nav').getByRole('button', { name: 'Alle' }).click();
  await mobile.getByRole('button', { name: 'Neu', exact: true }).click();
  await mobile.getByRole('menuitem', { name: 'Login' }).click();
  await mobile.locator('.modal').getByLabel('Name', { exact: true }).waitFor();
  await noSideways('the editor');
  await phoneSnap('editor');
  await mobile.keyboard.press('Escape');
  await mobile.goto(`${origin}/admin`);
  await mobile.locator('.stat-grid').waitFor({ timeout: 30000 });
  await noSideways('the admin portal');
  await phoneSnap('admin');
  await mobile.getByRole('navigation').getByRole('button', { name: 'Nutzer' }).click();
  await mobile.locator('.admin-table').getByText(email).waitFor();
  await noSideways('the users');
  await phoneSnap('admin-users');
  await phone.close();

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
