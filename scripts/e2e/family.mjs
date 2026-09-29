// A family in the web vault, in a real browser, with two accounts: the admin invites a second
// account to the server; the first makes a family, invites the second, which accepts in its
// vault; the owner compares the fingerprint phrase with the member's own and confirms; an item
// moves into the family's collection — and the member's vault shows it, password and all.
//
//   node scripts/e2e/family.mjs <origin> <email> <password> [screenshot directory]
//
// Afterwards scripts/e2e/bw-family.sh checks the same family with Bitwarden's CLI.

import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: family.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

const MEMBER = 'mio@example.com';
const MEMBER_PASSWORD = 'mio horse battery staple';

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
  if (shots) await page.screenshot({ path: `${shots}/fam${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

async function vault(page, secret) {
  const search = page.getByPlaceholder(/Tresor durchsuchen/);
  await search.waitFor({ timeout: 10000 }).catch(async () => {
    // After a reload the session is there, the keys are not: unlock.
    await page.locator('input[type=password]').first().fill(secret);
    await page.keyboard.press('Enter');
    await search.waitFor({ timeout: 30000 });
  });
}

async function settings(page, section) {
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await page.getByRole('navigation', { name: 'Bereiche' }).getByRole('button', { name: section }).click();
}

const sidebar = (page) => page.getByRole('navigation', { name: 'Tresor' });

const nyu = await open('nyu');
try {
  step('log in, and invite a second account to the server');
  await nyu.goto(origin);
  await nyu.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await nyu.getByLabel('E-Mail-Adresse').fill(email);
  await nyu.locator('input[type=password]').first().fill(password);
  await nyu.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await vault(nyu, password);
  await nyu.goto(`${origin}/admin`);
  await nyu.getByRole('heading', { name: 'Übersicht' }).waitFor({ timeout: 30000 });
  await nyu.getByRole('button', { name: 'Einladungen' }).click();
  await nyu.getByLabel('E-Mail-Adresse').fill(MEMBER);
  await nyu.getByRole('button', { name: 'Einladen' }).click();
  const invitation = (await nyu.locator('.invite-link').innerText()).trim();

  const mio = await open('mio');
  await mio.goto(invitation);
  await mio.getByRole('heading', { name: 'Konto anlegen' }).waitFor({ timeout: 30000 });
  await mio.getByLabel('Name', { exact: true }).fill('Mio');
  const fields = mio.locator('input[type=password]');
  await fields.nth(0).fill(MEMBER_PASSWORD);
  await fields.nth(1).fill(MEMBER_PASSWORD);
  await mio.getByRole('button', { name: 'Konto anlegen' }).click();
  await vault(mio, MEMBER_PASSWORD);

  step('an item of the owner, and a family');
  await nyu.goto(origin);
  await vault(nyu, password);
  await nyu.getByRole('button', { name: 'Neu', exact: true }).click();
  await nyu.getByRole('menuitem', { name: 'Login' }).click();
  const editor = nyu.locator('.modal');
  await editor.getByLabel('Name', { exact: true }).fill('Streaming');
  await editor.getByLabel('Benutzername').fill('katzen@example.com');
  await editor.getByLabel('Passwort', { exact: true }).fill('Miau-2026!');
  await nyu.getByRole('button', { name: 'Speichern' }).click();
  await nyu.locator('.item-list').getByText('Streaming').waitFor();

  await sidebar(nyu).getByRole('button', { name: 'Neue Familie' }).click();
  const made = nyu.getByRole('dialog', { name: 'Neue Familie' });
  await made.getByLabel('Name der Familie').fill('Katzen');
  await made.getByLabel('Erste Sammlung').fill('Allgemein');
  await made.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.getByRole('tab', { name: 'Mitglieder' }).waitFor({ timeout: 30000 });

  step('invite the second account, which accepts in its vault');
  await nyu.getByRole('button', { name: 'Einladen', exact: true }).click();
  const invite = nyu.getByRole('dialog', { name: 'In die Familie einladen' });
  await invite.getByLabel('E-Mail-Adressen').fill(MEMBER);
  await invite.getByLabel('Zugriff auf Allgemein').selectOption('write');
  await invite.getByRole('button', { name: 'Einladen', exact: true }).click();
  await nyu.getByText('Eingeladen ✧').waitFor();
  await snap(nyu, 'invited');

  await mio.reload();
  await vault(mio, MEMBER_PASSWORD);
  await mio.locator('.family-invitation').getByRole('button', { name: 'Annehmen' }).click();
  await mio.getByText(/Angenommen ✧/).waitFor();
  await settings(mio, 'Konto');
  await mio.getByRole('button', { name: 'Anzeigen', exact: true }).click();
  const own = (await mio.locator('.setting-row', { hasText: 'Fingerabdruck' }).locator('.setting-description').innerText()).trim();
  await mio.keyboard.press('Escape');

  step('the owner compares the phrase and confirms');
  await sidebar(nyu).getByRole('button', { name: 'Alle Einträge' }).first().click();
  await sidebar(nyu).getByRole('button', { name: 'Mitglieder & Sammlungen' }).click();
  await nyu.locator('.item-list').getByText('Mio').click();
  await nyu.getByRole('button', { name: 'Bestätigen …' }).click();
  const shown = (await nyu.locator('.modal .fingerprint').innerText()).trim();
  if (shown !== own) throw new Error(`the phrases differ: ${shown} / ${own}`);
  await snap(nyu, 'confirm');
  await nyu.getByRole('button', { name: 'Bestätigen', exact: true }).click();
  await nyu.getByText('Bestätigt ✧').waitFor();

  step('an item moves into the collection');
  await sidebar(nyu).getByRole('button', { name: 'Alle Einträge' }).first().click();
  await nyu.locator('.item-list').getByText('Streaming').click();
  await nyu.getByRole('button', { name: 'In eine Familie verschieben' }).click();
  const move = nyu.getByRole('dialog', { name: 'In eine Familie verschieben' });
  await move.getByLabel('Allgemein').check();
  await move.getByRole('button', { name: 'Verschieben' }).click();
  await nyu.getByText('In die Familie verschoben ✧').waitFor();
  await sidebar(nyu).getByRole('button', { name: /^Allgemein/ }).click();
  await nyu.locator('.item-list').getByText('Streaming').waitFor();

  step('the member sees it, password and all');
  // Live updates bring it; a reload is the fallback.
  const arrived = await mio
    .locator('.item-list')
    .getByText('Streaming')
    .waitFor({ timeout: 15000 })
    .then(() => true, () => false);
  if (!arrived) {
    await mio.reload();
    await vault(mio, MEMBER_PASSWORD);
  }
  await sidebar(mio).getByRole('button', { name: /^Allgemein/ }).click();
  await mio.locator('.item-list').getByText('Streaming').click();
  await mio.getByRole('button', { name: 'Passwort zeigen' }).click();
  await mio.getByText('Miau-2026!').waitFor();
  await snap(mio, 'member-reads');

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('a family: made, invited, accepted, confirmed with the phrase, an item shared and read: all good');
} catch (error) {
  await snap(nyu, 'failed').catch(() => undefined);
  console.error(`FAILED: ${error.message}`);
  if (problems.length) console.error(problems.join('\n'));
  process.exitCode = 1;
} finally {
  await browser.close();
}
