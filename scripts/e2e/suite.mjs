// UwUSSH's and UwURDP's entries in the web vault, in a real browser, against a running UwULock
// Server with a registered account and the suite vault switched on: the space made by the web
// vault, an identity with a generated password, an Ed25519 key made in the browser, a host using
// them with its command, the hint when an identity in use is deleted, an RDP host as an .rdp
// file without password or drives, and everything read back after a reload. Screenshots in light
// and dark, on a desktop and a phone.
//
//   node scripts/e2e/suite.mjs <origin> <email> <password> [screenshot directory]

import { mkdirSync, readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: suite.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(' ') : [],
});
const problems = [];
const step = (text) => console.log(`== ${text}`);

async function open(scheme, viewport) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport,
    locale: 'de-DE',
    colorScheme: scheme,
    acceptDownloads: true,
  });
  await context.addInitScript(() => {
    if (!localStorage.getItem('uwulock.settings')) {
      localStorage.setItem('uwulock.settings', JSON.stringify({ theme: 'system' }));
    }
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
      problems.push(`console: ${message.text()}`);
    }
  });
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await page.locator('input[type=password]').first().fill(password);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
  return { context, page };
}

const snap = async (page, name) => {
  if (shots) await page.screenshot({ path: `${shots}/suite-${name}.png` });
};

const section = (page, name) =>
  page.getByRole('navigation').getByRole('button', { name, exact: true }).click();
const tab = (page, name) => page.getByRole('tab', { name: new RegExp(`^${name}`) }).click();
const modal = (page) => page.locator('.modal').first();
const save = async (page) => {
  await modal(page).getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.modal').waitFor({ state: 'detached', timeout: 30000 });
};

try {
  const { context, page } = await open('light', { width: 1280, height: 860 });

  step('SSH: no app synced yet, so the web vault makes the space');
  await section(page, 'SSH (UwUSSH)');
  await page.getByRole('button', { name: 'Bereich anlegen' }).click();
  await page.getByRole('tab', { name: /^Hosts/ }).waitFor({ timeout: 30000 });

  step('an identity with a generated password');
  await tab(page, 'Identitäten');
  await page.getByRole('button', { name: 'Identität', exact: true }).click();
  await modal(page).getByLabel('Name', { exact: true }).fill('Nyu');
  await modal(page).getByLabel('Benutzername').fill('nyu');
  await modal(page).getByRole('button', { name: 'Passwort erzeugen' }).click();
  await page.locator('.modal').last().getByRole('button', { name: /Übernehmen|Verwenden/ }).click();
  await save(page);
  await page.getByRole('button', { name: 'Passwort zeigen' }).click();
  const shown = await page.locator('.detail .detail-row').last().innerText();
  if (shown.includes('••••') || shown.trim().length < 12) throw new Error(`no password shown: ${shown}`);

  step('an Ed25519 key made in the browser');
  await tab(page, 'Schlüssel');
  await page.getByRole('button', { name: 'Schlüssel', exact: true }).click();
  await modal(page).getByLabel('Name', { exact: true }).fill('Laptop');
  await modal(page).getByLabel('Kommentar').fill('nyu@example.com');
  await save(page);
  await page.locator('.detail').getByText(/^ssh-ed25519 AAAA.* nyu@example\.com$/).waitFor();

  step('a host with the identity, its command');
  await tab(page, 'Hosts');
  await page.getByRole('button', { name: 'Host', exact: true }).click();
  await modal(page).getByLabel('Name', { exact: true }).fill('Router');
  await modal(page).getByLabel('Adresse').fill('router.example.com');
  await modal(page).getByLabel('Port', { exact: true }).fill('2222');
  await modal(page).getByLabel('Identität', { exact: true }).selectOption({ label: 'Nyu' });
  await save(page);
  await page.locator('.detail').getByText('ssh -p 2222 nyu@router.example.com').waitFor();
  if (!(await page.getByRole('button', { name: 'In UwUSSH öffnen' }).count()))
    throw new Error('no link into UwUSSH on a desktop');
  await snap(page, 'ssh-host');

  step('an identity in use is not deleted');
  await tab(page, 'Identitäten');
  await page.locator('.detail-tools').getByRole('button', { name: 'Löschen' }).click();
  await modal(page).getByText('Wird noch verwendet').waitFor();
  await modal(page).getByText('Host: Router').waitFor();
  await snap(page, 'in-use');
  await modal(page).getByRole('button', { name: 'Verstanden' }).click();

  step('RDP: a host with a fixed size and a gateway, as an .rdp file');
  await section(page, 'Remote Desktop (UwURDP)');
  await page.getByRole('button', { name: 'Bereich anlegen' }).click();
  await page.getByRole('tab', { name: /^Hosts/ }).waitFor({ timeout: 30000 });
  await page.getByRole('button', { name: 'Host', exact: true }).click();
  await modal(page).getByLabel('Name', { exact: true }).fill('Desk');
  await modal(page).getByLabel('Adresse').fill('desk.example.com');
  await modal(page).getByRole('radio', { name: 'Feste Größe' }).click();
  await modal(page).getByLabel('Breite').fill('1280');
  await modal(page).getByLabel('Höhe').fill('720');
  await modal(page).getByLabel('Über ein Remote-Desktop-Gateway verbinden').check();
  await modal(page).getByLabel('Gateway-Adresse').fill('gw.example.com');
  await snap(page, 'rdp-editor');
  await save(page);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: '.rdp-Datei' }).click(),
  ]);
  const rdp = readFileSync(await download.path(), 'utf8');
  for (const line of ['full address:s:desk.example.com', 'desktopwidth:i:1280', 'redirectdrives:i:0', 'gatewayhostname:s:gw.example.com']) {
    if (!rdp.includes(line)) throw new Error(`the .rdp file lacks ${line}:\n${rdp}`);
  }
  if (/password/i.test(rdp)) throw new Error('the .rdp file carries a password');
  await snap(page, 'rdp-host');
  await context.close();

  for (const [scheme, viewport, name] of [
    ['dark', { width: 1280, height: 860 }, 'dark'],
    ['light', { width: 390, height: 844 }, 'phone'],
  ]) {
    step(`${name}: everything read back from the server`);
    const other = await open(scheme, viewport);
    // A phone shows one layer at a time: the sections are under "Mehr".
    if (viewport.width < 600)
      await other.page.getByRole('navigation', { name: 'Bereiche' }).getByRole('button', { name: 'Mehr' }).click();
    await section(other.page, 'SSH (UwUSSH)');
    await other.page.locator('.item-list').getByText('Router').first().click();
    await other.page.locator('.detail').getByText('ssh -p 2222 nyu@router.example.com').waitFor();
    await snap(other.page, `${name}-host`);
    await other.page.getByRole('button', { name: 'Bearbeiten' }).click();
    await snap(other.page, `${name}-editor`);
    await modal(other.page).getByRole('button', { name: 'Abbrechen' }).click();
    await other.context.close();
  }

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('UwUSSH and UwURDP in the browser: all good');
} finally {
  await browser.close();
}
