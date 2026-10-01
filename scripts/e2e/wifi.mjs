// Wi-Fi networks and the one-vault account menu, in a real browser, against a running UwULock
// Server with a registered account: a network made in the editor (Enterprise fields only for
// Enterprise), its details and QR code, the filter, and an account menu without "Add account".
// Screenshots in light and dark, on a desktop and a phone.
//
//   node scripts/e2e/wifi.mjs <origin> <email> <password> [screenshot directory]

import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: wifi.mjs <origin> <email> <password> [screenshot directory]');
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
  if (shots) await page.screenshot({ path: `${shots}/wifi-${name}.png` });
};

try {
  const { context, page } = await open('light', { width: 1280, height: 860 });

  step('a new Wi-Fi network: Enterprise fields only for Enterprise');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'WLAN' }).click();
  await page.getByLabel('Netzwerkname (SSID)').fill('campus');
  if ((await page.getByLabel('Name', { exact: true }).inputValue()) !== 'campus') {
    throw new Error('the name does not follow the SSID');
  }
  if (await page.getByLabel('EAP-Methode').count()) throw new Error('EAP shown for WPA2');
  await page.getByLabel('Sicherheit').selectOption('WPA2-Enterprise');
  await page.getByLabel('EAP-Methode').selectOption('PEAP');
  await page.getByLabel('Identität', { exact: true }).fill('nyu@example.com');
  await page.getByLabel('WLAN-Passwort').fill('correct; horse');
  await snap(page, 'editor-enterprise');
  await page.getByRole('button', { name: 'Speichern' }).click();

  step('a personal one, with the generator');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'WLAN' }).click();
  await page.getByLabel('Netzwerkname (SSID)').fill('uwu-net');
  await page.getByRole('button', { name: 'Passwort-Generator' }).click();
  await page.locator('.modal').last().getByRole('button', { name: /Übernehmen|Verwenden/ }).click();
  await page.getByLabel('Verstecktes Netzwerk (sendet seinen Namen nicht)').check();
  await snap(page, 'editor');
  await page.getByRole('button', { name: 'Speichern' }).click();

  step('the details, the filter and the QR code');
  await page.locator('.item-list').getByText('uwu-net').first().click();
  await page.getByRole('button', { name: 'Als QR-Code teilen' }).waitFor();
  await page.getByRole('navigation').getByRole('button', { name: /^WLAN/ }).click();
  await snap(page, 'details');
  await page.getByRole('button', { name: 'Als QR-Code teilen' }).click();
  await page.locator('[data-wifi-qr] svg').waitFor();
  await page.locator('.modal').getByRole('button', { name: 'Passwort zeigen' }).click();
  await snap(page, 'qr');
  await page.locator('.modal').getByRole('button', { name: 'Fertig' }).click();

  step('the account menu: this vault only');
  await page.locator('.account-switch').click();
  const entries = await page.getByRole('menuitem').allInnerTexts();
  if (entries.some((e) => /hinzufügen|wechseln|umbenennen/i.test(e))) {
    throw new Error(`the account menu offers another account: ${entries.join(', ')}`);
  }
  await snap(page, 'account-menu');
  await page.keyboard.press('Escape');
  await context.close();

  for (const [scheme, viewport, name] of [
    ['dark', { width: 1280, height: 860 }, 'dark'],
    ['light', { width: 390, height: 844 }, 'phone'],
    ['dark', { width: 390, height: 844 }, 'phone-dark'],
  ]) {
    step(`${name}`);
    const other = await open(scheme, viewport);
    await other.page.locator('.item-list').getByText('campus').first().click();
    await other.page.getByRole('button', { name: 'Als QR-Code teilen' }).waitFor();
    await snap(other.page, `${name}-details`);
    await other.page.getByRole('button', { name: 'Bearbeiten' }).click();
    await other.page.getByLabel('EAP-Methode').waitFor();
    await snap(other.page, `${name}-editor`);
    await other.page.getByRole('button', { name: 'Abbrechen' }).click();
    await other.page.getByRole('button', { name: 'Als QR-Code teilen' }).click();
    await other.page.locator('[data-wifi-qr] svg').waitFor();
    await snap(other.page, `${name}-qr`);
    await other.context.close();
  }

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('Wi-Fi in the browser: all good');
} finally {
  await browser.close();
}
