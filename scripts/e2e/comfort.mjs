// What Stufe 4c brought, in a real browser, against a running UwULock Server with a registered
// account: an item's earlier version shown and brought back, an own icon uploaded (encrypted in
// the browser), a reminder that is due and the list of due items from the mail's link, the travel
// mode settings, and a key rotation that carries the versions along.
//
//   node scripts/e2e/comfort.mjs <origin> <email> <password> [screenshot directory]

import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: comfort.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(' ') : [],
});
const problems = [];
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width: 1280, height: 800 },
  locale: 'de-DE',
});
const page = await context.newPage();
page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
page.on('console', (message) => {
  // A website icon that is not there is a 404, which the browser reports as a failed resource.
  if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
    problems.push(`console: ${message.text()}`);
  }
});

let shot = 0;
const snap = async (name) => {
  if (shots) await page.screenshot({ path: `${shots}/c${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

async function login() {
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await page.locator('input[type=password]').first().fill(password);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

/** A PNG of 2 × 2 pink pixels. */
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAEUlEQVR4nGN4UbnsPwgzwBgAbAYMGcOwgh8AAAAASUVORK5CYII=',
  'base64',
);

try {
  step('log in');
  await login();

  step('an item, changed once');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Login' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Bank');
  await page.getByLabel('Passwort', { exact: true }).fill('erstes-passwort');
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.item-list').getByText('Bank').first().click();
  await page.getByRole('button', { name: 'Bearbeiten' }).click();
  await page.getByLabel('Passwort', { exact: true }).fill('zweites-passwort');
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.getByRole('button', { name: 'Bearbeiten' }).waitFor();

  step('the version before, shown and brought back');
  await page.getByRole('button', { name: 'Frühere Versionen' }).click();
  await page.getByRole('button', { name: 'Ansehen' }).first().click();
  await page.locator('.modal').getByRole('button', { name: 'Geheimes zeigen' }).click();
  await page.locator('.modal').getByText('erstes-passwort').waitFor();
  await snap('version');
  await page.locator('.modal').getByRole('button', { name: 'Zurückholen' }).click();
  await page.getByText(/Zurückgeholt/).first().waitFor();
  await page.getByRole('button', { name: 'Ansehen' }).nth(1).waitFor();

  step('an own icon, encrypted before it goes up');
  await page.locator('.comfort-card input[type=file]').setInputFiles({
    name: 'bank.png',
    mimeType: 'image/png',
    buffer: PNG,
  });
  await page.getByText('Icon gespeichert ✧').first().waitFor();
  await page.locator('.item-list .item-tile img').first().waitFor();
  await snap('icon');

  step('a device in the home network: an app icon from the server\'s own databases');
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Login' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Jellyfin');
  if (!(await page.getByLabel('Adresse 1', { exact: true }).count())) {
    await page.getByRole('button', { name: 'Website hinzufügen' }).click();
  }
  await page.getByLabel('Adresse 1', { exact: true }).fill('http://jellyfin.local');
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.item-list').getByText('Jellyfin').first().click();
  await page.locator('img[src*="/icons/jellyfin.local/"]').first().waitFor();
  await snap('home-network-icon');
  await page.locator('.item-list').getByText('Bank').first().click();

  step('a reminder that is due, and the list from the mail');
  await page.getByRole('button', { name: 'Erinnern …' }).click();
  await page.getByRole('radio', { name: 'An einem Tag' }).click();
  await page.getByLabel('Tag', { exact: true }).fill('2020-01-01');
  await page.locator('.comfort-card').getByRole('button', { name: 'Speichern' }).click();
  await page.locator('.chip-due').first().waitFor();
  await page.goto(`${origin}/#/vault?due=1`);
  await page.locator('.list-pane[aria-label="Fällig"]').waitFor();
  await page.locator('.item-list').getByText('Bank').first().waitFor();
  await snap('due');

  step('travel mode wants two-step login first');
  await page.goto(`${origin}/#/settings/travel`);
  await page.getByRole('button', { name: 'Reisemodus einschalten' }).waitFor();
  if (await page.getByRole('button', { name: 'Reisemodus einschalten' }).isEnabled()) {
    throw new Error('travel mode could be switched on without two-step login and folders');
  }
  await snap('travel');
  await page.keyboard.press('Escape');

  step('new keys, the versions come along');
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await page.getByRole('navigation').getByRole('button', { name: 'Konto' }).click();
  await page.getByRole('button', { name: 'Neu verschlüsseln …' }).click();
  await page.locator('.modal input[type=password]').last().fill(password);
  await page.getByRole('button', { name: 'Neu verschlüsseln', exact: true }).click();
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 60000 });
  await login();
  await page.locator('.item-list').getByText('Bank').first().click();
  await page.getByRole('button', { name: 'Frühere Versionen' }).click();
  await page.getByRole('button', { name: 'Ansehen' }).first().click();
  await page.locator('.modal').getByRole('button', { name: 'Geheimes zeigen' }).click();
  await page.locator('.modal').getByText('zweites-passwort').waitFor();
  await page.locator('.item-list .item-tile img').first().waitFor();
  await snap('after-rotation');

  step('the icon databases in the admin portal, with their licences');
  await page.goto(`${origin}/admin#/vault/icons`);
  const databases = page.getByRole('region', { name: 'Icon-Datenbanken' });
  await databases.getByRole('switch', { name: 'Dashboard Icons' }).waitFor();
  await databases.getByRole('link', { name: 'Apache-2.0' }).waitFor();
  await databases.scrollIntoViewIfNeeded();
  await snap('icon-databases');
} catch (error) {
  await snap('failed');
  problems.push(String(error?.stack ?? error));
} finally {
  await browser.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('comfort: all fine');
