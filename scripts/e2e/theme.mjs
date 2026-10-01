// The theme and the account menu, in a real browser, against a running UwULock Server with a
// registered account: the account menu opens above its card (never over it, always inside the
// window, on a phone too), the admin portal follows the same theme setting as the vault — even
// one changed in another tab — and every admin page passes axe's checks in the light theme.
// Screenshots in light and dark, on a desktop and a phone.
//
//   node scripts/e2e/theme.mjs <origin> <email> <password> [screenshot directory]

import { mkdirSync, readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { checkA11y } from './axe.mjs';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: theme.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: process.env.CHROMIUM_ARGS ? process.env.CHROMIUM_ARGS.split(' ') : [],
});
const problems = [];
const step = (text) => console.log(`== ${text}`);
// Every tab of every area, from the list the portal itself is made of.
const ADMIN_PATHS = [
  ...readFileSync(new URL('../../web/src/admin/areas.ts', import.meta.url), 'utf8').matchAll(
    /\bpath: '(\/[^']*)'/g,
  ),
].map((match) => match[1]);
const DESKTOP = { width: 1280, height: 860 };
const PHONE = { width: 390, height: 844 };

/** A logged-in browser whose system asks for `scheme`; `theme` is the stored setting, if any. */
async function open(scheme, viewport, theme) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport,
    locale: 'de-DE',
    colorScheme: scheme,
  });
  if (theme) {
    await context.addInitScript((value) => {
      if (!localStorage.getItem('uwulock.settings')) {
        localStorage.setItem('uwulock.settings', JSON.stringify({ theme: value }));
      }
    }, theme);
  }
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
  if (shots) await page.screenshot({ path: `${shots}/theme-${name}.png` });
};

const theme = (page) => page.evaluate(() => document.documentElement.dataset.theme);

/** Opens the account menu and checks it sits above the card, inside the window. */
async function accountMenu(page, name, viewport) {
  if (viewport.width < 760) await page.locator('.bottom-nav').getByRole('button', { name: 'Mehr' }).click();
  await page.locator('.account-switch').click();
  const menu = page.getByRole('menu', { name: 'Konto' });
  await menu.waitFor();
  // The menu fades in; measure it at rest.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getComputedTiming().endTime !== Infinity)
        .map((a) => a.finished.catch(() => {})),
    ),
  );
  const box = await menu.boundingBox();
  const card = await page.locator('.account-card').boundingBox();
  if (!box || !card) throw new Error(`${name}: no menu or no card`);
  if (box.y + box.height > card.y + 0.5) {
    problems.push(`${name}: the account menu covers its card (menu ends ${box.y + box.height}, card starts ${card.y})`);
  }
  if (box.x < 0 || box.y < 0 || box.x + box.width > viewport.width || box.y + box.height > viewport.height) {
    problems.push(`${name}: the account menu sticks out of the window`);
  }
  await snap(page, `${name}-account-menu`);
  await page.keyboard.press('Escape');
}

try {
  for (const [scheme, viewport, name] of [
    ['light', DESKTOP, 'light'],
    ['dark', DESKTOP, 'dark'],
    ['light', PHONE, 'phone'],
    ['dark', PHONE, 'phone-dark'],
  ]) {
    step(`the account menu, ${name}`);
    const { context, page } = await open(scheme, viewport, 'system');
    if ((await theme(page)) !== scheme) problems.push(`${name}: the vault is not ${scheme}`);
    await accountMenu(page, name, viewport);
    await context.close();
  }

  step('the admin portal and the vault share one theme, across tabs');
  {
    // Nothing stored: dark, as the vault is by default, whatever the system wants.
    const { context, page: vault } = await open('light', DESKTOP);
    const admin = await context.newPage();
    await admin.goto(`${origin}/admin#/`);
    await admin.locator('.admin-panel, .stage h1').first().waitFor({ timeout: 30000 });
    if ((await theme(vault)) !== 'dark' || (await theme(admin)) !== 'dark') {
      problems.push('the default theme is not dark in both the vault and the admin portal');
    }
    // "System" in the vault: the admin portal's tab, already open, turns light with it.
    await vault.evaluate(() => {
      localStorage.setItem('uwulock.settings', JSON.stringify({ theme: 'system' }));
    });
    await admin.locator('html[data-theme="light"]').waitFor({ state: 'attached', timeout: 5000 });
    // And back to dark from the admin portal's appearance dialog.
    await admin.getByRole('button', { name: 'Darstellung' }).click();
    await admin.getByRole('radio', { name: 'Dunkel' }).click();
    await vault.locator('html[data-theme="dark"]').waitFor({ state: 'attached', timeout: 5000 });
    await context.close();
  }

  for (const [scheme, viewport, name, every] of [
    ['light', DESKTOP, 'light', true],
    ['light', PHONE, 'phone', false],
    ['dark', DESKTOP, 'dark', false],
  ]) {
    step(`the admin portal, ${name}`);
    const { context, page } = await open(scheme, viewport, 'system');
    await page.goto(`${origin}/admin#/`);
    await page.locator('.admin-panel, .stage h1').first().waitFor({ timeout: 30000 });
    if ((await theme(page)) !== scheme) problems.push(`admin ${name}: not ${scheme}`);
    for (const path of ADMIN_PATHS) {
      await page.goto(`${origin}/admin#${path}`);
      await page.locator('.admin-panel').first().waitFor({ timeout: 30000 });
      // The tab's data came when no spinner is left.
      await page.locator('.admin-panel .spin').first().waitFor({ state: 'detached', timeout: 15000 });
      const slug = path.slice(1).replace(/\//g, '-') || 'overview';
      // The overview draws its numbers once they came.
      if (slug === 'overview') await page.getByText('Zahlen', { exact: true }).waitFor();
      if (every) await checkA11y(page, `admin ${slug}, ${name}`);
      if (every || ['overview', 'security-failed-logins', 'branding'].includes(slug)) {
        await snap(page, `admin-${name}-${slug}`);
      }
    }
    if (ADMIN_PATHS.length < 20) problems.push(`only ${ADMIN_PATHS.length} admin pages found`);
    await context.close();
  }

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('Theme and account menu in the browser: all good');
} finally {
  await browser.close();
}
