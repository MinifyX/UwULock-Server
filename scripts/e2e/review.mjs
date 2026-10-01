// The password check one login at a time (0.7), in a real browser, against a running UwULock
// Server with a registered account: the report with its breach sources, the swipe stack moved
// by keys and by dragging, a problem ignored and the ignore undone, a new password generated and
// saved with the old one in the history, "later", the change-password page as the link to open,
// and the stack at phone width in the dark.
//
// The breach sources are played by the script: it answers the browser's requests to the
// server's /uwu/v1/hibp, /xon, /breaches/sites and /change-password itself, so nothing here
// reaches the internet.
//
//   node scripts/e2e/review.mjs <origin> <email> <password> [screenshot directory]

import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: review.mjs <origin> <email> <password> [screenshot directory]');
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
  if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
    problems.push(`console: ${message.text()}`);
  }
});

let shot = 0;
const snap = async (name) => {
  if (shots) await page.screenshot({ path: `${shots}/r${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);
const expect = (ok, what) => {
  if (!ok) throw new Error(what);
};

// ── The breach sources, played here ──
const WEAK = 'password';
const sha1 = createHash('sha1').update(WEAK).digest('hex').toUpperCase();
const today = new Date().toISOString().slice(0, 10);
const CHANGE_PAGE = 'https://shop.example.com/.well-known/change-password';
await context.route('**/uwu/v1/hibp/*', (route) => {
  const prefix = route.request().url().split('/').pop().toUpperCase();
  const body =
    prefix === sha1.slice(0, 5)
      ? `${sha1.slice(5)}:3861493\r\n0000000000000000000000000000000000A:0`
      : '0000000000000000000000000000000000A:0';
  return route.fulfill({ status: 200, contentType: 'text/plain', body });
});
await context.route('**/uwu/v1/xon/*', (route) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: '{"object":"xonPassword","count":0}' }),
);
await context.route('**/uwu/v1/breaches/sites', (route) =>
  route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      object: 'siteBreaches',
      updated: new Date().toISOString(),
      sources: [{ id: 'hibp', name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/', license: 'CC BY 4.0', updated: today }],
      breaches: [
        {
          domain: 'shop.example.com',
          title: 'Shop',
          date: today,
          added: today,
          records: 1000,
          passwords: true,
          dataClasses: ['Email addresses', 'Passwords'],
          sources: { hibp: 'Shop' },
        },
      ],
    }),
  }),
);
await context.route('**/uwu/v1/change-password/*', (route) => {
  const host = decodeURIComponent(route.request().url().split('/').pop());
  const url = host === 'shop.example.com' ? CHANGE_PAGE : null;
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ object: 'changePassword', host, url }) });
});

async function login() {
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await page.getByLabel('E-Mail-Adresse').fill(email);
  await page.locator('input[type=password]').first().fill(password);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click();
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

async function newLogin(name, secret, uri) {
  await page.getByRole('button', { name: 'Neu', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Login' }).click();
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('Passwort', { exact: true }).fill(secret);
  await page.getByLabel('Adresse 1', { exact: true }).fill(uri);
  await page.getByRole('button', { name: 'Speichern' }).click();
  await page.getByRole('button', { name: 'Bearbeiten' }).waitFor();
}

const progress = () => page.getByTestId('review-progress').innerText();
const card = () => page.getByTestId('review-card');
const nav = (name) => page.locator('.sidebar').getByRole('button', { name, exact: true });

try {
  step('log in, and three logins: one breached and reused, one reused over http, one fine');
  await login();
  await newLogin('Review Shop', WEAK, 'https://shop.example.com/login');
  await newLogin('Review Mail', WEAK, 'http://mail.example.org/');
  await newLogin('Review Fine', 'V3ry-l0ng-and-quite-r4ndom-Passphrase!', 'https://fine.example.net/');

  step('the report, with the breached site');
  await nav('Passwortprüfung').click();
  await page.getByRole('button', { name: /Jetzt prüfen|Nochmal prüfen/ }).click();
  await page.getByRole('heading', { name: /In Datenlecks/ }).waitFor({ timeout: 60000 });
  await page.getByRole('heading', { name: /Datenleck nach deiner letzten Passwortänderung/ }).waitFor();
  await snap('report');

  step('the stack: one card per login with a problem, the worst first');
  await page.locator('.report-pane').getByRole('button', { name: 'Durchgehen' }).click();
  await card().waitFor({ timeout: 30000 });
  // Other scripts may have left logins with problems in this account: only ours are counted on.
  const first = await progress();
  const total = Number(first.split(' von ')[1]);
  expect(first === `1 von ${total}` && total >= 2, `progress ${first}`);
  const at = (n) => `${n} von ${total}`;
  expect((await card().getByRole('heading').innerText()).includes('Review Shop'), 'shop first');
  await card().getByText('Datenleck nach deiner letzten Passwortänderung', { exact: true }).waitFor();
  const open = card().getByRole('link', { name: /Seite öffnen & Passwort ändern/ });
  await page.waitForFunction(
    (url) => document.querySelector('[data-testid=review-card] a')?.getAttribute('href') === url,
    CHANGE_PAGE,
  );
  expect((await open.getAttribute('target')) === '_blank', 'opens in a new tab');
  await snap('card');

  step('arrow keys and dragging move through the stack');
  await page.keyboard.press('ArrowRight');
  expect((await progress()) === at(2), 'arrow right');
  await page.keyboard.press('ArrowLeft');
  expect((await progress()) === at(1), 'arrow left');
  const box = await card().boundingBox();
  const y = box.y + 30;
  await page.mouse.move(box.x + box.width - 40, y);
  await page.mouse.down();
  for (let x = box.x + box.width - 40; x > box.x + box.width - 260; x -= 20) await page.mouse.move(x, y);
  await page.mouse.up();
  await page.waitForFunction(
    (text) => document.querySelector('[data-testid=review-progress]')?.textContent === text,
    at(2),
  );
  for (let n = 2; n < total && !(await card().getByRole('heading').innerText()).includes('Review Mail'); n++) {
    await page.keyboard.press('ArrowRight');
  }
  expect((await card().getByRole('heading').innerText()).includes('Review Mail'), 'the mail is in the stack');

  step('a problem ignored, undone, and ignored again');
  const reused = card().locator('.review-problem', { hasText: 'Mehrfach benutzt' });
  await reused.getByRole('button', { name: /^Ignorieren/ }).click();
  await reused.getByRole('button', { name: /^Rückgängig/ }).waitFor();
  await reused.getByRole('button', { name: /^Rückgängig/ }).click();
  await reused.getByRole('button', { name: /^Ignorieren/ }).waitFor();
  await reused.getByRole('button', { name: /^Ignorieren/ }).click();
  await reused.getByRole('button', { name: /^Rückgängig/ }).waitFor();

  step('later: the mail goes for this session');
  await card().getByRole('button', { name: 'Später' }).click();
  await page.waitForFunction(
    (text) => document.querySelector('[data-testid=review-progress]')?.textContent?.endsWith(text),
    ` von ${total - 1}`,
  );
  while (!(await progress()).startsWith('1 von')) await page.keyboard.press('ArrowLeft');
  expect((await card().getByRole('heading').innerText()).includes('Review Shop'), 'back at the shop');

  step('a new password, generated and saved');
  await card().getByRole('button', { name: 'Neues Passwort erzeugen & speichern' }).click();
  await page.locator('.modal').getByRole('button', { name: 'Übernehmen' }).click();
  await card().getByText('Neues Passwort gespeichert – jetzt noch auf der Website ändern.').waitFor({ timeout: 30000 });
  await snap('saved');

  step('the old password is in the history');
  await card().getByRole('button', { name: 'Eintrag öffnen' }).click();
  await page.locator('.item-list').getByText('Review Shop').first().click();
  await page.getByRole('button', { name: '1 früheres Passwort' }).waitFor({ timeout: 30000 });

  step('the report lists what is ignored; undone there');
  await nav('Passwortprüfung').click();
  const ignored = page.getByTestId('ignored');
  await ignored.waitFor({ timeout: 30000 });
  await ignored.getByText('Review Mail').waitFor();
  await ignored.getByRole('button', { name: 'Rückgängig' }).click();
  await ignored.waitFor({ state: 'detached' });

  step('at phone width, in the dark');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.evaluate(() => sessionStorage.removeItem('uwulock.review.later'));
  await page.reload();
  const search = page.getByPlaceholder(/Tresor durchsuchen/);
  const unlock = page.getByRole('button', { name: 'Entsperren', exact: true });
  const signIn = page.getByRole('heading', { name: 'Anmelden' });
  await search.or(unlock).or(signIn).first().waitFor({ timeout: 30000 });
  if (await signIn.isVisible()) {
    await login();
  } else if (await unlock.isVisible()) {
    await page.locator('input[type=password]').first().fill(password);
    await unlock.click();
    await search.waitFor({ timeout: 30000 });
  }
  await page.getByRole('button', { name: 'Prüfung', exact: true }).click();
  await page.locator('.report-pane').getByRole('button', { name: 'Durchgehen' }).click();
  await card().waitFor({ timeout: 30000 });
  const wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(wide <= 0, `the page scrolls sideways by ${wide}px`);
  await snap('phone-dark');

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('review: all good');
} catch (error) {
  await snap('failed').catch(() => undefined);
  console.error(error);
  console.error(problems.join('\n'));
  process.exitCode = 1;
} finally {
  await browser.close();
}
