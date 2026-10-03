// What Stufe 4c's second part brought, in a real browser, against a running UwULock Server with a
// registered admin account: an import from Apple Passwords (and a KeePass file opened with its
// password, up to the preview), an item shared as a Send only one address may open — the code
// comes by mail, to a mail server this script plays — and the server's own branding.
//
//   node scripts/e2e/sharing.mjs <origin> <email> <password> [screenshot directory]
//
// Leaves the server as it found it: mail off again, UwULock's own look.

import { mkdirSync, readFileSync } from 'node:fs';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { checkA11y } from './axe.mjs';

const [origin, email, password, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: sharing.mjs <origin> <email> <password> [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });
const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../../web/src/lib/import/fixtures');

/**
 * A mail server that takes every mail and keeps it: just enough SMTP for the server's mailer, on
 * a port of its own, without TLS (the server allows that for a relay on the same machine).
 */
function mailServer() {
  const mails = [];
  const waiting = [];
  const server = net.createServer((socket) => {
    let buffer = '';
    let data = null;
    let to = [];
    socket.write('220 fake.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      let end;
      while ((end = buffer.indexOf('\r\n')) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (data !== null) {
          if (line === '.') {
            const mail = { to, text: data };
            mails.push(mail);
            for (const wake of waiting.splice(0)) wake();
            data = null;
            to = [];
            socket.write('250 2.0.0 kept\r\n');
          } else data += `${line.startsWith('..') ? line.slice(1) : line}\n`;
          continue;
        }
        const command = line.slice(0, 4).toUpperCase();
        if (command === 'EHLO') socket.write('250-fake.test\r\n250 8BITMIME\r\n');
        else if (command === 'RCPT') {
          to.push(line.replace(/^RCPT TO:\s*<?([^>]*)>?.*$/i, '$1').toLowerCase());
          socket.write('250 2.1.5 ok\r\n');
        } else if (command === 'DATA') {
          data = '';
          socket.write('354 go on\r\n');
        } else if (command === 'QUIT') {
          socket.end('221 bye\r\n');
        } else socket.write('250 ok\r\n');
      }
    });
    socket.on('error', () => undefined);
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({
        port: server.address().port,
        close: () => server.close(),
        /** The first mail to `address`, once it came. */
        async mailTo(address) {
          for (;;) {
            const mail = mails.find((m) => m.to.includes(address));
            if (mail) return mail;
            await Promise.race([
              new Promise((wake) => waiting.push(wake)),
              new Promise((_, fail) => setTimeout(() => fail(new Error(`no mail to ${address}`)), 30000)),
            ]);
          }
        },
      }),
    ),
  );
}

/** The subject of a mail, with its encoded words (RFC 2047) decoded. */
function subject(text) {
  const header = text.split('\n\n')[0].replace(/\n[ \t]+/g, ' ');
  const line = header.split('\n').find((l) => /^subject:/i.test(l)) ?? '';
  return line
    .replace(/^subject:\s*/i, '')
    .replace(/=\?utf-8\?b\?([^?]+)\?=\s*/gi, (_, b64) => Buffer.from(b64, 'base64').toString('utf8'))
    .replace(/=\?utf-8\?q\?([^?]+)\?=\s*/gi, (_, q) =>
      Buffer.from(q.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (__, h) => String.fromCharCode(parseInt(h, 16))), 'latin1').toString('utf8'),
    );
}

const smtp = await mailServer();
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
    // Refused requests show up as failed resources; the Send page asks without an address first.
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
      problems.push(`${name}: console: ${message.text()}`);
    }
  });
  return page;
}

let shot = 0;
const snap = async (page, name) => {
  if (shots) await page.screenshot({ path: `${shots}/s${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

const nyu = await open('nyu');

async function unlock() {
  await nyu.goto(origin);
  const heading = nyu.getByRole('heading', { name: /Anmelden|gesperrt/ });
  await heading.first().waitFor({ timeout: 30000 });
  if (await nyu.getByLabel('E-Mail-Adresse').isVisible()) await nyu.getByLabel('E-Mail-Adresse').fill(email);
  await nyu.locator('input[type=password]').first().fill(password);
  await nyu.keyboard.press('Enter');
  await nyu.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

/** The admin portal's mail settings: this script's mail server, or none. */
async function mail(on) {
  await nyu.goto(`${origin}/admin#/mail`);
  const server = nyu.getByLabel('Adresse des Mailservers', { exact: true });
  await server.waitFor({ timeout: 30000 });
  if (on) {
    await server.fill('127.0.0.1');
    await nyu.getByRole('radio', { name: 'keine' }).click();
    await nyu.getByLabel('Port', { exact: true }).fill(String(smtp.port));
    await nyu.getByLabel('Absender-Adresse', { exact: true }).fill('lock@example.com');
  } else {
    await server.fill('');
  }
  // Changed settings wait in the bar at the foot of the page.
  await nyu.getByRole('region', { name: 'Ungespeicherte Änderungen' }).getByRole('button', { name: 'Speichern' }).click();
  await nyu.getByText(/Gespeichert/).first().waitFor();
}

try {
  step('mail through this script, and the server\'s own look');
  await unlock();
  await mail(true);
  await nyu.goto(`${origin}/admin#/branding`);
  await nyu.getByLabel('Name', { exact: true }).fill('Post & Co');
  await nyu.getByRole('button', { name: '#0891b2' }).click();
  await nyu.getByText(/Kontrast: .* ✧/).waitFor();
  await nyu.getByRole('button', { name: 'Speichern' }).click();
  await nyu.getByText('Gespeichert ✧').waitFor();
  await nyu.locator('input[type=file]').first().setInputFiles({
    name: 'logo.svg',
    mimeType: 'image/svg+xml',
    buffer: Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40"><rect width="120" height="40" rx="8" fill="#0891b2"/></svg>',
    ),
  });
  await nyu.getByText('Bild gespeichert ✧').waitFor();
  await nyu.locator('.titlebar .brand-logo:visible').waitFor();
  await snap(nyu, 'branding');
  await nyu.reload();
  if ((await nyu.title()) !== 'Post & Co') throw new Error(`the page is called ${await nyu.title()}`);
  // The colours come with the page, before any script: the light theme's accent is the chosen one.
  const colours = await nyu.evaluate(() => document.getElementById('uwu-branding')?.textContent ?? '');
  if (!colours.includes('--uwu-pink: #0891b2;')) throw new Error(`the page's colours: ${colours}`);

  step('a KeePass file opens with its password, up to the preview');
  await unlock();
  await nyu.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await nyu.getByRole('navigation').getByRole('button', { name: 'Import & Export' }).click();
  const importFile = nyu.locator('.settings-content input[type=file]').first();
  await importFile.setInputFiles({
    name: 'tresor.kdbx',
    mimeType: 'application/octet-stream',
    buffer: readFileSync(join(fixtures, 'argon2id-chacha20.kdbx')),
  });
  await nyu.getByLabel('Passwort der Datei').fill('nyu-test-passwort');
  await nyu.getByRole('button', { name: 'Öffnen', exact: true }).click();
  await nyu.getByRole('heading', { name: 'Import prüfen' }).waitFor({ timeout: 30000 });
  await nyu.locator('.import-list').getByText('Mail', { exact: true }).waitFor();
  await snap(nyu, 'import-keepass');
  await checkA11y(nyu, 'import preview');
  await nyu.locator('.modal').last().getByRole('button', { name: 'Abbrechen' }).click();

  step('Apple Passwords, imported');
  await importFile.setInputFiles({
    name: 'Passwords.csv',
    mimeType: 'text/csv',
    buffer: readFileSync(join(fixtures, 'apple.csv')),
  });
  await nyu.getByRole('heading', { name: 'Import prüfen' }).waitFor({ timeout: 30000 });
  await nyu.getByRole('button', { name: /Einträge importieren/ }).click();
  await nyu.getByText(/Einträge importiert/).waitFor({ timeout: 30000 });
  await nyu.keyboard.press('Escape');

  step('an item shared as an entry Send with its one-time codes, only for one address');
  await nyu.getByPlaceholder(/Tresor durchsuchen/).fill('example.com (nyu)');
  await nyu.locator('.item-list').getByText('example.com (nyu)').first().click();
  await nyu.getByRole('button', { name: 'Als Send teilen' }).click();
  const share = nyu.locator('.modal');
  await share.getByRole('checkbox', { name: 'Benutzername' }).waitFor();
  // The codes are a choice of their own, never ticked from the start.
  const codes = share.getByRole('checkbox', { name: /Einmal-Codes/ });
  if (await codes.isChecked()) throw new Error('the one-time codes are ticked from the start');
  await codes.click();
  // Their key travels in the Send: ticking them asks once more.
  await share.locator('[data-totp-confirm]').waitFor();
  if (await codes.isChecked()) throw new Error('the one-time codes are ticked before the confirm');
  await share.getByRole('button', { name: 'Schlüssel mitgeben' }).click();
  await share.locator('[data-totp-hint]').waitFor();
  await share.getByRole('radio', { name: 'Nur bestimmte Adressen' }).click();
  await share.getByLabel('E-Mail-Adressen').fill('friend@example.com');
  await snap(nyu, 'share');
  await checkA11y(nyu, 'share as Send');
  await share.getByRole('button', { name: 'Send anlegen' }).click();
  const link = await nyu.getByLabel('Link', { exact: true }).inputValue();
  if (!link.includes('/#/send/')) throw new Error(`the link is ${link}`);
  await nyu.getByRole('button', { name: 'Fertig' }).click();

  step('the recipient asks for a code, and opens it with the mailed one');
  const friend = await open('friend');
  await friend.goto(link);
  await friend.getByRole('heading', { name: 'Nur für bestimmte Adressen' }).waitFor({ timeout: 30000 });
  await friend.locator('.titlebar').getByText('Post & Co').waitFor();
  await friend.getByLabel('E-Mail-Adresse').fill('Friend@Example.com');
  await friend.getByRole('button', { name: 'Code schicken' }).click();
  await friend.getByRole('heading', { name: 'Code aus der Mail' }).waitFor();
  await checkA11y(friend, 'Send page asking for the code');
  const sent = await smtp.mailTo('friend@example.com');
  // Eight digits since 0.6.0-beta.2 (SV-L24).
  const code = subject(sent.text).match(/\b(\d{8})\s*$/)?.[1];
  if (!code) throw new Error(`no code in “${subject(sent.text)}”`);
  await friend
    .getByLabel('Code', { exact: true })
    .fill(code === '00000000' ? '11111111' : '00000000');
  await friend.getByRole('button', { name: 'Öffnen' }).click();
  await friend.getByText('Der Code stimmt nicht oder ist abgelaufen.').waitFor();
  await friend.getByLabel('Code', { exact: true }).fill(code);
  await friend.getByRole('button', { name: 'Öffnen' }).click();
  // An entry Send: shown as the item, with copy buttons and live codes, never as raw text.
  const entry = friend.locator('[data-shared-entry]');
  await entry.waitFor({ timeout: 30000 });
  if (await friend.locator('.send-text').count()) throw new Error('the entry Send shows its raw text');
  await entry.getByText('nyu', { exact: true }).waitFor();
  await entry.locator('.totp-code').filter({ hasText: /^\d{3} \d{3}$/ }).waitFor();
  if (await entry.getByText('apple-pass').count()) throw new Error('the password shows before a click');
  await entry.getByRole('button', { name: 'Passwort zeigen' }).click();
  await entry.getByText('apple-pass').waitFor();
  const html = await friend.content();
  if (html.includes('JBSWY3DPEHPK3PXP') || html.includes('otpauth')) {
    throw new Error('the Send page shows the TOTP key');
  }
  await snap(friend, 'send-opened');
  await checkA11y(friend, 'entry Send');
  // The original text: the readable lines, never the marker line with the key.
  await friend.getByRole('button', { name: 'Originaltext anzeigen' }).click();
  const original = await friend.locator('.send-text').innerText();
  if (!original.includes('nyu') || original.includes('uwulock-entry') || original.includes('JBSWY3DPEHPK3PXP')) {
    throw new Error(`the original text is “${original}”`);
  }
  await friend.getByRole('button', { name: 'Als Eintrag zeigen' }).click();
  await entry.waitFor();
  await friend.context().close();
} catch (error) {
  await snap(nyu, 'failed').catch(() => undefined);
  problems.push(String(error?.stack ?? error));
} finally {
  // As it was: no mail server, UwULock's look.
  try {
    await mail(false);
    await nyu.goto(`${origin}/admin#/branding`);
    await nyu.getByRole('button', { name: 'Name und Farbe zurücksetzen' }).click();
    await nyu.getByText('Wieder UwULock ✧').waitFor();
    await nyu.getByRole('button', { name: /Entfernen/ }).first().click();
    await nyu.getByText('Bild entfernt.').waitFor();
  } catch (error) {
    problems.push(`cleaning up: ${error?.message ?? error}`);
  }
  await browser.close();
  smtp.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('import, sharing as a Send for an address, and branding: all good');
