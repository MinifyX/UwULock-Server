// What 0.4 brought to the web vault, in a real browser, against a running UwULock Server with
// the account web.mjs made: attachments, Sends (and their page for whoever has the link), the
// password check, the API key, a security key as the second step, a passkey that logs in and
// unlocks, logging in with another device, and emergency access with a second account.
//
//   node scripts/e2e/features.mjs <origin> <email> <password> [api key file] [screenshot directory]
//
// Security keys and passkeys come from Chromium's virtual authenticator (DevTools protocol).

import { mkdirSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { checkA11y } from './axe.mjs';

const [origin, email, password, apiKeyFile, shots] = process.argv.slice(2);
if (!origin || !email || !password) {
  console.error('usage: features.mjs <origin> <email> <password> [api key file] [screenshot directory]');
  process.exit(2);
}
if (shots) mkdirSync(shots, { recursive: true });

// CHROMIUM_ARGS can make the browser trust a test certificate for real (for WebAuthn, which
// refuses a site whose certificate is only waved through): --ignore-certificate-errors-spki-list.
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
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
      problems.push(`${name}: console: ${message.text()}`);
    }
  });
  return page;
}

let shot = 0;
const snap = async (page, name) => {
  if (shots) await page.screenshot({ path: `${shots}/f${String(++shot).padStart(2, '0')}-${name}.png` });
};
const step = (text) => console.log(`== ${text}`);

/** A virtual authenticator on `page`: presence and verification are given, like a touch. */
async function authenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
  return cdp;
}

async function login(page, address, secret) {
  await page.goto(origin);
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 30000 });
  await page.getByLabel('E-Mail-Adresse').fill(address);
  await page.locator('input[type=password]').first().fill(secret);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click();
}

async function vault(page) {
  await page.getByPlaceholder(/Tresor durchsuchen/).waitFor({ timeout: 30000 });
}

async function settings(page, section) {
  await page.getByRole('button', { name: 'Einstellungen', exact: true }).click();
  await page.getByRole('navigation', { name: 'Bereiche' }).getByRole('button', { name: section }).click();
}

async function logOut(page) {
  await settings(page, 'Konto');
  await page.getByRole('button', { name: 'Abmelden', exact: true }).click();
  await page.getByRole('heading', { name: 'Anmelden' }).waitFor();
}

async function copiedLink(page) {
  await page.getByRole('button', { name: 'Link kopieren' }).click();
  return page.evaluate(() => navigator.clipboard.readText());
}

async function downloaded(page, click) {
  const [file] = await Promise.all([page.waitForEvent('download'), click()]);
  const chunks = [];
  for await (const chunk of await file.createReadStream()) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

const nyu = await open('nyu');
try {
  step('log in');
  await login(nyu, email, password);
  await vault(nyu);

  step('an item with a weak password and a file on it');
  await nyu.getByRole('button', { name: 'Neu', exact: true }).click();
  await nyu.getByRole('menuitem', { name: 'Login' }).click();
  const editor = nyu.locator('.modal');
  await editor.getByLabel('Name', { exact: true }).fill('Drucker');
  await editor.getByLabel('Benutzername').fill('admin');
  await editor.getByLabel('Passwort', { exact: true }).fill('1234');
  await nyu.getByRole('button', { name: 'Speichern' }).click();
  await nyu.locator('.item-list').getByText('Drucker').first().click();
  await nyu.locator('.attachment-add input[type=file]').setInputFiles({
    name: 'handbuch.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Papier nachfüllen ✧'),
  });
  await nyu.getByText('Angehängt ✧').waitFor({ timeout: 30000 });
  await nyu.locator('.detail').getByText('handbuch.txt').waitFor();
  await snap(nyu, 'attachment');
  const handbook = await downloaded(nyu, () =>
    nyu.getByRole('button', { name: 'handbuch.txt herunterladen' }).click(),
  );
  if (handbook !== 'Papier nachfüllen ✧') throw new Error(`the attachment came back as ${handbook}`);

  step('a text Send with a password, opened by somebody else');
  const sidebar = nyu.getByRole('navigation', { name: 'Tresor' });
  await sidebar.getByRole('button', { name: 'Sends' }).click();
  await nyu.getByRole('button', { name: 'Text', exact: true }).click();
  await nyu.locator('.modal').getByLabel('Name', { exact: true }).fill('WLAN');
  await nyu.locator('.modal').getByLabel('Text', { exact: true }).fill('Gast-WLAN: nyu-net / miau1234');
  await nyu.locator('.modal').getByRole('radio', { name: 'Mit Passwort' }).check();
  await nyu.locator('.modal input[type=password]').fill('geheim');
  await nyu.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.getByText(/Send angelegt/).waitFor();
  await snap(nyu, 'send');
  await checkA11y(nyu, 'Sends view');
  const textLink = await copiedLink(nyu);
  const stranger = await open('stranger');
  await stranger.goto(textLink);
  await stranger.getByRole('heading', { name: 'Passwort nötig' }).waitFor({ timeout: 30000 });
  await checkA11y(stranger, 'public Send page');
  await stranger.locator('input[type=password]').fill('geheim');
  await stranger.getByRole('button', { name: 'Öffnen' }).click();
  await stranger.getByText('Gast-WLAN: nyu-net / miau1234').waitFor();
  await snap(stranger, 'send-opened');

  step('a file Send');
  await nyu.getByRole('button', { name: 'Datei', exact: true }).click();
  await nyu.locator('.modal').getByLabel('Name', { exact: true }).fill('Foto');
  await nyu.locator('.modal input[type=file]').setInputFiles({
    name: 'foto.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('kein Foto, aber fast'),
  });
  await nyu.getByRole('button', { name: 'Anlegen' }).click();
  await nyu.getByText(/Send angelegt/).waitFor({ timeout: 30000 });
  const fileLink = await copiedLink(nyu);
  await stranger.goto(fileLink);
  await stranger.reload();
  const photo = await downloaded(stranger, () =>
    stranger.getByRole('button', { name: 'Herunterladen' }).click(),
  );
  if (photo !== 'kein Foto, aber fast') throw new Error(`the Send's file came back as ${photo}`);
  await stranger.context().close();

  step('the password check');
  await sidebar.getByRole('button', { name: 'Passwortprüfung' }).click();
  await nyu.getByRole('button', { name: 'Jetzt prüfen' }).click();
  await nyu.getByRole('heading', { name: /Schwach/ }).waitFor({ timeout: 60000 });
  await snap(nyu, 'password-check');
  await checkA11y(nyu, 'password check');

  step('the API key');
  const apiKey = async () => {
    await settings(nyu, 'Konto');
    await nyu.getByRole('button', { name: 'Anzeigen …' }).click();
    const keyDialog = nyu.getByRole('dialog', { name: 'API-Key' });
    await keyDialog.locator('input[type=password]').fill(password);
    await keyDialog.getByRole('button', { name: 'Anzeigen' }).click();
    await nyu.locator('.copy-field code').first().waitFor();
    const [clientId, clientSecret] = await nyu.locator('.copy-field code').allInnerTexts();
    if (!clientId?.startsWith('user.') || !clientSecret) throw new Error('no API key shown');
    await nyu.getByRole('button', { name: 'Fertig' }).click();
    await nyu.keyboard.press('Escape');
    if (apiKeyFile) writeFileSync(apiKeyFile, `${clientId}\n${clientSecret}\n`);
    return clientSecret;
  };
  const firstSecret = await apiKey();

  step('a security key as the second step');
  await authenticator(nyu);
  await settings(nyu, 'Zwei-Schritt-Anmeldung');
  await nyu.getByRole('button', { name: 'Einrichten …' }).nth(2).click();
  await nyu.locator('.modal input[type=password]').fill(password);
  await nyu.getByRole('button', { name: 'Weiter' }).click();
  await nyu.getByLabel('Name des neuen Schlüssels').fill('Testschlüssel');
  await nyu.getByRole('button', { name: 'Schlüssel hinzufügen' }).click();
  await nyu.getByText('Sicherheitsschlüssel eingerichtet ✧').waitFor({ timeout: 30000 });
  await nyu.getByRole('button', { name: 'Fertig' }).click();
  await nyu.keyboard.press('Escape');
  await logOut(nyu);
  await login(nyu, email, password);
  await nyu.getByRole('heading', { name: 'Zweistufige Anmeldung' }).waitFor({ timeout: 30000 });
  await snap(nyu, 'security-key-step');
  await nyu.getByRole('button', { name: 'Schlüssel verwenden' }).click();
  await vault(nyu);
  // Off again: Bitwarden's CLI logs in with the password after this.
  await settings(nyu, 'Zwei-Schritt-Anmeldung');
  await nyu.getByRole('button', { name: 'Verwalten …' }).click();
  await nyu.locator('.modal input[type=password]').fill(password);
  await nyu.getByRole('button', { name: 'Weiter' }).click();
  await nyu.locator('.modal').getByRole('button', { name: 'Entfernen' }).click();
  await nyu.getByText('Entfernt.').waitFor();
  await nyu.getByRole('button', { name: 'Fertig' }).click();
  await nyu.keyboard.press('Escape');

  step('a passkey that logs in and unlocks');
  await settings(nyu, 'Passkeys');
  await nyu.getByRole('button', { name: 'Hinzufügen …' }).click();
  await nyu.locator('.modal').getByLabel('Name').fill('Virtuell');
  await nyu.locator('.modal input[type=password]').fill(password);
  await nyu.getByRole('button', { name: 'Weiter' }).click();
  // The toast says whether the passkey unlocks too; the list below may render a moment later.
  const added = nyu.getByText(/Passkey hinzugefügt/);
  await added.waitFor({ timeout: 30000 });
  const unlocks = /entsperrt auch/.test(await added.textContent());
  await snap(nyu, 'passkey');
  await nyu.keyboard.press('Escape');
  await logOut(nyu);
  await nyu.getByRole('button', { name: 'Mit Passkey anmelden' }).click();
  if (unlocks) {
    await vault(nyu);
  } else {
    // Without PRF from this browser's authenticator: logged in, but the master password unlocks.
    console.log('   (this authenticator gave no PRF output: unlocking with the password)');
    await nyu.getByRole('heading', { name: /gesperrt/ }).waitFor({ timeout: 30000 });
    await nyu.locator('input[type=password]').first().fill(password);
    await nyu.keyboard.press('Enter');
    await vault(nyu);
  }

  step('logging in with another device');
  const tablet = await open('tablet');
  await tablet.goto(origin);
  await tablet.getByLabel('E-Mail-Adresse').fill(email);
  await tablet.getByRole('button', { name: 'Mit anderem Gerät anmelden' }).click();
  const asked = await tablet.locator('.fingerprint').innerText();
  await snap(tablet, 'device-login');
  await nyu.bringToFront();
  // The hub tells the open vault at once, long before it would look by itself.
  await nyu.getByRole('heading', { name: 'Ein Gerät möchte sich anmelden' }).waitFor({ timeout: 5000 });
  const shown = await nyu.locator('.modal .fingerprint').innerText();
  if (shown !== asked) throw new Error(`the phrases differ: ${asked} / ${shown}`);
  await nyu.getByRole('button', { name: 'Anmelden lassen' }).click();
  await vault(tablet);

  step('what the tablet saves shows up here at once');
  await tablet.getByRole('button', { name: 'Neu', exact: true }).click();
  await tablet.getByRole('menuitem', { name: 'Login' }).click();
  await tablet.locator('.modal').getByLabel('Name', { exact: true }).fill('Vom Tablet');
  await tablet.getByRole('button', { name: 'Speichern' }).click();
  await nyu.locator('.item-list').getByText('Vom Tablet').waitFor({ timeout: 5000 });
  await tablet.context().close();

  step('a second account, for emergency access');
  await nyu.goto(`${origin}/admin#/users/invitations`);
  await nyu.getByRole('heading', { name: 'Jemanden einladen' }).waitFor({ timeout: 30000 });
  await nyu.getByLabel('E-Mail-Adresse').fill('friend@example.com');
  await nyu.getByRole('button', { name: 'Einladen' }).click();
  const invitation = await nyu.locator('.invite-link').innerText();
  const friend = await open('friend');
  await friend.goto(invitation.trim());
  await friend.getByRole('heading', { name: 'Konto anlegen' }).waitFor({ timeout: 30000 });
  await friend.getByLabel('Name', { exact: true }).fill('Mika');
  const fields = friend.locator('input[type=password]');
  await fields.nth(0).fill('another horse battery staple');
  await fields.nth(1).fill('another horse battery staple');
  await friend.getByRole('button', { name: 'Konto anlegen' }).click();
  await vault(friend);

  step('emergency access: invite, confirm, ask, approve, view');
  await nyu.goto(origin);
  await vault(nyu).catch(async () => {
    await nyu.locator('input[type=password]').first().fill(password);
    await nyu.keyboard.press('Enter');
    await vault(nyu);
  });
  await settings(nyu, 'Notfallzugriff');
  await nyu.getByRole('button', { name: 'Einladen …' }).click();
  await nyu.getByLabel('E-Mail-Adresse ihres Kontos').fill('friend@example.com');
  await nyu
    .getByRole('dialog', { name: 'Vertrauensperson einladen' })
    .getByRole('button', { name: 'Einladen', exact: true })
    .click();
  await nyu.getByText('Eingeladen ✧').waitFor();
  // Without mail the invitation waits in the contact's settings, and is accepted there.
  await settings(friend, 'Notfallzugriff');
  await friend.getByRole('button', { name: 'Annehmen', exact: true }).click();
  await friend.getByText('Angenommen ✧').waitFor();
  await friend.keyboard.press('Escape');
  await nyu.keyboard.press('Escape');
  await settings(nyu, 'Notfallzugriff');
  await nyu.getByRole('button', { name: 'Bestätigen …' }).click();
  await nyu.locator('.modal .fingerprint').waitFor();
  await snap(nyu, 'emergency-confirm');
  await nyu.getByRole('button', { name: 'Bestätigen', exact: true }).click();
  await nyu.getByText('Bestätigt ✧').waitFor();
  await settings(friend, 'Notfallzugriff');
  await friend.getByRole('button', { name: 'Zugriff anfragen' }).click();
  await friend.getByText(/Angefragt/).waitFor();
  await nyu.keyboard.press('Escape');
  await settings(nyu, 'Notfallzugriff');
  await nyu.getByRole('button', { name: 'Freigeben' }).click();
  await nyu.getByText('Freigegeben.').waitFor();
  await friend.keyboard.press('Escape');
  await settings(friend, 'Notfallzugriff');
  await friend.getByRole('button', { name: 'Tresor ansehen' }).click();
  await friend.locator('.emergency-items').getByText('Drucker').waitFor({ timeout: 30000 });
  await snap(friend, 'emergency-view');

  step('new keys: attachments, Sends, the contact and the passkey come along');
  await nyu.keyboard.press('Escape');
  await settings(nyu, 'Konto');
  await nyu.getByRole('button', { name: 'Neu verschlüsseln …' }).click();
  // The contact who gets the new key is shown with their phrase first.
  await nyu.locator('.rotation-contact .fingerprint').waitFor();
  await snap(nyu, 'rotate-contacts');
  await nyu.locator('.modal input[type=password]').last().fill(password);
  await nyu.getByRole('button', { name: 'Neu verschlüsseln', exact: true }).click();
  await nyu.getByRole('heading', { name: 'Anmelden' }).waitFor({ timeout: 60000 });
  await login(nyu, email, password);
  await vault(nyu);
  // New keys change the security stamp, and with it the API key (R1-5): the old one is over.
  // The new one is what Bitwarden's CLI logs in with afterwards.
  const secondSecret = await apiKey();
  if (secondSecret === firstSecret) throw new Error('the API key outlived new keys');
  await vault(nyu);
  await nyu.locator('.item-list').getByText('Drucker').first().click();
  const again = await downloaded(nyu, () =>
    nyu.getByRole('button', { name: 'handbuch.txt herunterladen' }).click(),
  );
  if (again !== 'Papier nachfüllen ✧') throw new Error('the attachment did not open after new keys');
  await nyu.getByRole('navigation', { name: 'Tresor' }).getByRole('button', { name: 'Sends' }).click();
  await nyu.locator('.item-list').getByText('WLAN').waitFor();
  const stillOpens = await open('stranger-2');
  await stillOpens.goto(await copiedLink(nyu));
  await stillOpens.locator('input[type=password]').fill('geheim');
  await stillOpens.getByRole('button', { name: 'Öffnen' }).click();
  await stillOpens.getByText('Gast-WLAN: nyu-net / miau1234').waitFor({ timeout: 30000 });
  await stillOpens.context().close();
  // The vault it saw, and the settings under it.
  await friend.keyboard.press('Escape');
  await friend.keyboard.press('Escape');
  await settings(friend, 'Notfallzugriff');
  await friend.getByRole('button', { name: 'Tresor ansehen' }).click();
  await friend.locator('.emergency-items').getByText('Drucker').waitFor({ timeout: 30000 });
  await logOut(nyu);
  await nyu.getByRole('button', { name: 'Mit Passkey anmelden' }).click();
  await vault(nyu).catch(async () => {
    await nyu.locator('input[type=password]').first().fill(password);
    await nyu.keyboard.press('Enter');
    await vault(nyu);
  });
  await nyu.locator('.item-list').getByText('Drucker').first().waitFor();

  if (problems.length) throw new Error(problems.join('\n'));
  console.log('attachments, Sends, the password check, the API key, security keys, passkeys, devices, emergency access and new keys: all good');
} catch (error) {
  await snap(nyu, 'failed').catch(() => undefined);
  console.error(`FAILED: ${error.message}`);
  if (problems.length) console.error(problems.join('\n'));
  process.exitCode = 1;
} finally {
  await browser.close();
}
