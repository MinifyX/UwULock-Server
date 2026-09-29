/**
 * The CSV exports of browsers: Chrome and Edge (and everything built on Chromium), Firefox, and
 * Apple's Passwords app (Safari's passwords on macOS and iOS). Logins only.
 *
 * Field mapping after Bitwarden's importers (bitwarden/clients, libs/importer/src/importers/
 * chrome-csv-importer.ts, firefox-csv-importer.ts, safari-csv-importer.ts, GPL-3.0). Columns
 * those don't know become custom fields here instead of being dropped.
 */

import { t } from '../i18n';
import { ImportError } from './bytes';
import { Collector, nameFromUrl, some } from './collect';
import type { CsvTable } from './csv';

/**
 * The app of an Android password's address, "android://…@com.example.app/": what follows the
 * last "@", without a slash but at the end. Read without a regex, which took quadratic time on
 * a long address full of "@".
 */
export function androidApp(url: string): string | null {
  if (!url.startsWith('android://')) return null;
  const at = url.lastIndexOf('@');
  if (at < 'android://'.length) return null;
  const app = url.endsWith('/') ? url.slice(at + 1, -1) : url.slice(at + 1);
  return app && !app.includes('/') ? app : null;
}

export function readChromeCsv(table: CsvTable, collector: Collector) {
  if (!table.has('url', 'username', 'password')) {
    throw new ImportError(
      t('Das sieht nicht nach einem Passwort-Export von Chrome oder Edge aus.'),
    );
  }
  const known = ['name', 'url', 'username', 'password', 'note'];
  for (const row of table.rows) {
    const url = table.get(row, 'url');
    // Passwords of Android apps: android://…@com.example.app/ → androidapp://com.example.app
    const app = androidApp(url);
    const item = collector.login(table.get(row, 'name') || app || nameFromUrl(url));
    item.login.username = some(table.get(row, 'username'));
    item.login.password = some(table.get(row, 'password'));
    collector.uris(item, app ? `androidapp://${app}` : url);
    collector.appendNote(item, table.get(row, 'note'));
    for (const [name, value] of table.rest(row, known)) collector.extra(item, name, value);
    collector.add(item);
  }
}

export function readFirefoxCsv(table: CsvTable, collector: Collector) {
  // Firefox's own columns tell its export from other browsers'.
  const own = ['guid', 'httpRealm', 'formActionOrigin', 'hostname'].some((name) => table.has(name));
  if (!own || !table.has('username', 'password')) {
    throw new ImportError(t('Das sieht nicht nach einem Passwort-Export von Firefox aus.'));
  }
  // Firefox's own bookkeeping, nothing a person typed in.
  const known = [
    'url',
    'hostname',
    'username',
    'password',
    'formActionOrigin',
    'guid',
    'timeCreated',
    'timeLastUsed',
    'timePasswordChanged',
  ];
  for (const row of table.rows) {
    const url = table.get(row, 'url', 'hostname');
    // The Firefox account itself: it signs in to Firefox, not to a website.
    if (url === 'chrome://FirefoxAccounts') continue;
    const item = collector.login(nameFromUrl(url));
    item.login.username = some(table.get(row, 'username'));
    item.login.password = some(table.get(row, 'password'));
    collector.uris(item, url);
    for (const [name, value] of table.rest(row, known)) collector.extra(item, name, value);
    collector.add(item);
  }
}

export function readAppleCsv(table: CsvTable, collector: Collector) {
  if (!table.has('Title', 'Username', 'Password')) {
    throw new ImportError(t('Das sieht nicht nach einem Export der Passwörter-App von Apple aus.'));
  }
  const known = ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'];
  for (const row of table.rows) {
    const url = table.get(row, 'URL');
    const item = collector.login(table.get(row, 'Title') || nameFromUrl(url));
    item.login.username = some(table.get(row, 'Username'));
    item.login.password = some(table.get(row, 'Password'));
    item.login.totp = some(table.get(row, 'OTPAuth'));
    collector.uris(item, url);
    collector.appendNote(item, table.get(row, 'Notes'));
    for (const [name, value] of table.rest(row, known)) collector.extra(item, name, value);
    collector.add(item);
  }
}
