/**
 * Bitwarden's own exports (also Vaultwarden's and UwULock's): the vault reads them itself. Here
 * they are only read for the preview, and checked for what the vault would refuse anyway.
 */

import { t } from '../i18n';
import { ImportError } from './bytes';
import { Collector, some } from './collect';
import type { CsvTable } from './csv';
import { FieldType, ItemType, type BitwardenExport } from './types';

export function readBitwardenJson(data: unknown): BitwardenExport {
  const value = data as Partial<BitwardenExport> & { encrypted?: boolean };
  if (value.encrypted) {
    throw new ImportError(
      t(
        'Dieser Export ist verschlüsselt. Exportiere noch einmal als JSON ohne Passwort und importiere diese Datei.',
      ),
    );
  }
  if (!Array.isArray(value.items)) {
    throw new ImportError(t('Das sieht nicht nach einem JSON-Export von Bitwarden aus.'));
  }
  return { encrypted: false, folders: value.folders ?? [], items: value.items };
}

/** Bitwarden's CSV, for the preview only: the vault imports the file itself. */
export function readBitwardenCsv(table: CsvTable, collector: Collector) {
  if (!table.has('name')) {
    throw new ImportError(t('Das sieht nicht nach einem CSV-Export von Bitwarden aus.'));
  }
  for (const row of table.rows) {
    const item = collector.login(table.get(row, 'name'));
    if (table.get(row, 'type') === 'note') collector.retype(item, ItemType.Note);
    item.favorite = table.get(row, 'favorite') === '1';
    item.login.username = some(table.get(row, 'login_username'));
    item.login.password = some(table.get(row, 'login_password'));
    item.login.totp = some(table.get(row, 'login_totp'));
    collector.uris(item, ...table.get(row, 'login_uri').split(','));
    collector.appendNote(item, table.get(row, 'notes'));
    for (const line of table.get(row, 'fields').split('\n')) {
      const colon = line.indexOf(': ');
      if (colon > 0)
        collector.field(item, line.slice(0, colon), line.slice(colon + 2), FieldType.Text);
    }
    collector.add(item, table.get(row, 'folder') || null);
  }
}
