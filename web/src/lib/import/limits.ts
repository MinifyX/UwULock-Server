/**
 * How far an import goes before it stops: every importer runs in the user's own tab, on a file
 * the user chose, and these keep a broken or hostile file from holding the tab (and its memory)
 * without end. The ceilings sit well above what the apps write.
 */

import { t } from '../i18n';
import { ImportError } from './bytes';

/** The largest file UwULock reads: exports with thousands of items are a few MiB. */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/**
 * The most an import unpacks (gzip in a KDBX, deflate in a zip). An import unpacks one thing
 * (the KDBX payload, 1Password's export.data, Proton Pass's data.json), so this is the cap on
 * the whole import.
 */
export const MAX_UNPACKED_BYTES = 512 * 1024 * 1024;

/**
 * The most entries a zip may list. Zips without ZIP64 (which UwULock doesn't read) can't list
 * more than 65 535 anyway; the 1PUX and Proton Pass exports have one per item file.
 */
export const MAX_ZIP_ENTRIES = 50_000;

/**
 * KeePass's key derivations, checked before they run, on the page's thread. Argon2 like the
 * vault's own: at most 1 GiB of memory, and memory × passes no more than the vault's most
 * costly setting (1 GiB, 10 passes), which leaves KeePassXC's default of 64 MiB room for 160
 * passes. The lanes cost no time here (the module runs them one after another). AES-KDF: 100
 * million rounds, well above what KeePass and KeePassXC pick for a second's delay.
 */
export const MAX_ARGON2_MEMORY_KIB = 1024 * 1024;
export const MAX_ARGON2_COST_KIB = MAX_ARGON2_MEMORY_KIB * 10;
export const MAX_ARGON2_LANES = 256;
export const MAX_AES_KDF_ROUNDS = 100_000_000;

export const tooLarge = () =>
  new ImportError(
    t('Die Datei ist zu groß für den Import (mehr als {size} MiB).', {
      size: MAX_FILE_BYTES / 1024 / 1024,
    }),
  );

export const unpacksTooMuch = () =>
  new ImportError(
    t('Die Datei entpackt sich zu mehr als {size} MiB, das importiert UwULock nicht.', {
      size: MAX_UNPACKED_BYTES / 1024 / 1024,
    }),
  );

/** Throws when a file of `size` bytes is more than an import reads. */
export function checkFileSize(size: number) {
  if (size > MAX_FILE_BYTES) throw tooLarge();
}
