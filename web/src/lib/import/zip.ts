/**
 * Just enough of zip to read an export: 1Password's .1pux and Proton Pass's zip. The central
 * directory at the end lists the entries; each is stored or deflated, and the browser inflates.
 */

import { t } from '../i18n';
import { ImportError, inflate, Reader } from './bytes';
import { MAX_UNPACKED_BYTES, MAX_ZIP_ENTRIES, unpacksTooMuch } from './limits';

/** Files by name: a zip, or a single file standing in for one. */
export type Archive = { names: string[]; read(name: string): Promise<Uint8Array> };

type Entry = { name: string; method: number; flags: number; size: number; offset: number };

export class Zip implements Archive {
  private entries = new Map<string, Entry>();

  constructor(private bytes: Uint8Array) {
    const broken = () => new ImportError(t('Die ZIP-Datei ist beschädigt oder unvollständig.'));
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // The end record sits in the last 22 bytes plus a comment of up to 64 KiB.
    let end = -1;
    for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 22 - 0xffff); at--) {
      if (view.getUint32(at, true) === 0x06054b50) {
        end = at;
        break;
      }
    }
    if (end < 0) throw broken();
    const count = view.getUint16(end + 10, true);
    if (count > MAX_ZIP_ENTRIES) {
      throw new ImportError(
        t('Die ZIP-Datei hat mehr als {n} Einträge, das importiert UwULock nicht.', {
          n: MAX_ZIP_ENTRIES,
        }),
      );
    }
    const reader = new Reader(bytes, broken);
    reader.at = view.getUint32(end + 16, true);
    for (let i = 0; i < count; i++) {
      if (reader.u32() !== 0x02014b50) throw broken();
      reader.take(4);
      const flags = reader.u16();
      const method = reader.u16();
      reader.take(8);
      const size = reader.u32();
      reader.take(4);
      const nameLength = reader.u16();
      const extraLength = reader.u16();
      const commentLength = reader.u16();
      reader.take(8);
      const offset = reader.u32();
      const name = new TextDecoder().decode(reader.take(nameLength));
      reader.take(extraLength + commentLength);
      this.entries.set(name, { name, method, flags, size, offset });
    }
  }

  static is(bytes: Uint8Array): boolean {
    return bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3;
  }

  get names(): string[] {
    return [...this.entries.keys()];
  }

  async read(name: string): Promise<Uint8Array> {
    const entry = this.entries.get(name);
    if (!entry) throw new ImportError(t('In der ZIP-Datei fehlt {name}.', { name }));
    if (entry.flags & 1) throw new ImportError(t('Die ZIP-Datei ist verschlüsselt.'));
    if (entry.size === 0xffffffff) throw new ImportError(t('Die ZIP-Datei ist zu groß.'));
    const reader = new Reader(
      this.bytes,
      () => new ImportError(t('Die ZIP-Datei ist beschädigt oder unvollständig.')),
    );
    reader.at = entry.offset;
    if (reader.u32() !== 0x04034b50) {
      throw new ImportError(t('Die ZIP-Datei ist beschädigt oder unvollständig.'));
    }
    reader.take(22);
    const skip = reader.u16() + reader.u16();
    reader.take(skip);
    const data = reader.take(entry.size);
    if (entry.method === 0) return data;
    if (entry.method === 8) {
      return inflate(data, 'deflate-raw', MAX_UNPACKED_BYTES, unpacksTooMuch).catch((error) =>
        Promise.reject(
          error instanceof ImportError
            ? error
            : new ImportError(t('Die ZIP-Datei ist beschädigt oder unvollständig.')),
        ),
      );
    }
    throw new ImportError(
      t('Die ZIP-Datei ist in einer Art komprimiert, die UwULock nicht kennt.'),
    );
  }
}
