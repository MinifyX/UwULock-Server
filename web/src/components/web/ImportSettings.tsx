import { useRef, useState, type FormEvent } from 'react';
import { importVault } from '../../lib/account';
import { syncNow } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { N_, t, useLanguage } from '../../lib/i18n';
import {
  needsPassword,
  readImport,
  SOURCES,
  summarize,
  type ImportFile,
  type Parsed,
  type Source,
} from '../../lib/import';
import { wasmKdf } from '../../lib/import/kdf';
import { checkFileSize } from '../../lib/import/limits';
import { ItemType } from '../../lib/import/types';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import { ResultLine, Row, type Result } from './controls';

/** The preview lists this many items; more would only slow the page down. */
const LIST_LIMIT = 500;

const ACCEPT = '.json,.csv,.kdbx,.1pux,.zip,.xml,.pgp,application/json,text/csv,application/zip';

/** Lets the page draw ("Öffnet …") before the key derivation holds it up. */
const nextFrame = () =>
  new Promise<void>((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));

/**
 * Moving in from another password manager: pick the app (or let UwULock tell), pick the file,
 * give a KeePass file its password, look at what will come in, then import. The file is read
 * here in the browser; what it holds stays in memory only until the import or the cancel.
 */
export function ImportSettings() {
  useLanguage();
  const [source, setSource] = useState<Source | 'auto'>('auto');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [locked, setLocked] = useState<ImportFile | null>(null);
  const [parsed, setParsed] = useState<Parsed | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const pick = async (chosen: File | undefined) => {
    if (input.current) input.current.value = '';
    if (!chosen) return;
    setResult(null);
    setBusy(true);
    try {
      // Before the file is read into memory at all.
      checkFileSize(chosen.size);
      const file = { name: chosen.name, bytes: new Uint8Array(await chosen.arrayBuffer()) };
      if (needsPassword(file.bytes) && (source === 'auto' || source === 'keepass')) {
        setLocked(file);
      } else {
        setParsed(await readImport(file, source));
      }
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const done = (count: number) => {
    setParsed(null);
    setResult({ tone: 'info', text: t('{n} Einträge importiert ✧', { n: count }) });
  };

  return (
    <>
      <Row
        label={t('Importieren')}
        description={t(
          'Aus Bitwarden, Vaultwarden, UwULock, KeePass, KeePassXC, 1Password, Chrome, Edge, Firefox, Apple Passwörter, Proton Pass oder LastPass. Die Datei wird nur hier im Browser gelesen, und du siehst vorher, was kommt.',
        )}
      >
        <select
          className="select"
          value={source}
          aria-label={t('Importieren aus')}
          onChange={(e) => setSource(e.target.value as Source | 'auto')}
          disabled={busy}
        >
          <option value="auto">{t('Automatisch erkennen')}</option>
          {SOURCES.map((option) => (
            <option key={option.value} value={option.value}>
              {t(option.label)}
            </option>
          ))}
        </select>
        <input
          ref={input}
          type="file"
          accept={ACCEPT}
          hidden
          onChange={(e) => void pick(e.target.files?.[0])}
        />
        <button onClick={() => input.current?.click()} disabled={busy}>
          {busy ? t('Liest …') : t('Datei wählen …')}
        </button>
      </Row>
      <ResultLine result={result} />
      {locked && (
        <KeepassPrompt
          file={locked}
          onCancel={() => setLocked(null)}
          onOpen={(opened) => {
            setLocked(null);
            setParsed(opened);
          }}
        />
      )}
      {parsed && <ImportPreview parsed={parsed} onCancel={() => setParsed(null)} onDone={done} />}
    </>
  );
}

/** A KeePass file's password and, if it has one, its key file. */
function KeepassPrompt({
  file,
  onCancel,
  onOpen,
}: {
  file: ImportFile;
  onCancel: () => void;
  onOpen: (parsed: Parsed) => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [keyFile, setKeyFile] = useState<{ name: string; bytes: Uint8Array } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keyInput = useRef<HTMLInputElement>(null);
  const ready = Boolean(password || keyFile);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    await nextFrame();
    try {
      const credentials = { password, keyFile: keyFile?.bytes ?? null };
      onOpen(await readImport(file, 'keepass', { credentials, kdf: wasmKdf }));
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const pickKey = async (chosen: File | undefined) => {
    if (keyInput.current) keyInput.current.value = '';
    if (!chosen) return;
    try {
      checkFileSize(chosen.size);
    } catch (e) {
      setError(errorText(e));
      return;
    }
    setKeyFile({ name: chosen.name, bytes: new Uint8Array(await chosen.arrayBuffer()) });
  };

  return (
    <Modal
      title={t('KeePass-Datei öffnen')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void submit()}
            disabled={busy || !ready}
          >
            {busy ? t('Öffnet …') : t('Öffnen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={submit}>
        <p className="dialog-lead">
          {t(
            '„{name}“ ist mit einem Passwort geschützt. UwULock öffnet die Datei hier im Browser; das Passwort geht nirgendwohin.',
            { name: file.name },
          )}
        </p>
        <label className="field">
          <span>{t('Passwort der Datei')}</span>
          <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
        </label>
        <div className="field">
          <span id="import-key-file">{t('Schlüsseldatei (wenn die Datei eine hat)')}</span>
          <div className="import-key-file" aria-labelledby="import-key-file" role="group">
            <input
              ref={keyInput}
              type="file"
              hidden
              onChange={(e) => void pickKey(e.target.files?.[0])}
            />
            <button type="button" onClick={() => keyInput.current?.click()} disabled={busy}>
              {keyFile ? t('Andere wählen …') : t('Schlüsseldatei wählen …')}
            </button>
            {keyFile && (
              <>
                <span className="import-key-name">{keyFile.name}</span>
                <button
                  type="button"
                  onClick={() => setKeyFile(null)}
                  disabled={busy}
                  aria-label={t('Schlüsseldatei entfernen')}
                  data-secondary
                >
                  {t('Entfernen')}
                </button>
              </>
            )}
          </div>
        </div>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}

const TYPE_LABELS: Record<ItemType, string> = {
  [ItemType.Login]: N_('Login'),
  [ItemType.Note]: N_('Notiz'),
  [ItemType.Card]: N_('Karte'),
  [ItemType.Identity]: N_('Identität'),
  [ItemType.SshKey]: N_('Schlüssel (SSH)'),
};

/** What the file holds, before any of it goes to the vault. */
function ImportPreview({
  parsed,
  onCancel,
  onDone,
}: {
  parsed: Parsed;
  onCancel: () => void;
  onDone: (count: number) => void;
}) {
  useLanguage();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const summary = summarize(parsed);
  const total = summary.items.length;
  const app = t(SOURCES.find((s) => s.value === parsed.source)?.label ?? '');
  const counts = [
    [summary.logins, t('Logins')],
    [summary.notes, t('Notizen')],
    [summary.cards, t('Karten')],
    [summary.identities, t('Identitäten')],
    [summary.sshKeys, t('SSH-Schlüssel')],
    [summary.wifi, t('WLANs')],
  ].filter(([n]) => Number(n) > 0) as [number, string][];

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const count = await importVault(parsed.submit.format, parsed.submit.text);
      await syncNow();
      onDone(count);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('Import prüfen')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void run()}
            disabled={busy || total === 0}
          >
            {busy ? t('Importiert …') : t('{n} Einträge importieren', { n: total })}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t('{app}, {format}: {n} Einträge.', { app, format: parsed.format, n: total })}{' '}
        {t('Noch ist nichts im Tresor; das passiert erst mit „Importieren“.')}
      </p>
      {counts.length > 0 && (
        <ul className="import-counts" aria-label={t('Einträge nach Art')}>
          {counts.map(([n, label]) => (
            <li key={label}>
              <strong>{n}</strong> {label}
            </li>
          ))}
        </ul>
      )}
      {summary.folders.length > 0 && (
        <p className="import-folders">
          <span>{t('Neue Ordner:')}</span> {summary.folders.join(', ')}
        </p>
      )}
      {parsed.warnings.length > 0 && (
        <ul className="import-warnings" aria-label={t('Hinweise')}>
          {parsed.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}
      <ul className="import-list" tabIndex={0} aria-label={t('Einträge')} data-autofocus>
        {summary.items.slice(0, LIST_LIMIT).map((item, i) => (
          <li key={i}>
            <span className="import-item-name">{item.name}</span>
            <span className="import-item-detail">
              {[
                item.wifi ? t('WLAN') : t(TYPE_LABELS[item.type]),
                item.detail,
                item.folder ?? t('Ohne Ordner'),
              ]
                .filter(Boolean)
                .join(' · ')}
            </span>
            {item.totp && (
              <span className="chip" title={t('Mit Einmalcodes (TOTP)')}>
                TOTP
              </span>
            )}
          </li>
        ))}
        {total > LIST_LIMIT && (
          <li className="import-item-more">{t('… und {n} weitere', { n: total - LIST_LIMIT })}</li>
        )}
      </ul>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </Modal>
  );
}
