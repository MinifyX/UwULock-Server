import { useEffect, useRef, useState } from 'react';
import type { ItemSummary } from '../../lib/api';
import {
  deleteVersion,
  hasOwnIcon,
  iconFromDevice,
  iconFromFile,
  iconLibrary,
  isLocalHost,
  itemVersions,
  libraryIconBlob,
  openVersion,
  removeOwnIcon,
  removeReminder,
  reminderOf,
  restoreVersion,
  searchLibrary,
  suggestLibrary,
  setOwnIcon,
  setReminder,
  toIconPng,
  useComfort,
  type CipherVersion,
  type Library,
  type LibraryIcon,
  type OpenedVersion,
} from '../../lib/comfort';
import { useFeature } from '../../lib/branding';
import { errorText } from '../../lib/errors';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { useSwitch } from '../../lib/switches';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { ItemTile } from '../ItemTile';
import { Modal } from '../Modal';
import { radioArrows } from './controls';

/**
 * What the web vault adds to an item: its icon, a reminder to renew its password, and its
 * earlier versions. Each in a card of its own below the item's fields, where the server has
 * the feature switched on.
 */
export function ItemComfort({
  summary,
  passwordDate,
}: {
  summary: ItemSummary;
  /** When the login's password was last changed, for a reminder after some months. */
  passwordDate: string | null;
}) {
  useLanguage();
  useComfort();
  const ownIcons = useSwitch('own-icons');
  const reminders = useSwitch('reminders');
  // Versions also need the admin to keep some (more than 0 per item).
  const versions = useFeature('versions');
  if (summary.deleted) return null;
  return (
    <>
      {ownIcons && <IconCard summary={summary} />}
      {reminders && <ReminderCard summary={summary} passwordDate={passwordDate} />}
      {versions && <VersionsCard summary={summary} />}
    </>
  );
}

// ── The icon ──────────────────────────────────────────────

function IconCard({ summary }: { summary: ItemSummary }) {
  const [busy, setBusy] = useState(false);
  const [library, setLibrary] = useState(false);
  const libraryOn = useFeature('icon-library');
  const input = useRef<HTMLInputElement>(null);
  const own = hasOwnIcon(summary.id);
  const local = summary.host && isLocalHost(summary.host) ? summary.host : null;

  const keep = async (make: () => Promise<Uint8Array>, done: string) => {
    setBusy(true);
    try {
      await setOwnIcon(summary.id, await make());
      toast(done);
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
      if (input.current) input.current.value = '';
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await removeOwnIcon(summary.id);
      toast(t('Eigenes Icon entfernt.'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="detail-card comfort-card">
      <h3 className="detail-card-title">{t('Icon')}</h3>
      <div className="comfort-icon-row">
        <ItemTile item={summary} size="large" />
        <p className="field-hint">
          {own
            ? t(
                'Ein eigenes Icon, verschlüsselt gespeichert. Die offiziellen Bitwarden-Apps zeigen das der Website.',
              )
            : local
              ? t(
                  'Ein Gerät im Heimnetz: dieser Server fragt es nie. Hol das Icon vom Gerät oder lade eins hoch.',
                )
              : t('Das Icon der Website, geholt von diesem Server. Oder wähle ein eigenes.')}
        </p>
      </div>
      <div className="comfort-actions">
        <input
          ref={input}
          type="file"
          hidden
          accept="image/png,image/jpeg,image/webp,image/svg+xml"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void keep(() => iconFromFile(file), t('Icon gespeichert ✧'));
          }}
        />
        <button className="quiet" disabled={busy} onClick={() => input.current?.click()}>
          <Icon name="upload" size={15} />
          {t('Hochladen …')}
        </button>
        {libraryOn && (
          <button className="quiet" disabled={busy} onClick={() => setLibrary(true)}>
            <Icon name="grid" size={15} />
            {t('Aus der Bibliothek …')}
          </button>
        )}
        {local && (
          <button
            className="quiet"
            disabled={busy}
            onClick={() =>
              void keep(() => iconFromDevice(local), t('Icon vom Gerät gespeichert ✧'))
            }
          >
            <Icon name="home" size={15} />
            {t('Vom Gerät holen')}
          </button>
        )}
        {own && (
          <button className="quiet danger-text" disabled={busy} onClick={() => void remove()}>
            <Icon name="trash" size={15} />
            {t('Eigenes Icon entfernen')}
          </button>
        )}
      </div>
      {local && !own && (
        <LibrarySuggestions
          host={local}
          name={summary.name}
          onPick={(blob) => void keep(() => toIconPng(blob), t('Icon gespeichert ✧'))}
        />
      )}
      {library && (
        <LibraryDialog
          initial={summary.name}
          onCancel={() => setLibrary(false)}
          onPick={(blob) => {
            setLibrary(false);
            void keep(() => toIconPng(blob), t('Icon gespeichert ✧'));
          }}
        />
      )}
    </section>
  );
}

function LibraryPreview({ icon, onPick }: { icon: LibraryIcon; onPick: (blob: Blob) => void }) {
  const [variant, setVariant] = useState('default');
  const [picture, setPicture] = useState<{ url: string; blob: Blob } | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let url: string | null = null;
    let gone = false;
    setPicture(null);
    setFailed(false);
    libraryIconBlob(icon, variant).then(
      (blob) => {
        if (gone) return;
        url = URL.createObjectURL(blob);
        setPicture({ url, blob });
      },
      () => !gone && setFailed(true),
    );
    return () => {
      gone = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [icon, variant]);
  return (
    <li className="library-icon">
      <button
        type="button"
        disabled={!picture}
        onClick={() => picture && onPick(picture.blob)}
        aria-label={t('{name} wählen', { name: icon.name })}
      >
        <span className="library-picture">
          {picture ? <img src={picture.url} alt="" /> : failed ? '×' : '…'}
        </span>
        <span className="library-name">{icon.name}</span>
      </button>
      {icon.variants.length > 1 && (
        <select
          value={variant}
          aria-label={t('Variante von {name}', { name: icon.name })}
          onChange={(event) => setVariant(event.target.value)}
        >
          {icon.variants.map((name) => (
            <option key={name} value={name}>
              {name === 'light' ? t('hell') : name === 'dark' ? t('dunkel') : t('normal')}
            </option>
          ))}
        </select>
      )}
    </li>
  );
}

/** For a device in the home network: library icons that fit its name or the item's. */
function LibrarySuggestions({
  host,
  name,
  onPick,
}: {
  host: string;
  name: string;
  onPick: (blob: Blob) => void;
}) {
  const [index, setIndex] = useState<Library | null>(null);
  useEffect(() => {
    let gone = false;
    iconLibrary().then(
      (library) => !gone && setIndex(library),
      () => undefined,
    );
    return () => {
      gone = true;
    };
  }, []);
  const found = index ? suggestLibrary(index, host, name) : [];
  if (!found.length) return null;
  return (
    <div className="library-suggestions">
      <p className="field-hint">{t('Passt vielleicht, aus der Bibliothek:')}</p>
      <ul className="library-grid">
        {found.map((icon) => (
          <LibraryPreview key={`${icon.source}/${icon.id}`} icon={icon} onPick={onPick} />
        ))}
      </ul>
    </div>
  );
}

function LibraryDialog({
  initial,
  onCancel,
  onPick,
}: {
  initial: string;
  onCancel: () => void;
  onPick: (blob: Blob) => void;
}) {
  useLanguage();
  const [index, setIndex] = useState<Library | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState(initial);
  useEffect(() => {
    iconLibrary().then(setIndex, (e: unknown) => setError(errorText(e)));
  }, []);
  const found = index ? searchLibrary(index, query, 30) : [];
  return (
    <Modal
      title={t('Icon aus der Bibliothek')}
      size="wide"
      onCancel={onCancel}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onCancel}>
            {t('Abbrechen')}
          </button>
        </>
      }
    >
      <label className="field">
        <span>{t('Suchen')}</span>
        <input
          type="search"
          value={query}
          autoFocus
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t('Zum Beispiel Nextcloud')}
        />
      </label>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {!index && !error && <p className="field-hint">{t('Lädt die Bibliothek …')}</p>}
      {index && (
        <>
          {found.length ? (
            <ul className="library-grid">
              {found.map((icon) => (
                <LibraryPreview key={`${icon.source}/${icon.id}`} icon={icon} onPick={onPick} />
              ))}
            </ul>
          ) : (
            <p className="field-hint">
              {query.trim() ? t('Kein Icon gefunden.') : t('Tippe einen Namen ein.')}
            </p>
          )}
          <p className="field-hint library-credit">
            {index.sources.map((source) => (
              <span key={source.id}>
                <a href={source.url} target="_blank" rel="noreferrer noopener">
                  {source.name}
                </a>{' '}
                ·{' '}
                <a href={source.licenseUrl} target="_blank" rel="noreferrer noopener">
                  {source.license}
                </a>{' '}
                · {source.attribution}
              </span>
            ))}{' '}
            {t(
              'Das gewählte Icon holt dieser Server; im Eintrag wird es verschlüsselt gespeichert.',
            )}
          </p>
        </>
      )}
    </Modal>
  );
}

// ── The reminder ──────────────────────────────────────────

function ReminderCard({
  summary,
  passwordDate,
}: {
  summary: ItemSummary;
  passwordDate: string | null;
}) {
  const reminder = reminderOf(summary.id);
  const [editing, setEditing] = useState(false);
  const [mode, setMode] = useState<'months' | 'day'>(reminder?.everyMonths ? 'months' : 'day');
  const [months, setMonths] = useState(reminder?.everyMonths ?? 12);
  const [day, setDay] = useState(reminder?.due ?? '');
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      await setReminder(summary.id, mode === 'months' ? { everyMonths: months } : { due: day });
      setEditing(false);
      toast(t('Erinnerung gespeichert ✧'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await removeReminder(summary.id);
      toast(t('Erinnerung entfernt.'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="detail-card comfort-card">
      <h3 className="detail-card-title">{t('Erinnerung ans Erneuern')}</h3>
      {reminder && !editing && (
        <p className="comfort-line">
          {reminder.isDue && <span className="chip chip-due">{t('Fällig')}</span>}
          {reminder.everyMonths
            ? t('Alle {n} Monate, das nächste Mal am {day}.', {
                n: reminder.everyMonths,
                day: reminder.due,
              })
            : t('Am {day}.', { day: reminder.due })}
        </p>
      )}
      {!reminder && !editing && (
        <p className="field-hint">
          {t(
            'Der Server kennt nur den Tag und schickt dann eine Mail, die den Eintrag nicht nennt.',
          )}
        </p>
      )}
      {editing && (
        <div className="comfort-form">
          <div
            className="segmented"
            role="radiogroup"
            aria-label={t('Wann')}
            onKeyDown={radioArrows}
          >
            <button
              type="button"
              role="radio"
              aria-checked={mode === 'months'}
              tabIndex={mode === 'months' ? 0 : -1}
              onClick={() => setMode('months')}
            >
              {t('Nach Monaten')}
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={mode === 'day'}
              tabIndex={mode === 'day' ? 0 : -1}
              onClick={() => setMode('day')}
            >
              {t('An einem Tag')}
            </button>
          </div>
          {mode === 'months' ? (
            <label className="field">
              <span>
                {passwordDate
                  ? t('Monate nach der letzten Änderung des Passworts')
                  : t('Monate nach dem Anlegen des Eintrags')}
              </span>
              <input
                type="number"
                min={1}
                max={60}
                value={months}
                onChange={(event) =>
                  setMonths(Math.max(1, Math.min(60, Number(event.target.value) || 1)))
                }
              />
            </label>
          ) : (
            <label className="field">
              <span>{t('Tag')}</span>
              <input type="date" value={day} onChange={(event) => setDay(event.target.value)} />
            </label>
          )}
        </div>
      )}
      <div className="comfort-actions">
        {editing ? (
          <>
            <button
              className="primary"
              disabled={busy || (mode === 'day' && !day)}
              onClick={() => void save()}
            >
              {t('Speichern')}
            </button>
            <button className="quiet" disabled={busy} onClick={() => setEditing(false)}>
              {t('Abbrechen')}
            </button>
          </>
        ) : (
          <>
            <button className="quiet" disabled={busy} onClick={() => setEditing(true)}>
              <Icon name="bell" size={15} />
              {reminder ? t('Ändern') : t('Erinnern …')}
            </button>
            {reminder && (
              <button className="quiet danger-text" disabled={busy} onClick={() => void remove()}>
                <Icon name="trash" size={15} />
                {t('Entfernen')}
              </button>
            )}
          </>
        )}
      </div>
    </section>
  );
}

// ── Versions ──────────────────────────────────────────────

function VersionsCard({ summary }: { summary: ItemSummary }) {
  const [open, setOpen] = useState(false);
  const [versions, setVersions] = useState<CipherVersion[] | null>(null);
  const [shown, setShown] = useState<CipherVersion | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setVersions(null);
    itemVersions(summary.id).then(setVersions, (e: unknown) => setError(errorText(e)));
  }, [open, summary.id, summary.revisionDate]);

  return (
    <section className="detail-card comfort-card">
      <button className="history-toggle quiet" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="history" size={15} />
        {t('Frühere Versionen')}
        <Icon name="chevron" size={14} className={open ? 'turned' : undefined} />
      </button>
      {open && error && <p className="field-hint">{error}</p>}
      {open && versions && !versions.length && (
        <p className="field-hint">
          {t('Noch keine: bei jeder Änderung hebt der Server den Stand davor auf.')}
        </p>
      )}
      {open &&
        versions?.map((version) => (
          <div className="detail-row" key={version.id}>
            <div className="detail-text">
              <span className="detail-value">
                {t('Stand vom {when}', {
                  when: when(version.revisionDate) ?? version.revisionDate,
                })}
              </span>
              <span className="detail-label">
                {t('ersetzt {when}', { when: when(version.replacedDate) ?? version.replacedDate })}
              </span>
            </div>
            <div className="detail-actions">
              <button className="quiet" onClick={() => setShown(version)}>
                {t('Ansehen')}
              </button>
            </div>
          </div>
        ))}
      {shown && (
        <VersionDialog
          summary={summary}
          version={shown}
          onClose={() => setShown(null)}
          onChanged={() => {
            setShown(null);
            itemVersions(summary.id).then(setVersions, () => undefined);
          }}
        />
      )}
    </section>
  );
}

function VersionDialog({
  summary,
  version,
  onClose,
  onChanged,
}: {
  summary: ItemSummary;
  version: CipherVersion;
  onClose: () => void;
  onChanged: () => void;
}) {
  useLanguage();
  const [opened, setOpened] = useState<OpenedVersion | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    openVersion(summary.id, version).then(setOpened, (e: unknown) => setError(errorText(e)));
  }, [summary.id, version]);

  const act = async (work: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try {
      await work();
      toast(done);
      onChanged();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const secret = (value: string | null) => (value ? (reveal ? value : '••••••••') : null);
  const rows: [string, string | null][] = opened
    ? [
        [t('Name'), opened.name],
        [t('Benutzername'), opened.login?.username ?? null],
        [t('Passwort'), secret(opened.login?.password ?? null)],
        [t('Einmal-Code (TOTP)'), secret(opened.login?.totp ?? null)],
        [t('Adressen'), opened.login?.uris.join(', ') || null],
        ...Object.entries(opened.card ?? {}).map(
          ([key, value]) =>
            [key, key === 'number' || key === 'code' ? secret(value) : value] as [
              string,
              string | null,
            ],
        ),
        ...Object.entries(opened.identity ?? {}),
        [t('Öffentlicher Schlüssel'), opened.sshKey?.publicKey ?? null],
        ...opened.fields.map(
          (field) =>
            [field.name ?? '?', field.hidden ? secret(field.value) : field.value] as [
              string,
              string | null,
            ],
        ),
        [t('Notizen'), opened.notes],
      ]
    : [];

  return (
    <Modal
      title={t('Stand vom {when}', { when: when(version.revisionDate) ?? version.revisionDate })}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <button
            type="button"
            className="quiet danger-text"
            disabled={busy}
            onClick={() =>
              void act(() => deleteVersion(summary.id, version.id), t('Version gelöscht.'))
            }
          >
            {t('Version löschen')}
          </button>
          <span className="spacer" />
          <button type="button" data-secondary disabled={busy} onClick={onClose}>
            {t('Schließen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || !opened || !summary.revisionDate}
            onClick={() =>
              void act(
                () => restoreVersion(summary.id, version.id, summary.revisionDate ?? ''),
                t('Zurückgeholt ✧ Der Stand davor ist jetzt selbst eine Version.'),
              )
            }
          >
            {t('Zurückholen')}
          </button>
        </>
      }
    >
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {!opened && !error && <p className="field-hint">{t('Entschlüsselt …')}</p>}
      {opened && (
        <>
          <dl className="version-values">
            {rows
              .filter(([, value]) => value)
              .map(([label, value], index) => (
                <div key={index}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
          </dl>
          <button type="button" className="quiet" onClick={() => setReveal(!reveal)}>
            <Icon name="eye" size={15} />
            {reveal ? t('Geheimes verbergen') : t('Geheimes zeigen')}
          </button>
        </>
      )}
    </Modal>
  );
}
