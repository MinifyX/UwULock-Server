import { useCallback, useEffect, useState } from 'react';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import {
  PasswordPrompt,
  ResultLine,
  Row,
  Segmented,
  Toggle,
  type Result,
} from '../components/web/controls';
import { logout } from '../lib/api';
import {
  forgetHostKey,
  offsite,
  recoveryKey,
  restoreSnapshot,
  runOffsite,
  saveOffsite,
  snapshots,
  testOffsite,
  type Offsite as OffsiteView,
  type OffsiteDraft,
  type OffsiteKind,
  type Snapshot,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes, when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

const KINDS: { value: OffsiteKind; label: string }[] = [
  { value: 'sftp', label: 'SFTP' },
  { value: 's3', label: 'S3' },
  { value: 'folder', label: N_('Ordner') },
];

function draftOf(view: OffsiteView): OffsiteDraft {
  return {
    enabled: view.enabled,
    hour: view.hour,
    minute: view.minute,
    retention: { ...view.retention },
    // Encrypted unless somebody decided otherwise: the default for a first setup.
    encrypted: view.target ? view.encrypted : true,
    warnAfterHours: view.warnAfterHours,
    target: view.target ? { ...view.target, password: '', secretKey: '' } : null,
  };
}

function blankTarget(kind: OffsiteKind): NonNullable<OffsiteDraft['target']> {
  switch (kind) {
    case 'sftp':
      return { kind, host: '', port: 22, user: '', path: 'uwulock', method: 'key', password: '' };
    case 's3':
      return {
        kind,
        endpoint: '',
        region: 'us-east-1',
        bucket: '',
        prefix: 'uwulock',
        accessKey: '',
        secretKey: '',
        pathStyle: false,
      };
    default:
      return { kind, path: '/backup' };
  }
}

const pad = (n: number) => String(n).padStart(2, '0');

/**
 * Backups to another system: an SFTP server (a NAS), an S3 bucket or a mounted folder. Every
 * night and on request, deduplicated, encrypted with a recovery key that is shown once.
 */
export function Offsite() {
  useLanguage();
  const [view, setView] = useState<OffsiteView | null>(null);
  const [draft, setDraft] = useState<OffsiteDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [shownKey, setShownKey] = useState<string | null>(null);
  const [askingKey, setAskingKey] = useState(false);
  const [list, setList] = useState<Snapshot[] | null>(null);
  const [restoring, setRestoring] = useState<Snapshot | null>(null);

  const load = useCallback(async () => {
    try {
      const next = await offsite();
      setView(next);
      setDraft((current) => current ?? draftOf(next));
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    }
  }, []);
  useEffect(() => void load(), [load]);

  // While a backup runs, look again every two seconds.
  useEffect(() => {
    if (!view?.running) return;
    const timer = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(timer);
  }, [view?.running, load]);

  if (!view || !draft) return result ? <ResultLine result={result} /> : null;
  const target = draft.target;
  const setTarget = (change: Partial<NonNullable<OffsiteDraft['target']>>) =>
    setDraft({ ...draft, target: { ...target!, ...change } });
  const dirty = JSON.stringify(draft) !== JSON.stringify(draftOf(view));

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setResult(null);
    try {
      await work();
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const save = () =>
    run(async () => {
      const saved = await saveOffsite(draft);
      setView(saved);
      setDraft(draftOf(saved));
      if (saved.recoveryKey) setShownKey(saved.recoveryKey);
      setResult({ tone: 'info', text: t('Gespeichert ✧') });
    });

  const status = view.status;
  return (
    <section className="channel-card offsite" aria-label={t('Backups außer Haus')}>
      <div className="channel-head">
        <b className="channel-name">{t('Backups außer Haus')}</b>
        <span className="spacer" />
        <Toggle
          label={t('Backups außer Haus an')}
          checked={draft.enabled}
          disabled={!target}
          onChange={(enabled) => setDraft({ ...draft, enabled })}
        />
      </div>
      <p className="settings-lead">
        {t(
          'Jede Nacht und auf Knopfdruck auf ein anderes System: dedupliziert (nur Neues geht hoch) und verschlüsselt. Enthält die Datenbank, Anhänge, Send-Dateien, Datei-Anfragen und die Schlüssel des Servers.',
        )}
      </p>

      <Segmented
        label={t('Ziel')}
        value={target?.kind ?? ('' as OffsiteKind)}
        onChange={(kind) => setDraft({ ...draft, target: blankTarget(kind) })}
        options={KINDS.map((k) => ({ value: k.value, label: t(k.label) }))}
      />

      {target && (
        <div className="field-grid wide">
          {target.kind === 'sftp' && (
            <>
              <label className="field">
                <span>{t('Server')}</span>
                <input
                  value={target.host ?? ''}
                  placeholder="nas.example.com"
                  spellCheck={false}
                  onChange={(e) => setTarget({ host: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Port')}</span>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={target.port ?? 22}
                  onChange={(e) => setTarget({ port: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span>{t('Benutzer')}</span>
                <input
                  value={target.user ?? ''}
                  spellCheck={false}
                  onChange={(e) => setTarget({ user: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Ordner auf dem Server')}</span>
                <input
                  value={target.path ?? ''}
                  placeholder="/volume1/backups/uwulock"
                  spellCheck={false}
                  onChange={(e) => setTarget({ path: e.target.value })}
                />
              </label>
              <div className="field">
                <span>{t('Anmeldung')}</span>
                <Segmented
                  label={t('Anmeldung')}
                  value={target.method ?? 'key'}
                  onChange={(method) => setTarget({ method })}
                  options={[
                    { value: 'key', label: t('Schlüssel des Servers') },
                    { value: 'password', label: t('Passwort') },
                  ]}
                />
              </div>
              {target.method === 'password' ? (
                <label className="field">
                  <span>{t('Passwort')}</span>
                  <PasswordInput
                    value={target.password ?? ''}
                    onChange={(password) => setTarget({ password })}
                    autoComplete="new-password"
                  />
                  {view.target?.passwordSet && (
                    <small className="field-hint">
                      {t(
                        'Gespeichert. Leer lassen behält es, solange Server und Benutzer gleich bleiben.',
                      )}
                    </small>
                  )}
                </label>
              ) : view.target?.publicKey ? (
                <div className="field">
                  <span>{t('Für ~/.ssh/authorized_keys des Backup-Benutzers')}</span>
                  <code className="mono wrap">{view.target.publicKey}</code>
                  <button
                    type="button"
                    onClick={() =>
                      void navigator.clipboard
                        .writeText(view.target?.publicKey ?? '')
                        .then(() => toast(t('Kopiert ✧'), 'info'))
                    }
                  >
                    <Icon name="copy" size={14} />
                    {t('Kopieren')}
                  </button>
                </div>
              ) : (
                <p className="field-hint">
                  {t('Nach dem Speichern steht hier der öffentliche Schlüssel des Servers.')}
                </p>
              )}
              {view.target?.hostKey && (
                <div className="field">
                  <span>{t('Host-Schlüssel des Backup-Servers')}</span>
                  <code className="mono wrap">{view.target.hostKey}</code>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        const next = await forgetHostKey();
                        setView(next);
                        setResult({
                          tone: 'info',
                          text: t('Vergessen. Der nächste Test merkt sich den neuen.'),
                        });
                      })
                    }
                  >
                    {t('Vergessen')}
                  </button>
                </div>
              )}
            </>
          )}
          {target.kind === 's3' && (
            <>
              <label className="field">
                <span>{t('S3-Adresse (ohne Bucket)')}</span>
                <input
                  value={target.endpoint ?? ''}
                  placeholder="https://s3.eu-central-1.amazonaws.com"
                  spellCheck={false}
                  onChange={(e) => setTarget({ endpoint: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Region')}</span>
                <input
                  value={target.region ?? ''}
                  spellCheck={false}
                  onChange={(e) => setTarget({ region: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Bucket')}</span>
                <input
                  value={target.bucket ?? ''}
                  spellCheck={false}
                  onChange={(e) => setTarget({ bucket: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Ordner im Bucket')}</span>
                <input
                  value={target.prefix ?? ''}
                  spellCheck={false}
                  onChange={(e) => setTarget({ prefix: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Access Key')}</span>
                <input
                  value={target.accessKey ?? ''}
                  spellCheck={false}
                  onChange={(e) => setTarget({ accessKey: e.target.value })}
                />
              </label>
              <label className="field">
                <span>{t('Secret Key')}</span>
                <PasswordInput
                  value={target.secretKey ?? ''}
                  onChange={(secretKey) => setTarget({ secretKey })}
                  autoComplete="new-password"
                />
                {view.target?.secretKeySet && (
                  <small className="field-hint">
                    {t('Gespeichert. Leer lassen behält ihn für denselben Bucket und Access Key.')}
                  </small>
                )}
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={target.pathStyle ?? false}
                  onChange={(e) => setTarget({ pathStyle: e.target.checked })}
                />
                <span>{t('Bucket im Pfad (MinIO und ähnliche)')}</span>
              </label>
            </>
          )}
          {target.kind === 'folder' && (
            <label className="field">
              <span>{t('Ordner (eingehängt, außerhalb der Daten)')}</span>
              <input
                value={target.path ?? ''}
                placeholder="/backup"
                spellCheck={false}
                onChange={(e) => setTarget({ path: e.target.value })}
              />
            </label>
          )}
        </div>
      )}

      <div className="field-grid wide">
        <label className="field">
          <span>{t('Jede Nacht um (UTC)')}</span>
          <input
            type="time"
            value={`${pad(draft.hour)}:${pad(draft.minute)}`}
            onChange={(e) => {
              const [hour, minute] = e.target.value.split(':').map(Number);
              setDraft({ ...draft, hour: hour ?? 0, minute: minute ?? 0 });
            }}
          />
        </label>
        <label className="field">
          <span>{t('Tage aufheben')}</span>
          <input
            type="number"
            min={0}
            max={1000}
            value={draft.retention.days}
            onChange={(e) =>
              setDraft({
                ...draft,
                retention: { ...draft.retention, days: Number(e.target.value) },
              })
            }
          />
        </label>
        <label className="field">
          <span>{t('Wochen aufheben')}</span>
          <input
            type="number"
            min={0}
            max={1000}
            value={draft.retention.weeks}
            onChange={(e) =>
              setDraft({
                ...draft,
                retention: { ...draft.retention, weeks: Number(e.target.value) },
              })
            }
          />
        </label>
        <label className="field">
          <span>{t('Monate aufheben')}</span>
          <input
            type="number"
            min={0}
            max={1000}
            value={draft.retention.months}
            onChange={(e) =>
              setDraft({
                ...draft,
                retention: { ...draft.retention, months: Number(e.target.value) },
              })
            }
          />
        </label>
        <label className="field">
          <span>{t('Warnen, wenn das letzte älter ist als (Stunden)')}</span>
          <input
            type="number"
            min={1}
            max={2160}
            value={draft.warnAfterHours}
            onChange={(e) => setDraft({ ...draft, warnAfterHours: Number(e.target.value) })}
          />
        </label>
      </div>
      <Row
        label={t('Verschlüsselt')}
        description={t(
          'Empfohlen. Der Wiederherstellungsschlüssel erscheint einmal nach dem Speichern: Heb ihn getrennt vom Server auf. Liegen erst Backups am Ziel, lässt sich das nicht mehr ändern.',
        )}
      >
        <Toggle
          label={t('Verschlüsselt')}
          checked={draft.encrypted}
          onChange={(encrypted) => setDraft({ ...draft, encrypted })}
        />
      </Row>

      <div className="form-actions">
        <button className="primary" disabled={busy || !dirty} onClick={() => void save()}>
          {t('Speichern')}
        </button>
        <button
          disabled={busy || dirty || !view.target}
          onClick={() =>
            void run(async () => {
              const tested = await testOffsite();
              setResult({
                tone: 'info',
                text: tested.hostKey
                  ? tested.known
                    ? t('Verbindung steht ✧ Host-Schlüssel wie gemerkt.')
                    : t('Verbindung steht ✧ Host-Schlüssel gemerkt: {key}', { key: tested.hostKey })
                  : t('Verbindung steht ✧ Schreiben und Lesen gehen.'),
              });
              await load();
            })
          }
        >
          {t('Verbindung testen')}
        </button>
        <button
          disabled={busy || dirty || !view.target || view.running}
          onClick={() =>
            void run(async () => {
              await runOffsite();
              await load();
            })
          }
        >
          {view.running ? t('Läuft …') : t('Jetzt sichern')}
        </button>
        {view.encrypted && (
          <button className="quiet" disabled={busy} onClick={() => setAskingKey(true)}>
            {t('Wiederherstellungsschlüssel zeigen')}
          </button>
        )}
      </div>
      <ResultLine result={result} />

      <div className="detail-card">
        <p className="detail-line" data-tone={view.stale ? 'warning' : undefined}>
          {status.lastSuccess
            ? t('Zuletzt gelungen: {when}', { when: when(status.lastSuccess) ?? '' })
            : t('Noch kein Backup außer Haus.')}
          {view.stale && ` – ${t('zu alt')}`}
        </p>
        {status.bytes !== null && (
          <p className="detail-line">
            {t('{size} gesichert, davon {uploaded} neu hochgeladen, in {seconds} s', {
              size: bytes(status.bytes),
              uploaded: bytes(status.uploaded ?? 0),
              seconds: status.lastDuration ?? 0,
            })}
          </p>
        )}
        {status.lastError && (
          <p className="form-error" role="alert">
            {t('Der letzte Versuch ging nicht: {error}', { error: status.lastError })}
          </p>
        )}
      </div>

      <div className="form-actions">
        <button
          disabled={busy || !view.target}
          onClick={() =>
            void run(async () => {
              setList(await snapshots());
            })
          }
        >
          {t('Stände am Ziel zeigen')}
        </button>
      </div>
      {list && (
        <table className="admin-table">
          <thead>
            <tr>
              <th>{t('Stand')}</th>
              <th>{t('Größe')}</th>
              <th>{t('Version')}</th>
              <th aria-label={t('Aktionen')} />
            </tr>
          </thead>
          <tbody>
            {list.map((snapshot) => (
              <tr key={snapshot.id}>
                <td>
                  <b>{when(snapshot.date)}</b>
                  <small className="event-detail">
                    {snapshot.hostname} · {snapshot.id}
                  </small>
                </td>
                <td>{bytes(snapshot.bytes)}</td>
                <td>{snapshot.version}</td>
                <td className="row-actions">
                  <button onClick={() => setRestoring(snapshot)}>{t('Zurückspielen')}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {list?.length === 0 && <p className="empty-note">{t('Noch keine Stände am Ziel.')}</p>}

      {shownKey && (
        <Modal
          title={t('Dein Wiederherstellungsschlüssel')}
          tone="warning"
          onCancel={() => setShownKey(null)}
          footer={
            <>
              <button
                onClick={() =>
                  void navigator.clipboard
                    .writeText(shownKey)
                    .then(() => toast(t('Kopiert ✧'), 'info'))
                }
              >
                <Icon name="copy" size={14} />
                {t('Kopieren')}
              </button>
              <span className="spacer" />
              <button className="primary" onClick={() => setShownKey(null)}>
                {t('Ich habe ihn sicher aufgehoben')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Ohne diesen Schlüssel kann niemand die Backups lesen – auch du nicht, wenn der Server weg ist. Heb ihn getrennt vom Server auf, zum Beispiel in deinem Passwortmanager und auf Papier.',
            )}
          </p>
          <code className="recovery-key mono">{shownKey}</code>
        </Modal>
      )}
      {askingKey && (
        <PasswordPrompt
          title={t('Wiederherstellungsschlüssel zeigen?')}
          lead={t('Mit ihm lassen sich alle Backups außer Haus lesen.')}
          confirm={t('Zeigen')}
          onCancel={() => setAskingKey(false)}
          action={async (password) => {
            const key = await recoveryKey(password);
            setAskingKey(false);
            setShownKey(key);
          }}
        />
      )}
      {restoring && (
        <PasswordPrompt
          title={t('Diesen Stand zurückspielen?')}
          tone="warning"
          lead={t(
            'Alles kommt auf den Stand von {when}: Konten, Tresore, Einstellungen, Dateien. Vorher wird der jetzige Stand ein lokales Backup. Die Einstellungen der Backups außer Haus bleiben, wie sie jetzt sind. Danach melden sich alle neu an, du auch.',
            { when: when(restoring.date) ?? '' },
          )}
          confirm={t('Zurückspielen')}
          onCancel={() => setRestoring(null)}
          action={async (password) => {
            const done = await restoreSnapshot(restoring.id, password);
            setRestoring(null);
            toast(
              t('Zurückgespielt ✧ Der Stand davor ist jetzt {name}. Melde dich neu an.', {
                name: done.before,
              }),
              'info',
            );
            await logout();
          }}
        />
      )}
    </section>
  );
}
