import { useCallback, useEffect, useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import {
  Button,
  ButtonRow,
  Callout,
  Card,
  Checkbox,
  DangerZone,
  Field,
  FormRow,
  Modal,
  Section,
  Segmented,
  SettingRow,
  Table,
  TextField,
  Toggle,
} from '../components/ui';
import { PasswordPrompt, ResultLine, type Result } from '../components/web/controls';
import { Explain, NumberInput } from './fields';
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
import { EmptyNote } from '../components/NyuStates';

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
  const [newestHidden, setNewestHidden] = useState(false);
  const [confirmingKey, setConfirmingKey] = useState<string | null>(null);
  const [restoring, setRestoring] = useState<Snapshot | null>(null);
  const [askingSave, setAskingSave] = useState(false);
  const [askingForget, setAskingForget] = useState(false);

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

  // Only a folder of this machine takes backups unencrypted.
  const plainAllowed = target?.kind === 'folder';
  const forgetsKey = view.encrypted && !draft.encrypted;
  const save = async (password: string) => {
    const saved = await saveOffsite(draft, password, forgetsKey);
    setAskingSave(false);
    setView(saved);
    setDraft(draftOf(saved));
    if (saved.recoveryKey) setShownKey(saved.recoveryKey);
    setResult({ tone: 'info', text: t('Gespeichert ✧') });
  };

  const status = view.status;
  return (
    <div className="offsite">
      <Section
        heading={t('Backups außer Haus')}
        lead={t(
          'Jede Nacht und auf Knopfdruck auf ein anderes System: dedupliziert (nur Neues geht hoch) und verschlüsselt. Enthält die Datenbank, Anhänge, Send-Dateien, Datei-Anfragen und die Schlüssel des Servers.',
        )}
      >
        {view.encryptionRequired && (
          <Callout tone="error">
            {t(
              'Diese Backups gehen unverschlüsselt per SFTP oder S3 und laufen deshalb nicht mehr. Speichere die Einstellungen verschlüsselt, an einem neuen Ort.',
            )}
          </Callout>
        )}
        <SettingRow
          label={t('Backups außer Haus an')}
          description={
            target
              ? t('Jede Nacht zur eingestellten Zeit, dazu jederzeit mit „Jetzt sichern“.')
              : t('Erst ein Ziel wählen.')
          }
        >
          <Toggle
            label={t('Backups außer Haus an')}
            checked={draft.enabled}
            disabled={!target}
            onChange={(enabled) => setDraft({ ...draft, enabled })}
          />
        </SettingRow>
      </Section>

      <Section
        heading={t('Wohin')}
        lead={t('Ein NAS per SFTP, ein S3-Speicher oder ein eingehängter Ordner.')}
      >
        <SettingRow label={t('Ziel')}>
          <Segmented
            label={t('Ziel')}
            value={target?.kind ?? ('' as OffsiteKind)}
            onChange={(kind) =>
              setDraft({
                ...draft,
                target: blankTarget(kind),
                encrypted: kind === 'folder' ? draft.encrypted : true,
              })
            }
            options={KINDS.map((k) => ({ value: k.value, label: t(k.label) }))}
          />
        </SettingRow>

        {target?.kind === 'sftp' && (
          <>
            <FormRow min="wide">
              <TextField
                label={t('Server')}
                value={target.host ?? ''}
                placeholder="nas.example.com"
                spellCheck={false}
                onChange={(host) => setTarget({ host })}
              />
              <Field label={t('Port')}>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={target.port ?? 22}
                  onChange={(e) => setTarget({ port: Number(e.target.value) })}
                />
              </Field>
            </FormRow>
            <FormRow min="wide">
              <TextField
                label={t('Benutzer')}
                value={target.user ?? ''}
                spellCheck={false}
                onChange={(user) => setTarget({ user })}
              />
              <TextField
                label={t('Ordner auf dem Server')}
                value={target.path ?? ''}
                placeholder="/volume1/backups/uwulock"
                spellCheck={false}
                onChange={(path) => setTarget({ path })}
              />
            </FormRow>
            <SettingRow
              label={t('Anmeldung')}
              description={t('Mit dem Schlüssel des Servers ist sicherer als mit einem Passwort.')}
            >
              <Segmented
                label={t('Anmeldung')}
                value={target.method ?? 'key'}
                onChange={(method) => setTarget({ method })}
                options={[
                  { value: 'key', label: t('Schlüssel des Servers') },
                  { value: 'password', label: t('Passwort') },
                ]}
              />
            </SettingRow>
            {target.method === 'password' ? (
              <Field
                label={t('Passwort')}
                hint={
                  view.target?.passwordSet
                    ? t(
                        'Gespeichert. Leer lassen behält es, solange Server und Benutzer gleich bleiben.',
                      )
                    : undefined
                }
              >
                <PasswordInput
                  value={target.password ?? ''}
                  onChange={(password) => setTarget({ password })}
                  autoComplete="new-password"
                />
              </Field>
            ) : view.target?.publicKey ? (
              <Card
                heading={t('Für ~/.ssh/authorized_keys des Backup-Benutzers')}
                aside={
                  <Button
                    size="small"
                    icon="copy"
                    onClick={() =>
                      void navigator.clipboard
                        .writeText(view.target?.publicKey ?? '')
                        .then(() => toast(t('Kopiert ✧'), 'info'))
                    }
                  >
                    {t('Kopieren')}
                  </Button>
                }
              >
                <code className="mono wrap">{view.target.publicKey}</code>
              </Card>
            ) : (
              <p className="field-hint">
                {t('Nach dem Speichern steht hier der öffentliche Schlüssel des Servers.')}
              </p>
            )}
            {view.target?.hostKey && (
              <Card
                heading={t('Host-Schlüssel des Backup-Servers')}
                aside={
                  <Button
                    size="small"
                    variant="quiet-danger"
                    disabled={busy}
                    onClick={() => setAskingForget(true)}
                  >
                    {t('Vergessen …')}
                  </Button>
                }
              >
                <code className="mono wrap">{view.target.hostKey}</code>
              </Card>
            )}
          </>
        )}
        {target?.kind === 's3' && (
          <>
            <FormRow min="wide">
              <TextField
                label={t('S3-Adresse (ohne Bucket)')}
                value={target.endpoint ?? ''}
                placeholder="https://s3.eu-central-1.amazonaws.com"
                spellCheck={false}
                onChange={(endpoint) => setTarget({ endpoint })}
              />
              <TextField
                label={t('Region')}
                value={target.region ?? ''}
                spellCheck={false}
                onChange={(region) => setTarget({ region })}
              />
            </FormRow>
            <FormRow min="wide">
              <TextField
                label={t('Bucket')}
                value={target.bucket ?? ''}
                spellCheck={false}
                onChange={(bucket) => setTarget({ bucket })}
              />
              <TextField
                label={t('Ordner im Bucket')}
                value={target.prefix ?? ''}
                spellCheck={false}
                onChange={(prefix) => setTarget({ prefix })}
              />
            </FormRow>
            <FormRow min="wide">
              <TextField
                label={t('Access Key')}
                value={target.accessKey ?? ''}
                spellCheck={false}
                onChange={(accessKey) => setTarget({ accessKey })}
              />
              <Field
                label={t('Secret Key')}
                hint={
                  view.target?.secretKeySet
                    ? t('Gespeichert. Leer lassen behält ihn für denselben Bucket und Access Key.')
                    : undefined
                }
              >
                <PasswordInput
                  value={target.secretKey ?? ''}
                  onChange={(secretKey) => setTarget({ secretKey })}
                  autoComplete="new-password"
                />
              </Field>
            </FormRow>
            <Checkbox
              label={t('Bucket im Pfad (MinIO und ähnliche)')}
              checked={target.pathStyle ?? false}
              onChange={(pathStyle) => setTarget({ pathStyle })}
            />
          </>
        )}
        {target?.kind === 'folder' && (
          <TextField
            label={t('Ordner (eingehängt, außerhalb der Daten)')}
            value={target.path ?? ''}
            placeholder="/backup"
            spellCheck={false}
            onChange={(path) => setTarget({ path })}
          />
        )}
      </Section>

      <Section
        heading={t('Zeitplan und Aufbewahrung')}
        lead={t('Wann gesichert wird, und wie viele ältere Stände am Ziel bleiben.')}
      >
        <SettingRow
          label={t('Jede Nacht um')}
          description={t('In UTC, der Weltzeit ohne Sommerzeit.')}
        >
          <input
            type="time"
            aria-label={t('Jede Nacht um (UTC)')}
            value={`${pad(draft.hour)}:${pad(draft.minute)}`}
            onChange={(e) => {
              const [hour, minute] = e.target.value.split(':').map(Number);
              setDraft({ ...draft, hour: hour ?? 0, minute: minute ?? 0 });
            }}
          />
        </SettingRow>
        <SettingRow
          label={t('Tägliche Stände aufheben')}
          description={t('Von jedem der letzten Tage einer.')}
        >
          <NumberInput
            label={t('Tägliche Stände aufheben')}
            unit={t('Tage')}
            min={0}
            max={1000}
            value={draft.retention.days}
            onChange={(days) =>
              setDraft({ ...draft, retention: { ...draft.retention, days: days ?? 0 } })
            }
          />
        </SettingRow>
        <SettingRow
          label={t('Wöchentliche Stände aufheben')}
          description={t('Danach einer pro Woche.')}
        >
          <NumberInput
            label={t('Wöchentliche Stände aufheben')}
            unit={t('Wochen')}
            min={0}
            max={1000}
            value={draft.retention.weeks}
            onChange={(weeks) =>
              setDraft({ ...draft, retention: { ...draft.retention, weeks: weeks ?? 0 } })
            }
          />
        </SettingRow>
        <SettingRow
          label={t('Monatliche Stände aufheben')}
          description={t('Und danach einer pro Monat.')}
        >
          <NumberInput
            label={t('Monatliche Stände aufheben')}
            unit={t('Monate')}
            min={0}
            max={1000}
            value={draft.retention.months}
            onChange={(months) =>
              setDraft({ ...draft, retention: { ...draft.retention, months: months ?? 0 } })
            }
          />
        </SettingRow>
        <SettingRow
          label={t('Warnen nach')}
          description={t('Ist das letzte gelungene Backup älter, meldet es die Übersicht.')}
        >
          <NumberInput
            label={t('Warnen nach')}
            unit={t('Stunden')}
            min={1}
            max={2160}
            value={draft.warnAfterHours}
            onChange={(warnAfterHours) =>
              setDraft({ ...draft, warnAfterHours: warnAfterHours ?? 0 })
            }
          />
        </SettingRow>
      </Section>

      <Section heading={t('Verschlüsselung')}>
        <SettingRow
          label={t('Verschlüsselt')}
          description={
            plainAllowed ? (
              <Explain recommended={t('an')}>
                {t(
                  'Der Wiederherstellungsschlüssel erscheint einmal nach dem Speichern: Heb ihn getrennt vom Server auf. Liegen erst Backups am Ziel, lässt sich das nicht mehr ändern.',
                )}
              </Explain>
            ) : (
              t(
                'Backups per SFTP oder S3 sind immer verschlüsselt. Der Wiederherstellungsschlüssel erscheint einmal nach dem Speichern: Heb ihn getrennt vom Server auf.',
              )
            )
          }
        >
          <Toggle
            label={t('Verschlüsselt')}
            checked={draft.encrypted || !plainAllowed}
            disabled={!plainAllowed}
            onChange={(encrypted) => setDraft({ ...draft, encrypted })}
          />
        </SettingRow>
        {plainAllowed && !draft.encrypted && (
          <Callout tone="error">
            {t(
              'Unverschlüsselt liegt die ganze Datenbank lesbar im Ordner: Konten, Passwort-Hashes, die verschlüsselten Tresore. Die Schlüssel des Servers bleiben weg; nach einem Zurückspielen melden sich alle neu an, und SSO sowie UwUMail müssen neu eingerichtet werden. Zurückspielen geht dann nur über die Kommandozeile.',
            )}
          </Callout>
        )}
      </Section>

      <ButtonRow>
        <Button variant="primary" disabled={busy || !dirty} onClick={() => setAskingSave(true)}>
          {t('Speichern')}
        </Button>
        <Button
          disabled={busy || dirty || !view.target}
          onClick={() =>
            void run(async () => {
              const tested = await testOffsite();
              if (tested.confirmed === false && tested.hostKey) {
                setConfirmingKey(tested.hostKey);
                return;
              }
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
        </Button>
        <Button
          disabled={busy || dirty || !view.target || view.running}
          onClick={() =>
            void run(async () => {
              await runOffsite();
              await load();
            })
          }
        >
          {view.running ? t('Läuft …') : t('Jetzt sichern')}
        </Button>
        {view.encrypted && (
          <Button variant="quiet" disabled={busy} onClick={() => setAskingKey(true)}>
            {t('Wiederherstellungsschlüssel zeigen')}
          </Button>
        )}
      </ButtonRow>
      <ResultLine result={result} />

      <Section heading={t('Letzter Lauf')}>
        <Card as="div">
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
            <Callout tone="error">
              {t('Der letzte Versuch ging nicht: {error}', { error: status.lastError })}
            </Callout>
          )}
        </Card>
      </Section>

      <DangerZone
        heading={t('Zurückspielen')}
        lead={t(
          'Holt einen Stand vom Ziel zurück und ersetzt alles auf diesem Server. Vorher wird der jetzige Stand ein lokales Backup.',
        )}
      >
        <ButtonRow>
          <Button
            disabled={busy || !view.target}
            onClick={() =>
              void run(async () => {
                const got = await snapshots();
                setList(got.data);
                setNewestHidden(got.lastWrittenMissing === true);
              })
            }
          >
            {t('Stände am Ziel zeigen')}
          </Button>
        </ButtonRow>
        {list && list.length > 0 && (
          <Table
            label={t('Stände am Ziel')}
            head={
              <>
                <th>{t('Stand')}</th>
                <th>{t('Größe')}</th>
                <th>{t('Version')}</th>
                <th>
                  <span className="sr-only">{t('Aktionen')}</span>
                </th>
              </>
            }
          >
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
                  <Button
                    size="small"
                    variant="quiet-danger"
                    onClick={() => setRestoring(snapshot)}
                  >
                    {t('Zurückspielen')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
        {list && newestHidden && (
          <Callout tone="warning">
            {t(
              'Der letzte Stand, den dieser Server geschrieben hat, fehlt am Ziel. Wer das Ziel verwaltet, kann Stände verstecken: Spiel nichts zurück, bevor du weißt, warum.',
            )}
          </Callout>
        )}
        {list?.length === 0 && <EmptyNote>{t('Noch keine Stände am Ziel.')}</EmptyNote>}
      </DangerZone>
      {confirmingKey && (
        <Modal
          title={t('Host-Schlüssel bestätigen?')}
          tone="warning"
          onCancel={() => setConfirmingKey(null)}
          footer={
            <>
              <span className="spacer" />
              <Button data-secondary onClick={() => setConfirmingKey(null)}>
                {t('Abbrechen')}
              </Button>
              <Button
                variant="primary"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const key = confirmingKey;
                    setConfirmingKey(null);
                    await testOffsite(key);
                    setResult({
                      tone: 'info',
                      text: t('Verbindung steht ✧ Host-Schlüssel gemerkt: {key}', { key }),
                    });
                    await load();
                  })
                }
              >
                {t('Schlüssel vertrauen')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Der Backup-Server zeigt diesen Host-Schlüssel. Vergleiche ihn mit dem des Servers (dort: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub). Erst danach meldet sich dieser Server dort an.',
            )}
          </p>
          <code className="mono wrap">{confirmingKey}</code>
        </Modal>
      )}

      {shownKey && (
        <Modal
          title={t('Dein Wiederherstellungsschlüssel')}
          tone="warning"
          onCancel={() => setShownKey(null)}
          footer={
            <>
              <Button
                icon="copy"
                onClick={() =>
                  void navigator.clipboard
                    .writeText(shownKey)
                    .then(() => toast(t('Kopiert ✧'), 'info'))
                }
              >
                {t('Kopieren')}
              </Button>
              <span className="spacer" />
              <Button variant="primary" onClick={() => setShownKey(null)}>
                {t('Ich habe ihn sicher aufgehoben')}
              </Button>
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
      {askingSave && (
        <PasswordPrompt
          title={t('Backups außer Haus speichern?')}
          tone={forgetsKey ? 'warning' : 'default'}
          lead={
            forgetsKey
              ? t(
                  'Ohne Verschlüsselung vergisst der Server den Wiederherstellungsschlüssel. Die verschlüsselten Backups lassen sich dann nur noch mit dem Schlüssel lesen, den du aufgehoben hast.',
                )
              : t(
                  'Hier entscheidet sich, wohin die ganze Datenbank geht. Deshalb braucht jede Änderung dein Master-Passwort.',
                )
          }
          confirm={t('Speichern')}
          onCancel={() => setAskingSave(false)}
          action={save}
        />
      )}
      {askingForget && (
        <PasswordPrompt
          title={t('Host-Schlüssel vergessen?')}
          tone="warning"
          lead={t(
            'Der nächste Test vertraut dem Schlüssel, den der Backup-Server dann zeigt. Tu das nur, wenn du weißt, warum er sich geändert hat.',
          )}
          confirm={t('Vergessen')}
          onCancel={() => setAskingForget(false)}
          action={async (password) => {
            const next = await forgetHostKey(password);
            setAskingForget(false);
            setView(next);
            setResult({
              tone: 'info',
              text: t('Vergessen. Der nächste Test merkt sich den neuen.'),
            });
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
    </div>
  );
}
