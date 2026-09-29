import { useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { errorText } from '../../lib/errors';
import { bytes, when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import {
  deleteArrived,
  deleteFileRequest,
  downloadArrivedFile,
  fileRequests,
  markSeen,
  requestLink,
  resetExtras,
  saveFileRequest,
  submissions,
  takeOver,
  type Arrived,
  type FileRequest,
  type RequestDraft,
} from '../../lib/requests';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { listbox } from '../listbox';
import { BackToList, Panes } from '../panes';
import { PasswordInput } from '../PasswordInput';
import { PasswordPrompt, save } from './controls';

/**
 * File requests: a link somebody without an account uploads files and a message to —
 * encrypted in their browser for this account, so the server keeps only what it cannot read.
 * What arrives can be read here, and taken over into an item.
 */
export function FileRequestsView({ open }: { open?: string | null }) {
  useLanguage();
  const [requests, setRequests] = useState<FileRequest[] | null>(null);
  const [problem, setProblem] = useState<'lost' | 'off' | null>(null);
  const [selected, setSelected] = useState<string | null>(open ?? null);
  const [editing, setEditing] = useState<{ request: FileRequest | null } | null>(null);
  const [deleting, setDeleting] = useState<FileRequest | null>(null);
  const [resetting, setResetting] = useState(false);
  const { showDetail } = useContext(Panes);

  const reload = useCallback(() => {
    fileRequests().then(
      (list) => {
        setRequests(list);
        setProblem(null);
      },
      (e) => {
        const kind = (e as { kind?: string }).kind;
        const code = (e as { body?: { code?: string } }).body?.code;
        if (kind === 'extras-lost') setProblem('lost');
        else if (code === 'feature_off') setProblem('off');
        else toast(errorText(e), 'error');
        setRequests([]);
      },
    );
  }, []);
  useEffect(reload, [reload]);
  useEffect(() => {
    if (open) {
      setSelected(open);
      showDetail();
    }
  }, [open, showDetail]);

  const sorted = useMemo(
    () => [...(requests ?? [])].sort((a, b) => b.creationDate.localeCompare(a.creationDate)),
    [requests],
  );
  const current = sorted.find((request) => request.id === selected) ?? sorted[0] ?? null;
  const list = listbox({
    prefix: 'request',
    ids: sorted.map((request) => request.id),
    selected: current?.id ?? null,
    onSelect: setSelected,
    onOpen: (id) => {
      setSelected(id);
      showDetail();
    },
  });

  const copyLink = async (request: FileRequest) => {
    const link = requestLink(request);
    if (!link) return;
    await navigator.clipboard.writeText(link);
    toast(t('Link kopiert ✧'));
  };

  if (problem === 'off')
    return (
      <section className="list-pane">
        <div className="list-empty">
          <p>{t('Datei-Anfragen sind auf diesem Server ausgeschaltet.')}</p>
        </div>
      </section>
    );

  return (
    <>
      <section
        className="list-pane"
        aria-label={t('Datei-Anfragen')}
        tabIndex={-1}
        data-main-content
      >
        <div className="list-head">
          <p className="list-title">
            <span>{t('Datei-Anfragen')}</span>
            <span className="list-count">{sorted.length}</span>
            <span className="spacer" />
            <button
              className="new-item"
              disabled={problem === 'lost'}
              onClick={() => setEditing({ request: null })}
            >
              <Icon name="plus" size={15} />
              {t('Neu')}
            </button>
          </p>
        </div>
        {problem === 'lost' && (
          <div className="list-empty">
            <p>
              {t(
                'Die Schlüssel deines Kontos wurden erneuert, und die Namen und Links deiner Datei-Anfragen lassen sich nicht mehr öffnen. Die Links funktionieren weiter; um neue Anfragen zu machen, fang neu an.',
              )}
            </p>
            <button className="primary" onClick={() => setResetting(true)}>
              {t('Neu anfangen')}
            </button>
          </div>
        )}
        {sorted.length ? (
          <ul className="item-list" aria-label={t('Datei-Anfragen')} {...list.listProps}>
            {sorted.map((request) => (
              <li
                key={request.id}
                id={list.optionId(request.id)}
                role="option"
                aria-selected={request.id === current?.id}
                className="item-row"
                onClick={() => {
                  setSelected(request.id);
                  showDetail();
                }}
              >
                <span className="item-tile" data-hue="4">
                  <Icon name="download" size={18} />
                </span>
                <span className="item-text">
                  <span className="item-name">{request.name ?? t('(ohne Namen)')}</span>
                  <span className="item-sub">{status(request)}</span>
                </span>
                <span className="item-badges">
                  {request.unseen > 0 && (
                    <span className="badge" title={t('Neu angekommen')}>
                      {request.unseen}
                    </span>
                  )}
                  {request.passwordSet && <Icon name="lock" size={13} title={t('Mit Passwort')} />}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          requests &&
          problem !== 'lost' && (
            <div className="list-empty">
              <p>
                {t(
                  'Noch keine Datei-Anfragen. Mach einen Link, über den dir jemand ohne Konto Dateien schickt – etwa einen Ausweis-Scan. Verschlüsselt wird im Browser des Absenders, nur du kannst es öffnen.',
                )}
              </p>
            </div>
          )
        )}
      </section>

      <section className="detail-pane">
        <BackToList />
        {current ? (
          <RequestDetail
            key={current.id}
            request={current}
            onCopy={() => void copyLink(current)}
            onEdit={() => setEditing({ request: current })}
            onDelete={() => setDeleting(current)}
            onChanged={reload}
          />
        ) : (
          <div className="detail-empty" />
        )}
      </section>

      {editing && (
        <RequestEditor
          request={editing.request}
          onClose={() => setEditing(null)}
          onSaved={(saved) => {
            setEditing(null);
            setSelected(saved.id);
            reload();
          }}
        />
      )}
      {deleting && (
        <Modal
          title={t('Datei-Anfrage löschen?')}
          tone="warning"
          onCancel={() => setDeleting(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDeleting(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  const id = deleting.id;
                  setDeleting(null);
                  void deleteFileRequest(id).then(
                    () => {
                      toast(t('Gelöscht.'));
                      reload();
                    },
                    (e) => toast(errorText(e), 'error'),
                  );
                }}
              >
                {t('Löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t('Der Link nimmt danach nichts mehr an, und was angekommen ist, ist weg.')}
          </p>
        </Modal>
      )}
      {resetting && (
        <PasswordPrompt
          title={t('Neu anfangen?')}
          tone="warning"
          lead={t(
            'Der alte Schlüssel für UwULocks Extras geht, und mit ihm die Namen deiner Datei-Anfragen. Die Anfragen selbst und was angekommen ist bleiben.',
          )}
          confirm={t('Neu anfangen')}
          onCancel={() => setResetting(false)}
          action={async (password) => {
            await resetExtras(password);
            setResetting(false);
            reload();
          }}
        />
      )}
    </>
  );
}

function status(request: FileRequest): string {
  if (request.disabled) return t('Deaktiviert');
  if (Date.parse(request.expirationDate) < Date.now()) return t('Abgelaufen');
  if (request.maxSubmissions !== null && request.submissionCount >= request.maxSubmissions)
    return t('Voll');
  return t('Bis {when}', { when: when(request.expirationDate) ?? '' });
}

function RequestDetail({
  request,
  onCopy,
  onEdit,
  onDelete,
  onChanged,
}: {
  request: FileRequest;
  onCopy: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onChanged: () => void;
}) {
  useLanguage();
  const [arrived, setArrived] = useState<Arrived[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const link = requestLink(request);

  const load = useCallback(() => {
    submissions(request.id).then(setArrived, (e) => toast(errorText(e), 'error'));
  }, [request.id]);
  useEffect(load, [load]);

  // What is shown counts as seen.
  useEffect(() => {
    const unseen = arrived?.filter((submission) => !submission.seen) ?? [];
    if (!unseen.length) return;
    void Promise.all(unseen.map(markSeen)).then(onChanged, () => undefined);
  }, [arrived, onChanged]);

  const act = async (id: string, work: () => Promise<void>) => {
    setBusy(id);
    try {
      await work();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(null);
    }
  };

  const senderLine = (submission: Arrived) => {
    const who = [submission.sender?.name, submission.sender?.email].filter(Boolean).join(' · ');
    return who ? t('Absender (nicht geprüft): {who}', { who }) : '';
  };

  return (
    <article className="detail" aria-label={request.name ?? t('Datei-Anfrage')}>
      <header className="detail-head">
        <span className="item-tile" data-size="large" data-hue="4">
          <Icon name="download" size={26} />
        </span>
        <div className="detail-title">
          <h2>{request.name ?? t('(ohne Namen)')}</h2>
          <p className="chips">
            <span className="chip">{status(request)}</span>
            {request.passwordSet && <span className="chip">{t('Mit Passwort')}</span>}
          </p>
        </div>
        <div className="detail-tools">
          <button className="primary" disabled={!link} onClick={onCopy}>
            <Icon name="copy" size={15} />
            {t('Link kopieren')}
          </button>
          <button className="quiet" onClick={onEdit}>
            <Icon name="pencil" size={15} />
            {t('Bearbeiten')}
          </button>
          <button className="quiet danger-text" aria-label={t('Löschen')} onClick={onDelete}>
            <Icon name="trash" size={15} />
          </button>
        </div>
      </header>
      <section className="detail-card">
        <div className="detail-row">
          <div className="detail-text">
            <span className="detail-label">{t('Link')}</span>
            <span className="detail-value mono send-link">
              {link ??
                t('Der Link lässt sich nicht mehr zeigen. Mach unter Bearbeiten einen neuen.')}
            </span>
          </div>
        </div>
        {request.title && (
          <div className="detail-row">
            <div className="detail-text">
              <span className="detail-label">{t('Titel für den Absender')}</span>
              <span className="detail-value">{request.title}</span>
            </div>
          </div>
        )}
        {request.note && (
          <div className="detail-row">
            <div className="detail-text">
              <span className="detail-label">{t('Hinweis')}</span>
              <span className="detail-value multiline">{request.note}</span>
            </div>
          </div>
        )}
      </section>
      <section className="detail-card">
        <p className="detail-line">
          {request.maxSubmissions
            ? t('{n} von {max} Einsendungen', {
                n: request.submissionCount,
                max: request.maxSubmissions,
              })
            : t('{n} Einsendungen', { n: request.submissionCount })}
          {' · '}
          {request.maxFiles
            ? t('bis {n} Dateien je {size}', {
                n: request.maxFiles,
                size: bytes(request.maxFileBytes),
              })
            : t('nur Text')}
        </p>
        <p className="detail-line">
          {t('Läuft ab {when}', { when: when(request.expirationDate) ?? '' })}
        </p>
        <p className="detail-line">
          {t('Wird mit allem darin gelöscht {when}', { when: when(request.deletionDate) ?? '' })}
        </p>
      </section>

      <h3 className="detail-subhead">{t('Angekommen')}</h3>
      {arrived?.length === 0 && (
        <p className="empty-note">{t('Noch nichts. Du bekommst eine Mail, wenn etwas ankommt.')}</p>
      )}
      {arrived?.map((submission) => (
        <section
          key={submission.id}
          className="detail-card"
          aria-label={when(submission.creationDate) ?? ''}
        >
          <p className="detail-line">
            <b>{when(submission.creationDate)}</b>
            {senderLine(submission) && ` · ${senderLine(submission)}`}
          </p>
          {submission.text && <p className="detail-value multiline">{submission.text}</p>}
          {submission.files.map((file) => (
            <div key={file.id} className="detail-row">
              <span className="send-file">
                <Icon name="file" size={16} />
                {file.name} ({bytes(file.size)})
              </span>
              <span className="spacer" />
              <button
                className="quiet"
                disabled={busy !== null}
                onClick={() =>
                  void act(file.id, async () =>
                    save(await downloadArrivedFile(submission, file.id), file.name),
                  )
                }
              >
                <Icon name="download" size={15} />
                {busy === file.id ? t('Lädt …') : t('Herunterladen')}
              </button>
            </div>
          ))}
          <div className="form-actions">
            <button
              className="primary"
              disabled={busy !== null}
              onClick={() =>
                void act(submission.id, async () => {
                  const name = `${request.title ?? request.name ?? t('Datei-Anfrage')} – ${
                    when(submission.creationDate) ?? ''
                  }`;
                  await takeOver(submission, name, senderLine(submission));
                  toast(t('Als Notiz übernommen ✧ Die Dateien hängen daran.'));
                  load();
                  onChanged();
                })
              }
            >
              <Icon name="note" size={15} />
              {busy === submission.id ? t('Übernimmt …') : t('Als Eintrag übernehmen')}
            </button>
            <span className="spacer" />
            <button
              className="quiet danger-text"
              disabled={busy !== null}
              onClick={() =>
                void act(submission.id, async () => {
                  await deleteArrived(submission);
                  load();
                  onChanged();
                })
              }
            >
              <Icon name="trash" size={15} />
              {t('Löschen')}
            </button>
          </div>
        </section>
      ))}
    </article>
  );
}

const DAYS = [1, 3, 7, 14, 30, 90];

function daysUntil(iso: string | null): number {
  if (!iso) return 7;
  const days = Math.round((Date.parse(iso) - Date.now()) / 86_400_000);
  return DAYS.reduce((best, n) => (Math.abs(n - days) < Math.abs(best - days) ? n : best), 7);
}

function RequestEditor({
  request,
  onClose,
  onSaved,
}: {
  request: FileRequest | null;
  onClose: () => void;
  onSaved: (saved: FileRequest) => void;
}) {
  useLanguage();
  const [name, setName] = useState(request?.name ?? '');
  const [title, setTitle] = useState(request?.title ?? '');
  const [note, setNote] = useState(request?.note ?? '');
  const [owner, setOwner] = useState(request?.owner ?? '');
  const [days, setDays] = useState(daysUntil(request?.expirationDate ?? null));
  const [maxSubmissions, setMaxSubmissions] = useState(
    request ? (request.maxSubmissions ? String(request.maxSubmissions) : '') : '1',
  );
  const [maxFiles, setMaxFiles] = useState(request?.maxFiles ?? 5);
  const [maxMb, setMaxMb] = useState(
    request ? Math.max(1, Math.round(request.maxFileBytes / 1024 / 1024)) : 25,
  );
  const [textAllowed, setTextAllowed] = useState(request?.textAllowed ?? true);
  const [password, setPassword] = useState('');
  const [removePassword, setRemovePassword] = useState(false);
  const [disabled, setDisabled] = useState(request?.disabled ?? false);
  const [newLink, setNewLink] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = name.trim() && title.trim() && (maxFiles > 0 || textAllowed);
  // Without its old secret the page cannot keep a link: saving makes a new one.
  const linkLost = Boolean(request && !request.secret);

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    const draft: RequestDraft = {
      name: name.trim(),
      title: title.trim(),
      note: note.trim() || null,
      owner: owner.trim() || null,
      password: password || null,
      removePassword,
      expirationDate: new Date(Date.now() + days * 86_400_000).toISOString(),
      maxSubmissions: maxSubmissions ? Math.max(1, Math.min(100, Number(maxSubmissions))) : null,
      maxFiles,
      maxFileBytes: maxMb * 1024 * 1024,
      textAllowed,
      disabled,
      newLink,
    };
    try {
      const saved = await saveFileRequest(request, draft);
      toast(request ? t('Gespeichert ✧') : t('Datei-Anfrage angelegt – kopier jetzt den Link ✧'));
      onSaved(saved);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const dayText = (n: number) => (n === 1 ? t('1 Tag') : t('{n} Tage', { n }));
  return (
    <Modal
      title={request ? t('Datei-Anfrage bearbeiten') : t('Neue Datei-Anfrage')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <button className="quiet" data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <span className="spacer" />
          <button className="primary" disabled={!ready || busy} onClick={() => void submit()}>
            {busy ? t('Einen Moment …') : request ? t('Speichern') : t('Anlegen')}
          </button>
        </>
      }
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <label className="field">
          <span>{t('Name (nur für dich)')}</span>
          <input value={name} maxLength={200} autoFocus onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>{t('Titel für den Absender')}</span>
          <input
            value={title}
            maxLength={200}
            placeholder={t('z. B. Ausweis-Scan')}
            onChange={(e) => setTitle(e.target.value)}
          />
        </label>
        <label className="field">
          <span>{t('Hinweis für den Absender (freiwillig)')}</span>
          <textarea
            rows={3}
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        <label className="field">
          <span>{t('Dein Name, wie der Absender ihn sieht (freiwillig)')}</span>
          <input value={owner} maxLength={100} onChange={(e) => setOwner(e.target.value)} />
        </label>
        <div className="field-pair">
          <label className="field">
            <span>{t('Läuft ab nach')}</span>
            <select
              className="select"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              {DAYS.map((n) => (
                <option key={n} value={n}>
                  {dayText(n)}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('Einsendungen')}</span>
            <input
              type="number"
              min={1}
              max={100}
              value={maxSubmissions}
              placeholder={t('unbegrenzt')}
              onChange={(e) => setMaxSubmissions(e.target.value)}
            />
          </label>
        </div>
        <div className="field-pair">
          <label className="field">
            <span>{t('Dateien je Einsendung')}</span>
            <input
              type="number"
              min={0}
              max={100}
              value={maxFiles}
              onChange={(e) => setMaxFiles(Math.max(0, Number(e.target.value)))}
            />
          </label>
          <label className="field">
            <span>{t('Größte Datei (MB)')}</span>
            <input
              type="number"
              min={1}
              value={maxMb}
              disabled={maxFiles === 0}
              onChange={(e) => setMaxMb(Math.max(1, Number(e.target.value)))}
            />
          </label>
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={textAllowed}
            onChange={(e) => setTextAllowed(e.target.checked)}
          />
          <span>{t('Eine Nachricht erlauben')}</span>
        </label>
        <label className="field">
          <span>
            {request?.passwordSet
              ? t('Neues Passwort (leer lässt das alte)')
              : t('Passwort (freiwillig)')}
          </span>
          <PasswordInput value={password} onChange={setPassword} autoComplete="new-password" />
        </label>
        {request?.passwordSet && (
          <label className="check">
            <input
              type="checkbox"
              checked={removePassword}
              onChange={(e) => setRemovePassword(e.target.checked)}
            />
            <span>{t('Passwort entfernen')}</span>
          </label>
        )}
        {request && (
          <label className="check">
            <input
              type="checkbox"
              checked={newLink || linkLost}
              disabled={linkLost}
              onChange={(e) => setNewLink(e.target.checked)}
            />
            <span>{t('Neuer Link: der alte nimmt nichts mehr an')}</span>
          </label>
        )}
        {request?.passwordSet && (newLink || linkLost) && !password && (
          <p className="field-hint">
            {t('Das Passwort hängt am Link: Ein neuer Link braucht es neu, sonst hat er keins.')}
          </p>
        )}
        <label className="check">
          <input
            type="checkbox"
            checked={disabled}
            onChange={(e) => setDisabled(e.target.checked)}
          />
          <span>{t('Deaktiviert: der Link nimmt vorerst nichts an')}</span>
        </label>
        <p className="field-hint">
          {t(
            'Was ankommt, ist mit dem Schlüssel deines Kontos verschlüsselt. 30 Tage nach dem Ablauf löscht der Server die Anfrage mit allem darin.',
          )}
        </p>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}
