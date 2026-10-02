import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { isEntrySend, readableOf } from '../../lib/entrySend';
import { listen } from '../../lib/events';
import { errorText } from '../../lib/errors';
import {
  deleteSend,
  removeSendAuth,
  saveSend,
  sendDomainChoices,
  sendLink,
  sendsList,
  setSendDomain,
  type Send,
  type SendDraft,
  type SendKind,
} from '../../lib/features';
import { useFeature } from '../../lib/branding';
import { bytes, when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { domainOf, type SendDomain } from '../../lib/links';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { NyuScene } from '../nyu/scenes';
import { Modal } from '../Modal';
import { listbox } from '../listbox';
import { BackToList, Panes } from '../panes';
import { PasswordInput } from '../PasswordInput';
import { SendDomainField, useDefaultSendDomain, useSendDomains } from './SendDomainSelect';

/**
 * Sends: a text or a file behind a link, for somebody without an account. The link carries the
 * key; the server keeps only what it cannot read, and forgets it on the deletion date.
 */
export function SendsView() {
  useLanguage();
  const [sends, setSends] = useState<Send[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ send: Send | null; kind: SendKind } | null>(null);
  const [deleting, setDeleting] = useState<Send | null>(null);
  /** Which send domain each Send chose, when the server has any. */
  const [choices, setChoices] = useState<Record<string, string | null>>({});
  const { showDetail } = useContext(Panes);
  const domains = useSendDomains();
  const withDomains = domains.length > 0;

  const reload = useCallback(() => {
    sendsList().then(setSends, (e) => toast(errorText(e), 'error'));
    if (withDomains) sendDomainChoices().then(setChoices, () => undefined);
  }, [withDomains]);

  useEffect(() => {
    reload();
    const stop = listen('vault-changed', reload);
    return () => void stop.then((unlisten) => unlisten());
  }, [reload]);

  const sorted = useMemo(
    () => [...sends].sort((a, b) => (b.revisionDate ?? '').localeCompare(a.revisionDate ?? '')),
    [sends],
  );
  const current = sorted.find((send) => send.id === selected) ?? sorted[0] ?? null;

  const list = listbox({
    prefix: 'send',
    ids: sorted.map((send) => send.id),
    selected: current?.id ?? null,
    onSelect: setSelected,
    onOpen: (id) => {
      setSelected(id);
      showDetail();
    },
  });

  const linkOf = (send: Send) => sendLink(send, domainOf(domains, choices[send.id]));

  const copyLink = async (send: Send) => {
    await navigator.clipboard.writeText(linkOf(send));
    toast(t('Link kopiert ✧'));
  };

  return (
    <>
      <section className="list-pane" aria-label={t('Sends')} tabIndex={-1} data-main-content>
        <div className="list-head">
          <p className="list-title">
            <span>{t('Sends')}</span>
            <span className="list-count">{sends.length}</span>
            <span className="spacer" />
            <button className="new-item" onClick={() => setEditing({ send: null, kind: 0 })}>
              <Icon name="plus" size={15} />
              {t('Text')}
            </button>
            <button className="new-item" onClick={() => setEditing({ send: null, kind: 1 })}>
              <Icon name="plus" size={15} />
              {t('Datei')}
            </button>
          </p>
        </div>
        {sorted.length ? (
          <ul className="item-list" aria-label={t('Sends')} {...list.listProps}>
            {sorted.map((send) => (
              <li
                key={send.id}
                id={list.optionId(send.id)}
                role="option"
                aria-selected={send.id === current?.id}
                className="item-row"
                onClick={() => {
                  setSelected(send.id);
                  showDetail();
                }}
              >
                <span className="item-tile" data-hue="2">
                  <Icon name={send.kind === 1 ? 'file' : 'note'} size={18} />
                </span>
                <span className="item-text">
                  <span className="item-name">{send.name || t('(ohne Namen)')}</span>
                  <span className="item-sub">{status(send)}</span>
                </span>
                <span className="item-badges">
                  {send.hasPassword && <Icon name="lock" size={13} title={t('Mit Passwort')} />}
                  {send.disabled && <Icon name="stop" size={13} title={t('Deaktiviert')} />}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="list-empty">
            <NyuScene name="letter" className="empty-scene" />
            <p>
              {t(
                'Noch keine Sends. Ein Send ist ein Text oder eine Datei hinter einem Link – für jemanden ohne Konto, verschlüsselt, und nach einer Frist wieder weg.',
              )}
            </p>
          </div>
        )}
      </section>

      <section className="detail-pane">
        <BackToList />
        {current ? (
          <article className="detail" aria-label={current.name}>
            <header className="detail-head">
              <span className="item-tile" data-size="large" data-hue="2">
                <Icon name={current.kind === 1 ? 'file' : 'note'} size={26} />
              </span>
              <div className="detail-title">
                <h2>{current.name || t('(ohne Namen)')}</h2>
                <p className="chips">
                  <span className="chip">{current.kind === 1 ? t('Datei') : t('Text')}</span>
                  {current.hasPassword && <span className="chip">{t('Mit Passwort')}</span>}
                  {current.disabled && <span className="chip chip-muted">{t('Deaktiviert')}</span>}
                </p>
              </div>
              <div className="detail-tools">
                <button className="primary" onClick={() => void copyLink(current)}>
                  <Icon name="copy" size={15} />
                  {t('Link kopieren')}
                </button>
                <button
                  className="quiet"
                  onClick={() => setEditing({ send: current, kind: current.kind })}
                >
                  <Icon name="pencil" size={15} />
                  {t('Bearbeiten')}
                </button>
                <button
                  className="quiet danger-text"
                  onClick={() => setDeleting(current)}
                  title={t('Löschen')}
                  aria-label={t('Löschen')}
                >
                  <Icon name="trash" size={15} />
                </button>
              </div>
            </header>
            <section className="detail-card">
              <div className="detail-row">
                <div className="detail-text">
                  <span className="detail-label">{t('Link')}</span>
                  <span className="detail-value mono send-link">{linkOf(current)}</span>
                </div>
              </div>
              {current.kind === 0 ? (
                <div className="detail-row">
                  <div className="detail-text">
                    <span className="detail-label">
                      {isEntrySend(current.text) ? t('Text · als Eintrag geteilt') : t('Text')}
                    </span>
                    <span className="detail-value multiline">{readableOf(current.text ?? '')}</span>
                  </div>
                </div>
              ) : (
                <div className="detail-row">
                  <div className="detail-text">
                    <span className="detail-label">{t('Datei')}</span>
                    <span className="detail-value">
                      {current.fileName} {current.size !== null && `(${bytes(current.size)})`}
                    </span>
                  </div>
                </div>
              )}
              {current.notes && (
                <div className="detail-row">
                  <div className="detail-text">
                    <span className="detail-label">{t('Notizen (nur für dich)')}</span>
                    <span className="detail-value multiline">{current.notes}</span>
                  </div>
                </div>
              )}
            </section>
            <section className="detail-card">
              <p className="detail-line">
                {current.maxAccessCount
                  ? t('{n} von {max} Mal geöffnet', {
                      n: current.accessCount,
                      max: current.maxAccessCount,
                    })
                  : t('{n} Mal geöffnet', { n: current.accessCount })}
              </p>
              {current.expirationDate && (
                <p className="detail-line">
                  {t('Läuft ab {when}', { when: when(current.expirationDate) ?? '' })}
                </p>
              )}
              <p className="detail-line">
                {t('Wird gelöscht {when}', { when: when(current.deletionDate) ?? '' })}
              </p>
              {current.authType === 0 && (
                <p className="detail-line">
                  {t('Nur für: {emails}', { emails: current.emails.join(', ') })}
                </p>
              )}
              {current.authType !== 2 && (
                <button
                  className="quiet"
                  onClick={() =>
                    void removeSendAuth(current.id).then(
                      () =>
                        toast(
                          current.authType === 0
                            ? t('Adressen entfernt.')
                            : t('Passwort entfernt.'),
                        ),
                      (e) => toast(errorText(e), 'error'),
                    )
                  }
                >
                  {current.authType === 0 ? t('Adressen entfernen') : t('Passwort entfernen')}
                </button>
              )}
            </section>
          </article>
        ) : (
          <div className="detail-empty" />
        )}
      </section>

      {editing && (
        <SendEditor
          send={editing.send}
          kind={editing.kind}
          domains={domains}
          domainId={editing.send ? (choices[editing.send.id] ?? null) : null}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reload();
          }}
        />
      )}
      {deleting && (
        <Modal
          title={t('Send löschen?')}
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
                  void deleteSend(id).then(
                    () => toast(t('Gelöscht.')),
                    (e) => toast(errorText(e), 'error'),
                  );
                }}
              >
                {t('Löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">{t('Der Link öffnet danach nichts mehr.')}</p>
        </Modal>
      )}
    </>
  );
}

function status(send: Send): string {
  const now = Date.now();
  if (send.disabled) return t('Deaktiviert');
  if (send.expirationDate && Date.parse(send.expirationDate) < now) return t('Abgelaufen');
  if (send.maxAccessCount && send.accessCount >= send.maxAccessCount)
    return t('So oft geöffnet, wie erlaubt');
  return t('Bis {when}', { when: when(send.expirationDate ?? send.deletionDate) ?? '' });
}

const DAYS = [1, 2, 3, 7, 14, 30];

function inDays(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

function daysUntil(iso: string | null): number {
  if (!iso) return 7;
  const days = Math.round((Date.parse(iso) - Date.now()) / 86_400_000);
  return DAYS.reduce((best, n) => (Math.abs(n - days) < Math.abs(best - days) ? n : best), 7);
}

function SendEditor({
  send,
  kind,
  domains,
  domainId,
  onClose,
  onSaved,
}: {
  send: Send | null;
  kind: SendKind;
  /** The server's send domains; none: the field is not shown. */
  domains: SendDomain[];
  /** The domain the Send chose so far. */
  domainId: string | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  useLanguage();
  const [name, setName] = useState(send?.name ?? '');
  const [text, setText] = useState(send?.text ?? '');
  const [hidden, setHidden] = useState(send?.hidden ?? false);
  const [notes, setNotes] = useState(send?.notes ?? '');
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [maxAccess, setMaxAccess] = useState(
    send?.maxAccessCount ? String(send.maxAccessCount) : '',
  );
  const [deletion, setDeletion] = useState(daysUntil(send?.deletionDate ?? null));
  const [expires, setExpires] = useState<number | 0>(
    send?.expirationDate ? daysUntil(send.expirationDate) : 0,
  );
  const [disabled, setDisabled] = useState(send?.disabled ?? false);
  const [hideEmail, setHideEmail] = useState(send?.hideEmail ?? false);
  const [access, setAccess] = useState<0 | 1 | 2>(send?.authType ?? 2);
  const [emails, setEmails] = useState(send?.emails.join(', ') ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const mailOk = useFeature('send-emails');
  // A new Send starts on the account's default domain, which the server gives it anyway.
  const fallback = useDefaultSendDomain(!send && domains.length > 0);
  const [domain, setDomain] = useState<string | null | undefined>(send ? domainId : undefined);
  const chosenDomain = domain === undefined ? fallback.value : domain;

  const addresses = splitAddresses(emails);
  const ready =
    fallback.ready &&
    name.trim() &&
    (kind === 0 ? text.trim() : send || file) &&
    (access !== 0 || addresses.length > 0) &&
    (access !== 1 || password || send?.hasPassword);

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    const draft: SendDraft = {
      kind,
      name: name.trim(),
      notes: notes.trim() || null,
      text: kind === 0 ? text : null,
      hidden,
      fileName: file?.name ?? send?.fileName ?? null,
      password: access === 1 ? password || null : null,
      authType: access,
      emails: access === 0 ? addresses : [],
      maxAccessCount: maxAccess ? Math.max(1, Number(maxAccess)) : null,
      expirationDate: expires ? inDays(Math.min(expires, deletion)) : null,
      deletionDate: inDays(deletion),
      disabled,
      hideEmail,
    };
    try {
      const saved = await saveSend(send?.id ?? null, draft, file ?? undefined);
      const before = send ? domainId : fallback.value;
      if (domains.length > 0 && saved && chosenDomain !== before) {
        // The Send is saved either way; only its link would stay on the old address.
        await setSendDomain(saved, chosenDomain).catch((e) => toast(errorText(e), 'error'));
      }
      toast(send ? t('Gespeichert ✧') : t('Send angelegt – kopier jetzt den Link ✧'));
      onSaved();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const days = (n: number) => (n === 1 ? t('1 Tag') : t('{n} Tage', { n }));
  return (
    <Modal
      title={
        send ? t('Send bearbeiten') : kind === 1 ? t('Neuer Datei-Send') : t('Neuer Text-Send')
      }
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="primary" disabled={!ready || busy} onClick={() => void submit()}>
            {busy ? t('Einen Moment …') : send ? t('Speichern') : t('Anlegen')}
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
          <span>{t('Name')}</span>
          <input value={name} maxLength={200} autoFocus onChange={(e) => setName(e.target.value)} />
        </label>
        {kind === 0 ? (
          <>
            <label className="field">
              <span>{t('Text')}</span>
              <textarea
                rows={5}
                value={text}
                maxLength={1000}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={hidden}
                onChange={(e) => setHidden(e.target.checked)}
              />
              <span>{t('Text erst auf Klick zeigen')}</span>
            </label>
          </>
        ) : send ? (
          <p className="field-hint">
            {t('Die Datei eines Sends bleibt, wie sie ist: {name}', { name: send.fileName ?? '' })}
          </p>
        ) : (
          <div className="field">
            <span>{t('Datei')}</span>
            <input
              ref={input}
              type="file"
              hidden
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
            <button type="button" onClick={() => input.current?.click()}>
              <Icon name="upload" size={15} />
              {file ? `${file.name} (${bytes(file.size)})` : t('Datei wählen …')}
            </button>
          </div>
        )}
        <div className="field-pair">
          <label className="field">
            <span>{t('Löschen nach')}</span>
            <select
              className="select"
              value={deletion}
              onChange={(e) => setDeletion(Number(e.target.value))}
            >
              {DAYS.map((n) => (
                <option key={n} value={n}>
                  {days(n)}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('Läuft ab nach')}</span>
            <select
              className="select"
              value={expires}
              onChange={(e) => setExpires(Number(e.target.value))}
            >
              <option value={0}>{t('Nie (bis zum Löschen)')}</option>
              {DAYS.map((n) => (
                <option key={n} value={n}>
                  {days(n)}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>{t('Höchstens so oft öffnen')}</span>
          <input
            type="number"
            min={1}
            value={maxAccess}
            placeholder={t('unbegrenzt')}
            onChange={(e) => setMaxAccess(e.target.value)}
          />
        </label>
        {domains.length > 0 && (
          <SendDomainField
            label={t('Adresse des Links')}
            value={chosenDomain}
            onChange={setDomain}
            domains={domains}
            disabled={!fallback.ready}
            hint={t(
              'Der Send öffnet sich unter jeder dieser Adressen; diese steht im Link, den du kopierst.',
            )}
          />
        )}
        <SendAccess
          value={access}
          onChange={setAccess}
          mailOk={mailOk || access === 0}
          hasPassword={Boolean(send?.hasPassword)}
          password={password}
          onPassword={setPassword}
          emails={emails}
          onEmails={setEmails}
        />
        <label className="field">
          <span>{t('Notizen (nur für dich)')}</span>
          <textarea
            rows={2}
            value={notes}
            maxLength={1000}
            onChange={(e) => setNotes(e.target.value)}
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={hideEmail}
            onChange={(e) => setHideEmail(e.target.checked)}
          />
          <span>{t('Meine Adresse nicht zeigen')}</span>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={disabled}
            onChange={(e) => setDisabled(e.target.checked)}
          />
          <span>{t('Deaktiviert: der Link öffnet vorerst nichts')}</span>
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}

/** Addresses as somebody types them: separated by commas, spaces or lines. */
export function splitAddresses(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((address) => address.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Who may open a Send: anybody with the link, whoever knows a password, or only given addresses
 * — they get a code by mail first, which needs mail on the server.
 */
export function SendAccess({
  value,
  onChange,
  mailOk,
  hasPassword,
  password,
  onPassword,
  emails,
  onEmails,
}: {
  value: 0 | 1 | 2;
  onChange: (value: 0 | 1 | 2) => void;
  mailOk: boolean;
  hasPassword: boolean;
  password: string;
  onPassword: (value: string) => void;
  emails: string;
  onEmails: (value: string) => void;
}) {
  useLanguage();
  const options: { value: 0 | 1 | 2; label: string }[] = [
    { value: 2, label: t('Jeder mit dem Link') },
    { value: 1, label: t('Mit Passwort') },
    { value: 0, label: t('Nur bestimmte Adressen') },
  ];
  return (
    <fieldset className="field send-access">
      <legend>{t('Wer darf öffnen?')}</legend>
      <div className="radio-row">
        {options.map((option) => (
          <label key={option.value} className="check">
            <input
              type="radio"
              name="send-access"
              value={option.value}
              checked={value === option.value}
              disabled={option.value === 0 && !mailOk}
              onChange={() => onChange(option.value)}
            />
            <span>{option.label}</span>
          </label>
        ))}
      </div>
      {!mailOk && (
        <p className="field-hint">
          {t('Nur bestimmte Adressen braucht Mail auf dem Server; hier ist keine eingerichtet.')}
        </p>
      )}
      {value === 1 && (
        <label className="field">
          <span>{hasPassword ? t('Neues Passwort (leer lässt das alte)') : t('Passwort')}</span>
          <PasswordInput value={password} onChange={onPassword} autoComplete="new-password" />
        </label>
      )}
      {value === 0 && (
        <label className="field">
          <span>{t('E-Mail-Adressen')}</span>
          <textarea
            rows={2}
            value={emails}
            onChange={(e) => onEmails(e.target.value)}
            placeholder="friend@example.com, family@example.org"
            aria-describedby="send-emails-hint"
          />
          <span id="send-emails-hint" className="field-hint">
            {t(
              'Wer den Link öffnet, gibt seine Adresse an und bekommt einen Code per Mail. Der Server kennt dafür die Adressen.',
            )}
          </span>
        </label>
      )}
    </fieldset>
  );
}
