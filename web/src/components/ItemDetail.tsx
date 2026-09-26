import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import {
  copyField,
  deleteItem,
  failure,
  openItemUri,
  archiveItem,
  restoreItem,
  revealField,
  setFavorite,
  totpCode,
  vaultItem,
  verifyReprompt,
  type ItemDetail as Detail,
  type ItemSummary,
  type Overview,
  type TotpCode,
} from '../lib/api';
import { errorText } from '../lib/errors';
import { charClasses, copiedText, spacedCode, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { IDENTITY_LABEL, KIND_LABEL } from '../lib/items';
import { getSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { Icon } from './Icon';
import { ItemTile } from './ItemTile';
import { Modal } from './Modal';
import { PasswordInput } from './PasswordInput';

async function copy(id: string, field: string) {
  try {
    await copyField(id, field);
    toast(copiedText(field, getSettings().clipboardClear));
  } catch (e) {
    toast(errorText(e), 'error');
  }
}

/** A password with letters, digits and symbols told apart by colour. */
export function Colored({ text }: { text: string }) {
  return (
    <span className="colored">
      {charClasses(text).map((run, index) => (
        <span key={index} data-class={run.kind}>
          {run.text}
        </span>
      ))}
    </span>
  );
}

function CopyButton({ id, field, label }: { id: string; field: string; label: string }) {
  useLanguage();
  return (
    <button
      className="icon-button"
      onClick={() => void copy(id, field)}
      aria-label={t('{label} kopieren', { label })}
      title={t('Kopieren')}
    >
      <Icon name="copy" size={15} />
    </button>
  );
}

function Row({
  label,
  children,
  actions,
  mono,
}: {
  label: string;
  children: ReactNode;
  actions?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="detail-row">
      <div className="detail-text">
        <span className="detail-label">{label}</span>
        <span className={mono ? 'detail-value mono' : 'detail-value'}>{children}</span>
      </div>
      {actions && <div className="detail-actions">{actions}</div>}
    </div>
  );
}

/** A value that stays dots until the eye is clicked; then it comes from Rust. */
function SecretRow({
  id,
  field,
  label,
  masked = '••••••••••••',
  multiline,
  colored = true,
}: {
  id: string;
  field: string;
  label: string;
  masked?: string;
  multiline?: boolean;
  colored?: boolean;
}) {
  useLanguage();
  const [value, setValue] = useState<string | null>(null);
  // Out of sight when the window is left alone for a while.
  useEffect(() => {
    if (value === null) return;
    const timer = window.setTimeout(() => setValue(null), 60_000);
    return () => window.clearTimeout(timer);
  }, [value]);
  const toggle = async () => {
    if (value !== null) {
      setValue(null);
      return;
    }
    try {
      setValue(await revealField(id, field));
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };
  return (
    <Row
      label={label}
      mono
      actions={
        <>
          <button
            className="icon-button"
            onClick={() => void toggle()}
            aria-label={
              value === null ? t('{label} zeigen', { label }) : t('{label} verbergen', { label })
            }
            aria-pressed={value !== null}
            title={value === null ? t('Zeigen') : t('Verbergen')}
          >
            <Icon name={value === null ? 'eye' : 'eyeOff'} size={15} />
          </button>
          <CopyButton id={id} field={field} label={label} />
        </>
      }
    >
      {value === null ? (
        <span className="masked">{masked}</span>
      ) : multiline ? (
        <pre className="secret-block">{value}</pre>
      ) : colored ? (
        <Colored text={value} />
      ) : (
        value
      )}
    </Row>
  );
}

/** The current one-time code, counting down, fetched again when it turns over. */
function TotpRow({ id }: { id: string }) {
  useLanguage();
  const [code, setCode] = useState<TotpCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const next = await totpCode(id);
        if (stopped) return;
        setCode(next);
        setError(null);
      } catch (e) {
        if (!stopped) setError(errorText(e));
      }
      if (!stopped) timer = window.setTimeout(() => void tick(), 1000);
    };
    void tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [id]);

  const fraction = code ? code.remaining / code.period : 0;
  const circumference = 2 * Math.PI * 9;
  return (
    <Row
      label={t('Einmal-Code (TOTP)')}
      mono
      actions={<CopyButton id={id} field="totp" label={t('Code')} />}
    >
      {error ? (
        <span className="detail-error">{error}</span>
      ) : code ? (
        <span className="totp" data-soon={code.remaining <= 5 || undefined}>
          <span className="totp-code">{spacedCode(code.code)}</span>
          <svg className="totp-ring" viewBox="0 0 24 24" width="22" height="22" aria-hidden>
            <circle cx="12" cy="12" r="9" className="totp-track" />
            <circle
              cx="12"
              cy="12"
              r="9"
              className="totp-left"
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - fraction)}
              transform="rotate(-90 12 12)"
            />
          </svg>
          <span className="totp-seconds">{code.remaining}</span>
        </span>
      ) : (
        '…'
      )}
    </Row>
  );
}

function Section({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="detail-card">
      {title && <h3 className="detail-card-title">{title}</h3>}
      {children}
    </section>
  );
}

/** The master password again, before an item with re-prompt shows anything. */
function Reprompt({ id, onPassed }: { id: string; onPassed: () => void }) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyReprompt(id, password);
      onPassed();
    } catch (e) {
      setError(errorText(e));
      setPassword('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="detail-card reprompt" onSubmit={submit}>
      <p className="detail-card-title">
        <Icon name="lock" size={15} />
        {t('Master-Passwort erforderlich')}
      </p>
      <p className="dialog-lead">
        {t(
          'Dieser Eintrag ist besonders geschützt. Gib dein Master-Passwort ein, um ihn zu öffnen.',
        )}
      </p>
      <PasswordInput
        value={password}
        onChange={setPassword}
        autoFocus
        disabled={busy}
        label={t('Master-Passwort')}
      />
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div className="form-actions">
        <span className="spacer" />
        <button className="primary" type="submit" disabled={busy || !password}>
          {busy ? t('Prüft …') : t('Öffnen')}
        </button>
      </div>
    </form>
  );
}

/** Asks before something is thrown away for good. */
function ConfirmDelete({
  name,
  permanent,
  onCancel,
  onConfirm,
}: {
  name: string;
  permanent: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  useLanguage();
  return (
    <Modal
      title={permanent ? t('Endgültig löschen?') : t('In den Papierkorb?')}
      tone={permanent ? 'warning' : 'default'}
      onCancel={onCancel}
      footer={
        <>
          <span className="spacer" />
          <button className="danger" data-secondary onClick={onConfirm}>
            {permanent ? t('Endgültig löschen') : t('In den Papierkorb')}
          </button>
          <button className="primary" data-autofocus onClick={onCancel}>
            {t('Abbrechen')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {permanent
          ? t(
              '„{name}“ wird auf dem Server gelöscht. Das lässt sich nicht rückgängig machen – auch nicht im Web-Tresor.',
              { name },
            )
          : t('„{name}“ wandert in den Papierkorb. Der Server hebt ihn dort noch 30 Tage auf.', {
              name,
            })}
      </p>
    </Modal>
  );
}

export function ItemDetail({
  summary,
  overview,
  onEdit,
}: {
  summary: ItemSummary;
  overview: Overview | null;
  onEdit: () => void;
}) {
  useLanguage();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [asking, setAsking] = useState<null | 'trash' | 'permanent'>(null);
  const [busy, setBusy] = useState(false);
  const id = summary.id;

  const load = () => {
    vaultItem(id)
      .then((next) => {
        setDetail(next);
        setError(null);
      })
      .catch((e) => {
        if (failure(e).kind !== 'not-found') setError(errorText(e));
      });
  };
  // Reload when the sync brought a new revision of this item.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [id, summary.revisionDate]);

  const act = async (what: () => Promise<void>, done: string) => {
    setBusy(true);
    try {
      await what();
      toast(done);
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
      setAsking(null);
    }
  };

  const folder = overview?.folders.find((f) => f.id === summary.folderId)?.name;
  const org = overview?.organizations.find((o) => o.id === summary.organizationId)?.name;
  const collections = (overview?.collections ?? [])
    .filter((c) => summary.collectionIds.includes(c.id))
    .map((c) => c.name);

  const d = detail;
  return (
    <article className="detail" aria-label={summary.name}>
      <header className="detail-head">
        <ItemTile item={summary} size="large" />
        <div className="detail-title">
          <h2>
            {summary.name || t('(ohne Namen)')}
            {summary.favorite && (
              <Icon name="star" size={16} className="badge-star" title={t('Favorit')} />
            )}
          </h2>
          <p className="chips">
            <span className="chip">{t(KIND_LABEL[summary.kind])}</span>
            {folder && (
              <span className="chip">
                <Icon name="folder" size={12} />
                {folder}
              </span>
            )}
            {org && (
              <span className="chip">
                <Icon name="building" size={12} />
                {org}
                {collections.length > 0 && ` · ${collections.join(', ')}`}
              </span>
            )}
            {summary.deleted && <span className="chip chip-muted">{t('Im Papierkorb')}</span>}
            {summary.archived && !summary.deleted && (
              <span className="chip chip-muted">{t('Im Archiv')}</span>
            )}
          </p>
        </div>
        <div className="detail-tools">
          {summary.deleted ? (
            <>
              <button
                className="quiet"
                disabled={busy}
                onClick={() => void act(() => restoreItem(id), t('Aus dem Papierkorb geholt ✧'))}
              >
                <Icon name="history" size={15} />
                {t('Wiederherstellen')}
              </button>
              <button
                className="quiet danger-text"
                disabled={busy}
                onClick={() => setAsking('permanent')}
              >
                <Icon name="trash" size={15} />
                {t('Endgültig löschen')}
              </button>
            </>
          ) : (
            <>
              <button
                className="icon-button"
                disabled={busy}
                aria-pressed={summary.favorite}
                title={summary.favorite ? t('Favorit entfernen') : t('Zu Favoriten')}
                aria-label={summary.favorite ? t('Favorit entfernen') : t('Zu Favoriten')}
                onClick={() =>
                  void act(
                    () => setFavorite(id, !summary.favorite),
                    summary.favorite ? t('Kein Favorit mehr') : t('Favorit ✧'),
                  )
                }
              >
                <Icon
                  name="star"
                  size={15}
                  className={summary.favorite ? 'badge-star' : undefined}
                />
              </button>
              <button
                className="icon-button"
                disabled={busy}
                aria-pressed={summary.archived}
                title={summary.archived ? t('Aus dem Archiv holen') : t('Archivieren')}
                aria-label={summary.archived ? t('Aus dem Archiv holen') : t('Archivieren')}
                onClick={() =>
                  void act(
                    () => archiveItem(id, !summary.archived),
                    summary.archived ? t('Aus dem Archiv geholt ✧') : t('Archiviert.'),
                  )
                }
              >
                <Icon name="archive" size={15} />
              </button>
              <button
                className="icon-button"
                disabled={busy}
                title={t('In den Papierkorb')}
                aria-label={t('In den Papierkorb')}
                onClick={() => setAsking('trash')}
              >
                <Icon name="trash" size={15} />
              </button>
              <button
                className="primary"
                disabled={busy || summary.broken || !!d?.locked}
                onClick={onEdit}
              >
                <Icon name="pencil" size={15} />
                {t('Bearbeiten')}
              </button>
            </>
          )}
        </div>
      </header>

      {asking && (
        <ConfirmDelete
          name={summary.name || t('(ohne Namen)')}
          permanent={asking === 'permanent'}
          onCancel={() => setAsking(null)}
          onConfirm={() =>
            void act(
              () => deleteItem(id, asking === 'permanent'),
              asking === 'permanent' ? t('Gelöscht.') : t('Im Papierkorb.'),
            )
          }
        />
      )}

      {error && (
        <p className="notice" data-tone="error">
          {error}
        </p>
      )}
      {summary.broken && (
        <p className="notice" data-tone="error">
          {t(
            'Ein Teil dieses Eintrags ließ sich nicht entschlüsseln. Im Web-Tresor sieht er vielleicht anders aus.',
          )}
        </p>
      )}

      {d?.locked && <Reprompt id={id} onPassed={load} />}

      {d && !d.locked && (
        <>
          {d.login && (
            <Section>
              {d.login.username && (
                <Row
                  label={t('Benutzername')}
                  actions={<CopyButton id={id} field="username" label={t('Benutzername')} />}
                >
                  {d.login.username}
                </Row>
              )}
              {d.login.hasPassword && <SecretRow id={id} field="password" label={t('Passwort')} />}
              {d.login.hasTotp && <TotpRow id={id} />}
              {!d.login.username && !d.login.hasPassword && !d.login.hasTotp && (
                <p className="detail-empty-line">{t('Kein Benutzername, kein Passwort.')}</p>
              )}
            </Section>
          )}

          {d.login && d.login.uris.length > 0 && (
            <Section title={d.login.uris.length === 1 ? t('Website') : t('Websites')}>
              {d.login.uris.map((uri, index) => (
                <Row
                  key={index}
                  label={uri.host ?? t('Adresse')}
                  actions={
                    <>
                      {uri.openable && (
                        <button
                          className="icon-button"
                          onClick={() =>
                            void openItemUri(id, index).catch((e) => toast(String(e), 'error'))
                          }
                          aria-label={t('{uri} im Browser öffnen', {
                            uri: uri.uri,
                          })}
                          title={t('Im Browser öffnen')}
                        >
                          <Icon name="external" size={15} />
                        </button>
                      )}
                      <CopyButton id={id} field={`uri:${index}`} label={t('Adresse')} />
                    </>
                  }
                >
                  <span className="uri">{uri.uri}</span>
                </Row>
              ))}
            </Section>
          )}

          {d.card && (
            <Section>
              {d.card.cardholderName && (
                <Row
                  label={t('Karteninhaber')}
                  actions={<CopyButton id={id} field="card-name" label={t('Karteninhaber')} />}
                >
                  {d.card.cardholderName}
                </Row>
              )}
              {d.card.brand && <Row label={t('Marke')}>{d.card.brand}</Row>}
              {d.card.numberEnding && (
                <SecretRow
                  id={id}
                  field="card-number"
                  label={t('Kartennummer')}
                  masked={`•••• •••• •••• ${d.card.numberEnding}`}
                  colored={false}
                />
              )}
              {(d.card.expMonth || d.card.expYear) && (
                <Row
                  label={t('Gültig bis')}
                  mono
                  actions={<CopyButton id={id} field="card-expiry" label={t('Gültig bis')} />}
                >
                  {(d.card.expMonth ?? '').padStart(2, '0')}/{d.card.expYear ?? ''}
                </Row>
              )}
              {d.card.hasCode && (
                <SecretRow
                  id={id}
                  field="card-code"
                  label={t('Prüfnummer')}
                  masked="•••"
                  colored={false}
                />
              )}
            </Section>
          )}

          {d.identity && d.identity.length > 0 && (
            <Section>
              {d.identity.map((entry) =>
                entry.sensitive ? (
                  <SecretRow
                    key={entry.name}
                    id={id}
                    field={`identity:${entry.name}`}
                    label={t(IDENTITY_LABEL[entry.name] ?? entry.name)}
                    colored={false}
                  />
                ) : (
                  <Row
                    key={entry.name}
                    label={t(IDENTITY_LABEL[entry.name] ?? entry.name)}
                    actions={
                      <CopyButton
                        id={id}
                        field={`identity:${entry.name}`}
                        label={t(IDENTITY_LABEL[entry.name] ?? entry.name)}
                      />
                    }
                  >
                    {entry.value}
                  </Row>
                ),
              )}
            </Section>
          )}

          {d.sshKey && (
            <Section>
              {d.sshKey.fingerprint && (
                <Row
                  label={t('Fingerprint')}
                  mono
                  actions={<CopyButton id={id} field="ssh-fingerprint" label={t('Fingerprint')} />}
                >
                  {d.sshKey.fingerprint}
                </Row>
              )}
              {d.sshKey.publicKey && (
                <Row
                  label={t('Öffentlicher Schlüssel')}
                  mono
                  actions={
                    <CopyButton id={id} field="ssh-public" label={t('Öffentlicher Schlüssel')} />
                  }
                >
                  <span className="uri">{d.sshKey.publicKey}</span>
                </Row>
              )}
              {d.sshKey.hasPrivateKey && (
                <SecretRow
                  id={id}
                  field="ssh-private"
                  label={t('Privater Schlüssel')}
                  masked="-----BEGIN ••••••••-----"
                  multiline
                />
              )}
            </Section>
          )}

          {d.notes && (
            <Section title={t('Notizen')}>
              <div className="notes">
                <p>{d.notes}</p>
                <CopyButton id={id} field="notes" label={t('Notizen')} />
              </div>
            </Section>
          )}

          {d.fields && d.fields.length > 0 && (
            <Section title={t('Eigene Felder')}>
              {d.fields.map((field) => {
                const label = field.name || t('Feld {n}', { n: field.index + 1 });
                if (field.kind === 'hidden' && field.hasValue)
                  return (
                    <SecretRow
                      key={field.index}
                      id={id}
                      field={`field:${field.index}`}
                      label={label}
                    />
                  );
                if (field.kind === 'boolean')
                  return (
                    <Row key={field.index} label={label}>
                      <span className="bool" data-on={field.value === 'true' || undefined}>
                        {field.value === 'true' ? t('Ja') : t('Nein')}
                      </span>
                    </Row>
                  );
                if (field.kind === 'linked')
                  return (
                    <Row key={field.index} label={label}>
                      <span className="muted">{t('verknüpft mit einem anderen Feld')}</span>
                    </Row>
                  );
                return (
                  <Row
                    key={field.index}
                    label={label}
                    actions={
                      field.value ? (
                        <CopyButton id={id} field={`field:${field.index}`} label={label} />
                      ) : undefined
                    }
                  >
                    {field.value ?? <span className="muted">—</span>}
                  </Row>
                );
              })}
            </Section>
          )}

          {d.passwordHistory && d.passwordHistory.length > 0 && (
            <Section>
              <button
                className="history-toggle quiet"
                aria-expanded={showHistory}
                onClick={() => setShowHistory(!showHistory)}
              >
                <Icon name="history" size={15} />
                {d.passwordHistory.length === 1
                  ? t('1 früheres Passwort')
                  : t('{n} frühere Passwörter', { n: d.passwordHistory.length })}
                <Icon name="chevron" size={14} className={showHistory ? 'turned' : undefined} />
              </button>
              {showHistory &&
                d.passwordHistory.map((entry) => (
                  <SecretRow
                    key={entry.index}
                    id={id}
                    field={`history:${entry.index}`}
                    label={when(entry.lastUsed) ?? t('Früher')}
                  />
                ))}
            </Section>
          )}

          <footer className="detail-foot">
            {d.login && d.login.passkeys > 0 && (
              <p>
                <Icon name="key" size={13} />
                {t('Mit Passkey – den kann UwULock noch nicht benutzen.')}
              </p>
            )}
            {(d.attachments ?? 0) > 0 && (
              <p>
                <Icon name="file" size={13} />
                {t('{n} Anhänge – die öffnest du vorerst im Web-Tresor.', {
                  n: d.attachments ?? 0,
                })}
              </p>
            )}
            <p className="muted">
              {[
                when(summary.revisionDate) &&
                  t('Geändert {when}', {
                    when: when(summary.revisionDate) ?? '',
                  }),
                when(d.creationDate) && t('Erstellt {when}', { when: when(d.creationDate) ?? '' }),
                d.login?.passwordRevisionDate &&
                  t('Passwort geändert {when}', {
                    when: when(d.login.passwordRevisionDate) ?? '',
                  }),
              ]
                .filter(Boolean)
                .join(' · ')}
            </p>
          </footer>
        </>
      )}
    </article>
  );
}
