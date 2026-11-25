import { Button, Icon, IconButton, ICONS } from '@uwusuite/design';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import {
  copyField,
  deleteItem,
  deletePasskey,
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
  type PasskeyInfo,
  type TotpCode,
} from '../lib/api';
import { useFeature } from '../lib/branding';
import { errorText, maskedErrorText } from '../lib/errors';
import { charClasses, copiedText, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { IDENTITY_LABEL, KIND_LABEL, securityLabel } from '../lib/items';
import {
  reloadMaskedLinks,
  STATE_LABEL,
  updateMasked,
  useMaskedLinks,
  type MaskedLink,
} from '../lib/masked';
import { getSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { isEnterprise, readWifi } from '../lib/wifi';
import { Attachments } from './web/Attachments';
import { ItemComfort } from './web/ItemComfort';
import { ShareAsSend } from './web/ShareAsSend';
import { ShareToFamily, shareTargets } from './web/ShareToFamily';
import { WifiShare } from './web/WifiShare';
import { ItemTile } from './ItemTile';
import { Modal } from './Modal';
import { PasswordInput } from './PasswordInput';
import { TotpCodes } from './Totp';

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

/** A row's tools step back until the row is pointed at, only so far that they keep 3:1. */
const ROW_TOOL =
  'opacity-75 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 contrast-high:opacity-100';

function CopyButton({ id, field, label }: { id: string; field: string; label: string }) {
  useLanguage();
  return (
    <IconButton
      icon={ICONS.copy}
      className={ROW_TOOL}
      onClick={() => void copy(id, field)}
      label={t('{label} kopieren', { label })}
    />
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
    <div className="detail-row group">
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
          <IconButton
            icon={value === null ? ICONS.show : ICONS.hide}
            className={ROW_TOOL}
            onClick={() => void toggle()}
            label={
              value === null ? t('{label} zeigen', { label }) : t('{label} verbergen', { label })
            }
            aria-pressed={value !== null}
          />
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

  return (
    <Row
      label={t('Einmal-Code (TOTP)')}
      mono
      actions={<CopyButton id={id} field="totp" label={t('Code')} />}
    >
      {error ? (
        <span className="detail-error">{error}</span>
      ) : code ? (
        <TotpCodes code={code} onCopyNext={() => void copy(id, 'totp-next')} />
      ) : (
        '…'
      )}
    </Row>
  );
}

/**
 * The first website, and the others behind "+2 weitere Websites": most logins are used on one,
 * and a long list pushes the rest of the item down.
 */
function Websites({ id, uris }: { id: string; uris: NonNullable<Detail['login']>['uris'] }) {
  useLanguage();
  const [all, setAll] = useState(false);
  const shown = all ? uris : uris.slice(0, 1);
  const more = uris.length - 1;
  return (
    <Section title={uris.length === 1 ? t('Website') : t('Websites')}>
      {shown.map((uri, index) => (
        <Row
          key={index}
          label={uri.host ?? t('Adresse')}
          actions={
            <>
              {uri.openable && (
                <IconButton
                  icon={ICONS.openExternal}
                  className={ROW_TOOL}
                  onClick={() =>
                    void openItemUri(id, index).catch((e) => toast(String(e), 'error'))
                  }
                  label={t('{uri} im Browser öffnen', {
                    uri: uri.uri,
                  })}
                />
              )}
              <CopyButton id={id} field={`uri:${index}`} label={t('Adresse')} />
            </>
          }
        >
          <span className="uri">{uri.uri}</span>
        </Row>
      ))}
      {more > 0 && (
        <Button
          variant="ghost"
          icon={ICONS.website}
          className="history-toggle"
          aria-expanded={all}
          onClick={() => setAll(!all)}
          data-more-websites
        >
          {all
            ? t('Weniger zeigen')
            : more === 1
              ? t('+1 weitere Website')
              : t('+{n} weitere Websites', { n: more })}
          <Icon icon={ICONS.next} size="xs" className={all ? 'turned' : undefined} />
        </Button>
      )}
    </Section>
  );
}

/**
 * The login's passkeys: for which site, which user, since when — and deleting one. Signing in
 * with them is the browser extension's and the apps' job.
 */
function Passkeys({
  id,
  passkeys,
  count,
  editable,
  reload,
}: {
  id: string;
  passkeys: PasskeyInfo[];
  /** How many the item has, also when the list could not be read. */
  count: number;
  editable: boolean;
  /** Reads the list again: after a delete, also one that failed because it changed meanwhile. */
  reload: () => void;
}) {
  useLanguage();
  const [asking, setAsking] = useState<PasskeyInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const remove = async (passkey: PasskeyInfo) => {
    setBusy(true);
    try {
      await deletePasskey(id, passkey);
      toast(t('Passkey gelöscht.'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
      setAsking(null);
      reload();
    }
  };
  const site = (passkey: PasskeyInfo) =>
    passkey.readable ? passkey.rpName || passkey.rpId : t('Passkey, den UwULock nicht lesen kann');
  return (
    <Section title={count === 1 ? t('Passkey') : t('Passkeys')}>
      {passkeys.map((passkey) => (
        <div
          className="detail-row passkey-row group"
          key={`${passkey.index}-${passkey.credentialId}`}
        >
          <Icon icon={ICONS.passkey} className="passkey-icon" />
          <div className="detail-text">
            <span className="detail-value">
              {site(passkey)}
              {passkey.readable && passkey.rpName && passkey.rpName !== passkey.rpId && (
                <span className="muted"> · {passkey.rpId}</span>
              )}
            </span>
            <span className="detail-label">
              {[
                passkey.userName || passkey.userDisplayName,
                when(passkey.creationDate || null) &&
                  t('Erstellt {when}', { when: when(passkey.creationDate) ?? '' }),
              ]
                .filter(Boolean)
                .join(' · ') || t('Ohne Benutzername')}
            </span>
          </div>
          {editable && (
            <div className="detail-actions">
              <IconButton
                icon={ICONS.delete}
                className={ROW_TOOL}
                disabled={busy}
                onClick={() => setAsking(passkey)}
                label={t('Passkey für {site} löschen', { site: site(passkey) })}
              />
            </div>
          )}
        </div>
      ))}
      {passkeys.length < count && (
        <p className="detail-empty-line">
          {t('{n} Passkeys ließen sich nicht lesen.', { n: count - passkeys.length })}
        </p>
      )}
      <p className="field-hint">
        {t(
          'Anmelden mit dem Passkey geht mit der UwULock-Erweiterung oder den Apps. Er bleibt beim Duplizieren und im Export erhalten.',
        )}
      </p>
      {asking && (
        <Modal
          title={t('Passkey löschen?')}
          tone="warning"
          onCancel={() => setAsking(null)}
          footer={
            <>
              <span className="spacer" />
              <Button
                variant="danger"
                data-secondary
                disabled={busy}
                onClick={() => void remove(asking)}
              >
                {t('Passkey löschen')}
              </Button>
              <Button variant="primary" data-autofocus onClick={() => setAsking(null)}>
                {t('Abbrechen')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Danach meldest du dich bei {site} nicht mehr mit diesem Passkey an. Hast du keinen anderen Weg hinein, richte dort vorher einen neuen ein.',
              { site: site(asking) },
            )}
          </p>
        </Modal>
      )}
    </Section>
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
        <Icon icon={ICONS.locked} />
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
        <Button variant="primary" type="submit" disabled={busy || !password}>
          {busy ? t('Prüft …') : t('Öffnen')}
        </Button>
      </div>
    </form>
  );
}

/**
 * Before a masked address's item goes: switch the address off too (the default)? Not deleted —
 * that could not be undone, and the item may come back out of the trash.
 */
export function MaskedOffCheck({
  emails,
  checked,
  onChange,
}: {
  emails: string[];
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  useLanguage();
  if (!emails.length) return null;
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {emails.length === 1
          ? t('Maskierte Adresse {email} abschalten?', { email: emails[0]! })
          : t('{n} maskierte Adressen abschalten?', { n: emails.length })}
      </span>
    </label>
  );
}

/**
 * Switch off the masked addresses of items about to go. UwUMail not answering must not keep
 * the items: that is said, and the deleting goes on.
 */
export async function switchOffMasked(links: MaskedLink[]): Promise<void> {
  const results = await Promise.allSettled(
    links.map((link) => updateMasked(link.id, { state: 'disabled' })),
  );
  const failed = results.find((result) => result.status === 'rejected');
  if (failed) toast(maskedErrorText((failed as PromiseRejectedResult).reason), 'error');
  void reloadMaskedLinks();
}

/** Asks before something is thrown away for good. */
function ConfirmDelete({
  name,
  permanent,
  masked,
  onCancel,
  onConfirm,
}: {
  name: string;
  permanent: boolean;
  /** The item's masked address, when it is on. */
  masked: MaskedLink | null;
  onCancel: () => void;
  onConfirm: (switchOff: boolean) => void;
}) {
  useLanguage();
  const [switchOff, setSwitchOff] = useState(true);
  return (
    <Modal
      title={permanent ? t('Endgültig löschen?') : t('In den Papierkorb?')}
      tone={permanent ? 'warning' : 'default'}
      onCancel={onCancel}
      footer={
        <>
          <span className="spacer" />
          <Button
            variant="danger"
            data-secondary
            onClick={() => onConfirm(Boolean(masked) && switchOff)}
          >
            {permanent ? t('Endgültig löschen') : t('In den Papierkorb')}
          </Button>
          <Button variant="primary" data-autofocus onClick={onCancel}>
            {t('Abbrechen')}
          </Button>
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
      <MaskedOffCheck
        emails={masked ? [masked.email] : []}
        checked={switchOff}
        onChange={setSwitchOff}
      />
    </Modal>
  );
}

export function ItemDetail({
  summary,
  overview,
  onEdit,
  onClone,
}: {
  summary: ItemSummary;
  overview: Overview | null;
  onEdit: () => void;
  /** Opens the editor on a copy of the item ("Duplizieren"). */
  onClone?: () => void;
}) {
  useLanguage();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [asking, setAsking] = useState<null | 'trash' | 'permanent'>(null);
  const [sharing, setSharing] = useState(false);
  const [moving, setMoving] = useState(false);
  const [sharingWifi, setSharingWifi] = useState(false);
  const [busy, setBusy] = useState(false);
  const id = summary.id;
  const link = useMaskedLinks(useFeature('masked-addresses'))[id] ?? null;

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
  const wifi = d && !d.locked && summary.kind === 'wifi' ? readWifi(d.fields ?? []) : null;
  const fields = wifi ? wifi.others : (d?.fields ?? []);
  return (
    <article className="detail" aria-label={summary.name}>
      <header className="detail-head">
        <ItemTile item={summary} size="large" />
        <div className="detail-title">
          <h2>
            {summary.name || t('(ohne Namen)')}
            {summary.favorite && (
              <Icon icon={ICONS.favorite} className="badge-star" label={t('Favorit')} />
            )}
          </h2>
          <p className="chips">
            <span className="chip">{t(KIND_LABEL[summary.kind])}</span>
            {folder && (
              <span className="chip">
                <Icon icon={ICONS.folder} size="xs" />
                {folder}
              </span>
            )}
            {org && (
              <span className="chip">
                <Icon icon={ICONS.organization} size="xs" />
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
              <Button
                variant="ghost"
                icon={ICONS.history}
                disabled={busy}
                onClick={() => void act(() => restoreItem(id), t('Aus dem Papierkorb geholt ✧'))}
              >
                {t('Wiederherstellen')}
              </Button>
              <Button
                variant="ghost"
                icon={ICONS.delete}
                className="text-danger-ink!"
                disabled={busy}
                onClick={() => setAsking('permanent')}
              >
                {t('Endgültig löschen')}
              </Button>
            </>
          ) : (
            <>
              <IconButton
                icon={ICONS.favorite}
                // Filled pink like the star next to the name, as before.
                className={summary.favorite ? '[&>svg]:fill-current [&>svg]:text-pink' : undefined}
                disabled={busy}
                aria-pressed={summary.favorite}
                label={summary.favorite ? t('Favorit entfernen') : t('Zu Favoriten')}
                onClick={() =>
                  void act(
                    () => setFavorite(id, !summary.favorite),
                    summary.favorite ? t('Kein Favorit mehr') : t('Favorit ✧'),
                  )
                }
              />
              <IconButton
                icon={ICONS.archive}
                disabled={busy}
                aria-pressed={summary.archived}
                label={summary.archived ? t('Aus dem Archiv holen') : t('Archivieren')}
                onClick={() =>
                  void act(
                    () => archiveItem(id, !summary.archived),
                    summary.archived ? t('Aus dem Archiv geholt ✧') : t('Archiviert.'),
                  )
                }
              />
              <IconButton
                icon={ICONS.send}
                disabled={busy || summary.broken || !d || d.locked}
                label={t('Als Send teilen')}
                aria-haspopup="dialog"
                onClick={() => setSharing(true)}
              />
              {/* A family's item stays one: copies are of one's own items. */}
              {onClone && !summary.organizationId && (
                <IconButton
                  icon={ICONS.collection}
                  disabled={busy || summary.broken || !d || d.locked}
                  label={t('Duplizieren')}
                  aria-haspopup="dialog"
                  onClick={onClone}
                  data-clone
                />
              )}
              <IconButton
                icon={ICONS.delete}
                disabled={busy}
                label={t('In den Papierkorb')}
                onClick={() => setAsking('trash')}
              />
              {(summary.organizationId || shareTargets().length > 0) && (
                <IconButton
                  icon={summary.organizationId ? ICONS.overview : ICONS.home}
                  disabled={busy || summary.broken || !!d?.locked}
                  label={
                    summary.organizationId ? t('Sammlungen') : t('In eine Familie verschieben')
                  }
                  onClick={() => setMoving(true)}
                />
              )}
              <Button
                variant="primary"
                icon={ICONS.edit}
                disabled={busy || summary.broken || !!d?.locked}
                onClick={onEdit}
                title={t('Bearbeiten (E)')}
                aria-keyshortcuts="E"
                data-edit
              >
                {t('Bearbeiten')}
              </Button>
            </>
          )}
        </div>
      </header>

      {sharing && (
        <ShareAsSend itemId={id} itemName={summary.name} onClose={() => setSharing(false)} />
      )}

      {moving && (
        <ShareToFamily
          itemId={id}
          itemName={summary.name || t('(ohne Namen)')}
          organizationId={summary.organizationId}
          collectionIds={summary.collectionIds}
          onClose={() => setMoving(false)}
        />
      )}

      {sharingWifi && wifi && (
        <WifiShare itemId={id} wifi={wifi} onClose={() => setSharingWifi(false)} />
      )}

      {asking && (
        <ConfirmDelete
          name={summary.name || t('(ohne Namen)')}
          permanent={asking === 'permanent'}
          masked={link?.state === 'enabled' ? link : null}
          onCancel={() => setAsking(null)}
          onConfirm={(switchOff) =>
            void act(
              async () => {
                if (switchOff && link) await switchOffMasked([link]);
                await deleteItem(id, asking === 'permanent');
              },
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
                  {link && (
                    <span className="chip masked-chip">
                      <Icon icon={ICONS.maskedAddress} size="xs" />
                      {link.state
                        ? t('Maskierte Adresse · {state}', { state: t(STATE_LABEL[link.state]) })
                        : t('Maskierte Adresse')}
                      {/* The username was changed since: say which address it is. */}
                      {link.email.toLowerCase() !== d.login.username.toLowerCase() &&
                        ` · ${link.email}`}
                    </span>
                  )}
                </Row>
              )}
              {d.login.hasPassword && <SecretRow id={id} field="password" label={t('Passwort')} />}
              {d.login.hasTotp && <TotpRow id={id} />}
              {!d.login.username && !d.login.hasPassword && !d.login.hasTotp && (
                <p className="detail-empty-line">{t('Kein Benutzername, kein Passwort.')}</p>
              )}
            </Section>
          )}

          {d.login && d.login.uris.length > 0 && <Websites id={id} uris={d.login.uris} />}

          {d.login && d.login.passkeys > 0 && (
            <Passkeys
              id={id}
              passkeys={d.login.passkeyList ?? []}
              count={d.login.passkeys}
              editable={!summary.deleted && !summary.broken}
              reload={load}
            />
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

          {wifi && (
            <Section>
              <Row
                label={t('Netzwerkname (SSID)')}
                mono
                actions={
                  wifi.ssid && wifi.from.ssid !== undefined ? (
                    <CopyButton id={id} field={`field:${wifi.from.ssid}`} label="SSID" />
                  ) : undefined
                }
              >
                {wifi.ssid || <span className="muted">—</span>}
              </Row>
              {wifi.password?.hasValue && wifi.security !== 'None' && (
                <SecretRow id={id} field={`field:${wifi.password.index}`} label={t('Passwort')} />
              )}
              <Row label={t('Sicherheit')}>
                {wifi.security ? t(securityLabel(wifi.security)) : <span className="muted">—</span>}
              </Row>
              <Row label={t('Verstecktes Netzwerk')}>
                <span className="bool" data-on={wifi.hidden || undefined}>
                  {wifi.hidden ? t('Ja') : t('Nein')}
                </span>
              </Row>
              {isEnterprise(wifi.security) &&
                (
                  [
                    ['eap', t('EAP-Methode')],
                    ['phase2', t('Phase 2')],
                    ['identity', t('Identität')],
                    ['anonymous', t('Anonyme Identität')],
                    ['ca', t('CA-Zertifikat')],
                  ] as const
                ).map(([key, label]) =>
                  wifi[key] ? (
                    <Row
                      key={key}
                      label={label}
                      actions={
                        wifi.from[key] !== undefined ? (
                          <CopyButton id={id} field={`field:${wifi.from[key]}`} label={label} />
                        ) : undefined
                      }
                    >
                      {wifi[key] === 'none' ? t('Keine') : wifi[key]}
                    </Row>
                  ) : null,
                )}
              <Button
                variant="ghost"
                icon={ICONS.qrCode}
                // vault.css still aligns `.detail-card > button.quiet` this way; the class is gone.
                className="justify-self-start -ml-3"
                onClick={() => setSharingWifi(true)}
                aria-haspopup="dialog"
                data-wifi-share
              >
                {t('Als QR-Code teilen')}
              </Button>
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

          {fields.length > 0 && (
            <Section title={t('Eigene Felder')}>
              {fields.map((field) => {
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
              <Button
                variant="ghost"
                icon={ICONS.history}
                className="history-toggle"
                aria-expanded={showHistory}
                onClick={() => setShowHistory(!showHistory)}
              >
                {d.passwordHistory.length === 1
                  ? t('1 früheres Passwort')
                  : t('{n} frühere Passwörter', { n: d.passwordHistory.length })}
                <Icon icon={ICONS.next} size="xs" className={showHistory ? 'turned' : undefined} />
              </Button>
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

          <Attachments
            itemId={id}
            revision={summary.revisionDate}
            editable={!summary.deleted && !summary.organizationId}
          />

          <ItemComfort summary={summary} />

          <footer className="detail-foot">
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
