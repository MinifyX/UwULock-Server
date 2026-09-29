import { useCallback, useEffect, useMemo, useState } from 'react';
import { secret } from '../../lib/account';
import { vaultItems } from '../../lib/api';
import { useFeature } from '../../lib/branding';
import { errorCode, errorText, maskedErrorText } from '../../lib/errors';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import {
  connectMasked,
  createMasked,
  createMaskedApiKey,
  defaultDomainOf,
  deleteMasked,
  deleteMaskedApiKey,
  disconnectMasked,
  forwarderUrls,
  maskedAddresses,
  maskedApiKeys,
  reloadMaskedConnection,
  reloadMaskedLinks,
  STATE_LABEL,
  updateMasked,
  useMaskedConnectionState,
  type ConnectResult,
  type MaskedAddress,
  type MaskedApiKey,
  type MaskedConnection,
} from '../../lib/masked';
import { go } from '../../lib/route';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { PasswordPrompt, Row } from './controls';

/** Why connecting did not work, from the way back (`?result=error&reason=…`). */
export function connectFailureText(reason: Extract<ConnectResult, { ok: false }>['reason']) {
  switch (reason) {
    case 'denied':
      return t('Nicht verbunden: Bei UwUMail wurde „Ablehnen“ gewählt.');
    case 'expired':
      return t('Nicht verbunden: Das hat zu lange gedauert. Versuch es noch einmal.');
    case 'invalid_state':
      return t(
        'Nicht verbunden: Die Antwort von UwUMail passte nicht zu dieser Anfrage. Starte das Verbinden noch einmal hier im selben Browser.',
      );
    case 'upstream':
      return t('Nicht verbunden: UwUMail hat nicht wie erwartet geantwortet.');
    default:
      return t('Nicht verbunden: Etwas ist schiefgegangen.');
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t('Kopiert ✧'));
  } catch (e) {
    toast(errorText(e), 'error');
  }
}

/** Which of the connection's domains a new address gets. */
export function MaskedDomainField({
  connection,
  value,
  onChange,
}: {
  connection: MaskedConnection;
  value: string;
  onChange: (domain: string) => void;
}) {
  useLanguage();
  const domains = connection.domains ?? [];
  return (
    <label className="field">
      <span>{t('Domain')}</span>
      <select
        className="select"
        value={value || defaultDomainOf(connection)}
        disabled={domains.length < 2}
        onChange={(e) => onChange(e.target.value)}
      >
        {domains.map((domain) => (
          <option key={domain} value={domain}>
            {domain === connection.defaultDomain ? t('{domain} (Standard)', { domain }) : domain}
          </option>
        ))}
      </select>
    </label>
  );
}

/**
 * A new masked address: its domain, the website it is for, a description. From the settings,
 * and from an item's editor (then for that item).
 */
export function NewMaskedDialog({
  connection,
  forDomain: initialFor = '',
  description: initialDescription = '',
  cipherId = null,
  note,
  onClose,
  onCreated,
}: {
  connection: MaskedConnection;
  forDomain?: string;
  description?: string;
  cipherId?: string | null;
  /** Something to know first: the item has an address already. */
  note?: string;
  onClose: () => void;
  onCreated: (address: MaskedAddress) => Promise<void> | void;
}) {
  useLanguage();
  const [domain, setDomain] = useState(defaultDomainOf(connection));
  const [forDomain, setForDomain] = useState(initialFor);
  const [description, setDescription] = useState(initialDescription);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const made = await createMasked({
        forDomain: forDomain.trim(),
        description: description.trim(),
        domain: domain || null,
        cipherId,
      });
      await onCreated(made);
      void reloadMaskedLinks();
    } catch (e) {
      setError(maskedErrorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('Neue maskierte Adresse')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <button className="quiet" data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <span className="spacer" />
          <button className="primary" disabled={busy} onClick={() => void submit()}>
            {busy ? t('Einen Moment …') : t('Anlegen')}
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
        <p className="dialog-lead">
          {t(
            'UwUMail denkt sich die Adresse aus. Mails an sie landen in deinem Postfach, bis du sie abschaltest.',
          )}
        </p>
        {note && <p className="field-hint">{note}</p>}
        <MaskedDomainField connection={connection} value={domain} onChange={setDomain} />
        <label className="field">
          <span>{t('Für die Website (freiwillig)')}</span>
          <input
            value={forDomain}
            spellCheck={false}
            placeholder="https://shop.example.com"
            onChange={(e) => setForDomain(e.target.value)}
          />
        </label>
        <label className="field">
          <span>{t('Beschreibung (freiwillig)')}</span>
          <input
            value={description}
            maxLength={200}
            onChange={(e) => setDescription(e.target.value)}
          />
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

type Dialog =
  | { kind: 'disconnect' }
  | { kind: 'new' }
  | { kind: 'delete'; address: MaskedAddress }
  | { kind: 'new-key' }
  | { kind: 'delete-key'; key: MaskedApiKey }
  | null;

/**
 * Masked addresses (§13): connecting UwUMail once, the addresses there, and keys for the
 * official Bitwarden apps, whose generators make addresses through this server.
 */
export function MaskedSettings({ onClose }: { onClose: () => void }) {
  useLanguage();
  const enabled = useFeature('masked-addresses');
  const state = useMaskedConnectionState(true);
  const connection = state.connection;
  const [server, setServer] = useState('');
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);

  // Asked afresh each time the page opens (the first time asks anyway): UwUMail may have ended
  // it meanwhile.
  const [known] = useState(state.loaded);
  useEffect(() => {
    if (known) void reloadMaskedConnection();
  }, [known]);

  const allowed = connection?.allowedServers ?? [];
  const chosenServer = server || allowed[0]?.url || '';
  const connected = Boolean(connection?.connected);

  const connect = async (target: string) => {
    setBusy(true);
    try {
      const answer = await connectMasked(target);
      // The same tab: the cookie the server just set only fits this browser.
      location.href = answer.authorizeUrl;
    } catch (e) {
      toast(maskedErrorText(e), 'error');
      setBusy(false);
    }
  };

  if (!state.loaded) return <p className="settings-lead">{t('Lädt …')}</p>;
  if (!connection) {
    return (
      <p className="settings-lead" role="alert">
        {errorCode(state.error) === 'feature_off'
          ? t(
              'Auf diesem Server ist noch kein UwUMail-Server freigegeben. Ein Admin kann das im Admin-Portal unter Einstellungen einrichten.',
            )
          : maskedErrorText(state.error)}
      </p>
    );
  }

  const serverName = (url: string | null) =>
    allowed.find((entry) => entry.url === url)?.name ?? url ?? '';

  return (
    <>
      <p className="settings-lead">
        {t(
          'Für jede Website eine eigene Mail-Adresse von deinem UwUMail-Server. Mails an sie landen in deinem Postfach – und eine Adresse, die Spam bekommt oder verkauft wurde, schaltest du einfach ab.',
        )}
      </p>

      {!connected ? (
        !enabled || allowed.length === 0 ? (
          <p className="settings-lead">
            {t(
              'Auf diesem Server ist noch kein UwUMail-Server freigegeben. Ein Admin kann das im Admin-Portal unter Einstellungen einrichten.',
            )}
          </p>
        ) : (
          <>
            <Row
              label={t('UwUMail-Server')}
              description={t(
                'Du meldest dich dort an und erlaubst UwULock, maskierte Adressen anzulegen. Deine Mails lesen oder senden kann UwULock damit nicht.',
              )}
            >
              {allowed.length > 1 ? (
                <select
                  className="select"
                  aria-label={t('UwUMail-Server')}
                  value={chosenServer}
                  onChange={(e) => setServer(e.target.value)}
                >
                  {allowed.map((entry) => (
                    <option key={entry.url} value={entry.url}>
                      {entry.name ? `${entry.name} (${entry.url})` : entry.url}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="setting-value">{serverName(chosenServer) || chosenServer}</span>
              )}
            </Row>
            <Row
              label={t('Verbinden')}
              description={t(
                'Du kommst danach hierher zurück und entsperrst den Tresor noch einmal.',
              )}
            >
              <button
                className="primary"
                disabled={busy || !chosenServer}
                onClick={() => void connect(chosenServer)}
              >
                {busy ? t('Einen Moment …') : t('Mit UwUMail verbinden')}
              </button>
            </Row>
          </>
        )
      ) : (
        <>
          <Row
            label={t('Verbunden mit')}
            description={[
              connection.server,
              connection.connectedDate &&
                t('Seit {when}.', { when: when(connection.connectedDate) ?? '' }),
              connection.lastUsedDate &&
                t('Zuletzt benutzt {when}.', { when: when(connection.lastUsedDate) ?? '' }),
            ]
              .filter(Boolean)
              .join(' · ')}
          >
            <span className="setting-value">{connection.username}</span>
          </Row>
          {connection.status === 'revoked' ? (
            <Row
              label={t('Zustand')}
              description={t(
                'UwUMail hat die Verbindung beendet – etwa, weil sie dort abgemeldet wurde. Verbinde dich neu, um wieder Adressen anzulegen.',
              )}
            >
              <button
                className="primary"
                disabled={busy || !connection.server}
                onClick={() => void connect(connection.server ?? '')}
              >
                {t('Neu verbinden')}
              </button>
            </Row>
          ) : (
            <Row
              label={t('Zustand')}
              description={
                connection.status === 'unreachable'
                  ? t('UwUMail war beim letzten Versuch nicht erreichbar.')
                  : undefined
              }
            >
              <span className="setting-value">
                {connection.status === 'unreachable' ? t('Nicht erreichbar') : t('Verbunden ✧')}
              </span>
            </Row>
          )}
          <Row
            label={t('Domains')}
            description={
              connection.defaultDomain
                ? t('Neue Adressen bekommen {domain}, wenn du nichts anderes wählst.', {
                    domain: connection.defaultDomain,
                  })
                : undefined
            }
          >
            <span className="setting-value">{(connection.domains ?? []).join(', ')}</span>
          </Row>
          <Row
            label={t('Trennen')}
            description={t(
              'Die Adressen bleiben bei UwUMail und bekommen weiter Mails; UwULock legt nur keine neuen mehr an.',
            )}
          >
            <button className="quiet danger-text" onClick={() => setDialog({ kind: 'disconnect' })}>
              {t('Trennen …')}
            </button>
          </Row>

          <Addresses
            connection={connection}
            dialog={dialog}
            setDialog={setDialog}
            onOpenItem={(itemId) => {
              onClose();
              go(`/vault?itemId=${encodeURIComponent(itemId)}`);
            }}
          />
          <ApiKeys connection={connection} dialog={dialog} setDialog={setDialog} />
        </>
      )}

      {dialog?.kind === 'disconnect' && (
        <Modal
          title={t('UwUMail trennen?')}
          tone="warning"
          onCancel={() => !busy && setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary disabled={busy} onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await disconnectMasked();
                    toast(t('Getrennt.'));
                    setDialog(null);
                    await Promise.all([reloadMaskedConnection(), reloadMaskedLinks()]);
                  } catch (e) {
                    toast(maskedErrorText(e), 'error');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t('Trennen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'UwULock meldet sich bei {server} ab. Die Adressen bleiben dort und bekommen weiter Mails; die Bitwarden-Apps legen über ihre Schlüssel keine neuen mehr an.',
              { server: serverName(connection.server) },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

/** The addresses at UwUMail: copy, switch off and on, delete, and the item each belongs to. */
function Addresses({
  connection,
  dialog,
  setDialog,
  onOpenItem,
}: {
  connection: MaskedConnection;
  dialog: Dialog;
  setDialog: (next: Dialog) => void;
  onOpenItem: (itemId: string) => void;
}) {
  useLanguage();
  const [list, setList] = useState<MaskedAddress[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [names, setNames] = useState<Map<string, string>>(new Map());
  const [showDeleted, setShowDeleted] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const reload = useCallback(() => {
    maskedAddresses().then(
      (found) => {
        setList(found);
        setError(null);
      },
      (e) => setError(maskedErrorText(e)),
    );
  }, []);
  useEffect(reload, [reload]);

  // The items' names, from the open vault: the server only knows their ids.
  useEffect(() => {
    vaultItems().then(
      (items) => setNames(new Map(items.map((item) => [item.id, item.name]))),
      () => undefined,
    );
  }, []);

  const shown = useMemo(
    () =>
      [...(list ?? [])]
        .filter((address) => showDeleted || address.state !== 'deleted')
        .sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? '')),
    [list, showDeleted],
  );
  const deleted = (list ?? []).filter((address) => address.state === 'deleted').length;

  const act = async (address: MaskedAddress, work: () => Promise<unknown>, done: string) => {
    setBusy(address.id);
    try {
      await work();
      toast(done);
      reload();
      void reloadMaskedLinks();
    } catch (e) {
      toast(maskedErrorText(e), 'error');
    } finally {
      setBusy(null);
    }
  };

  const deleting = dialog?.kind === 'delete' ? dialog.address : null;

  return (
    <>
      <h3 className="settings-heading">{t('Adressen')}</h3>
      <div className="form-actions">
        {deleted > 0 && (
          <label className="check">
            <input
              type="checkbox"
              checked={showDeleted}
              onChange={(e) => setShowDeleted(e.target.checked)}
            />
            <span>{t('Gelöschte zeigen ({n})', { n: deleted })}</span>
          </label>
        )}
        <span className="spacer" />
        <button
          className="primary"
          onClick={() => setDialog({ kind: 'new' })}
          disabled={connection.status === 'revoked'}
        >
          <Icon name="plus" size={15} />
          {t('Neue Adresse …')}
        </button>
      </div>
      {error && (
        <p className="notice" data-tone="error" role="alert">
          {error}
        </p>
      )}
      {list === null && !error && <p className="empty-note">{t('Lädt …')}</p>}
      {list !== null && shown.length === 0 && (
        <p className="empty-note">{t('Noch keine maskierten Adressen.')}</p>
      )}
      {shown.length > 0 && (
        <ul className="masked-list">
          {shown.map((address) => {
            const itemName = address.cipherId ? names.get(address.cipherId) : undefined;
            const gone = address.state === 'deleted';
            return (
              <li key={address.id} className="masked-card" data-state={address.state}>
                <div className="channel-head">
                  <b className="channel-name mono">{address.email}</b>
                  <span className="chip">{t(STATE_LABEL[address.state] ?? address.state)}</span>
                  <span className="spacer" />
                  {!gone && (
                    <button
                      className="icon-button"
                      title={t('Kopieren')}
                      aria-label={t('{label} kopieren', { label: address.email })}
                      onClick={() => void copy(address.email)}
                    >
                      <Icon name="copy" size={15} />
                    </button>
                  )}
                </div>
                <p className="channel-status">
                  {[
                    address.forDomain,
                    address.description,
                    address.lastMessageAt
                      ? t('Letzte Mail {when}', { when: when(address.lastMessageAt) ?? '' })
                      : t('Noch keine Mail'),
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </p>
                {!gone && (
                  <div className="form-actions">
                    {address.cipherId && (
                      <button
                        className="quiet"
                        onClick={() => onOpenItem(address.cipherId ?? '')}
                        disabled={!itemName}
                      >
                        <Icon name="key" size={15} />
                        {itemName
                          ? t('Eintrag: {name}', { name: itemName || t('(ohne Namen)') })
                          : t('Eintrag nicht im Tresor')}
                      </button>
                    )}
                    <span className="spacer" />
                    {address.state === 'enabled' ? (
                      <button
                        disabled={busy === address.id}
                        onClick={() =>
                          void act(
                            address,
                            () => updateMasked(address.id, { state: 'disabled' }),
                            t('Abgeschaltet: Mails an {email} kommen nicht mehr an.', {
                              email: address.email,
                            }),
                          )
                        }
                      >
                        {t('Abschalten')}
                      </button>
                    ) : (
                      <button
                        disabled={busy === address.id}
                        onClick={() =>
                          void act(
                            address,
                            () => updateMasked(address.id, { state: 'enabled' }),
                            t('Eingeschaltet ✧'),
                          )
                        }
                      >
                        {t('Einschalten')}
                      </button>
                    )}
                    <button
                      className="quiet danger-text"
                      disabled={busy === address.id}
                      onClick={() => setDialog({ kind: 'delete', address })}
                    >
                      {t('Löschen …')}
                    </button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {dialog?.kind === 'new' && (
        <NewMaskedDialog
          connection={connection}
          onClose={() => setDialog(null)}
          onCreated={(made) => {
            setDialog(null);
            toast(t('Angelegt: {email} ✧', { email: made.email }));
            void copy(made.email);
            reload();
          }}
        />
      )}
      {deleting && (
        <Modal
          title={t('Adresse löschen?')}
          tone="warning"
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  setDialog(null);
                  void act(deleting, () => deleteMasked(deleting.id), t('Gelöscht.'));
                }}
              >
                {t('Endgültig löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              '{email} ist danach für immer weg: UwUMail weist Mails an sie ab und vergibt sie nie wieder. Nur abschalten lässt sich rückgängig machen.',
              { email: deleting.email },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

/**
 * Keys for the official Bitwarden apps: their generator makes addresses through this server,
 * as if it were addy.io or SimpleLogin (§13.4–13.6).
 */
function ApiKeys({
  connection,
  dialog,
  setDialog,
}: {
  connection: MaskedConnection;
  dialog: Dialog;
  setDialog: (next: Dialog) => void;
}) {
  useLanguage();
  const [keys, setKeys] = useState<MaskedApiKey[]>([]);
  const [name, setName] = useState('');
  const [made, setMade] = useState<MaskedApiKey | null>(null);
  const urls = forwarderUrls();

  const reload = useCallback(() => {
    maskedApiKeys().then(setKeys, (e) => toast(maskedErrorText(e), 'error'));
  }, []);
  useEffect(reload, [reload]);

  return (
    <>
      <h3 className="settings-heading">{t('Für die Bitwarden-Apps')}</h3>
      <p className="settings-lead">
        {t(
          'In den offiziellen Apps und Erweiterungen: Generator → Benutzername → Weitergeleitete E-Mail-Alias → addy.io oder SimpleLogin. Als „Self-host server URL“ die passende Adresse unten, als API-Schlüssel einen Schlüssel von hier. Als Domain eine deiner Domains: {domains}.',
          { domains: (connection.domains ?? []).join(', ') },
        )}
      </p>
      <div className="form">
        <div className="field">
          <span>{t('addy.io: Self-host server URL')}</span>
          <div className="copy-field">
            <code className="mono">{urls.addy}</code>
            <button
              className="icon-button"
              aria-label={t('{label} kopieren', { label: 'addy.io URL' })}
              onClick={() => void copy(urls.addy)}
            >
              <Icon name="copy" size={15} />
            </button>
          </div>
        </div>
        <div className="field">
          <span>{t('SimpleLogin: Self-host server URL')}</span>
          <div className="copy-field">
            <code className="mono">{urls.simpleLogin}</code>
            <button
              className="icon-button"
              aria-label={t('{label} kopieren', { label: 'SimpleLogin URL' })}
              onClick={() => void copy(urls.simpleLogin)}
            >
              <Icon name="copy" size={15} />
            </button>
          </div>
        </div>
      </div>
      {keys.map((key) => (
        <Row
          key={key.id}
          label={key.name}
          description={[
            key.hint,
            t('Seit {when}.', { when: when(key.creationDate) ?? '' }),
            key.lastUsedDate
              ? t('Zuletzt benutzt {when}.', { when: when(key.lastUsedDate) ?? '' })
              : t('Noch nie benutzt.'),
          ].join(' · ')}
        >
          <button
            className="quiet danger-text"
            onClick={() => setDialog({ kind: 'delete-key', key })}
          >
            {t('Löschen …')}
            <span className="sr-only">{key.name}</span>
          </button>
        </Row>
      ))}
      <Row label={t('Schlüssel erstellen')} description={t('Bis zu zehn, einer pro App.')}>
        <button
          className="primary"
          disabled={keys.length >= 10}
          onClick={() => setDialog({ kind: 'new-key' })}
        >
          {t('Erstellen …')}
        </button>
      </Row>

      {dialog?.kind === 'new-key' && (
        <PasswordPrompt
          title={t('Schlüssel erstellen')}
          lead={t(
            'Der Schlüssel legt nur maskierte Adressen an; anmelden kann er sich nicht. Du siehst ihn ein einziges Mal.',
          )}
          confirm={t('Erstellen')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            const { masterPasswordHash } = await secret(password);
            try {
              const key = await createMaskedApiKey(name.trim() || 'Bitwarden', masterPasswordHash);
              setDialog(null);
              setName('');
              setMade(key);
              reload();
            } catch (e) {
              // The prompt shows it; a wrong password comes back as the server's words.
              throw { kind: 'invalid', message: maskedErrorText(e) };
            }
          }}
        >
          <label className="field">
            <span>{t('Name')}</span>
            <input
              value={name}
              maxLength={50}
              placeholder={t('z. B. Firefox')}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
        </PasswordPrompt>
      )}
      {made?.key && (
        <Modal
          title={t('Schlüssel für {name}', { name: made.name })}
          onCancel={() => setMade(null)}
          footer={
            <>
              <span className="spacer" />
              <button className="primary" data-autofocus onClick={() => setMade(null)}>
                {t('Fertig')}
              </button>
            </>
          }
        >
          <div className="form">
            <p className="dialog-lead">
              {t(
                'Kopier ihn jetzt in die App: Er wird nur dieses eine Mal angezeigt. Verloren? Lösch ihn und mach einen neuen.',
              )}
            </p>
            <div className="field">
              <span>{t('API-Schlüssel')}</span>
              <div className="copy-field">
                <code className="mono">{made.key}</code>
                <button
                  className="icon-button"
                  aria-label={t('{label} kopieren', { label: t('API-Schlüssel') })}
                  onClick={() => void copy(made.key ?? '')}
                >
                  <Icon name="copy" size={15} />
                </button>
              </div>
            </div>
          </div>
        </Modal>
      )}
      {dialog?.kind === 'delete-key' && (
        <Modal
          title={t('Schlüssel löschen?')}
          tone="warning"
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  const target = dialog.key;
                  setDialog(null);
                  void deleteMaskedApiKey(target.id).then(
                    () => {
                      toast(t('Gelöscht.'));
                      reload();
                    },
                    (e) => toast(maskedErrorText(e), 'error'),
                  );
                }}
              >
                {t('Löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t('Die App mit „{name}“ legt danach keine Adressen mehr an.', {
              name: dialog.key.name,
            })}
          </p>
        </Modal>
      )}
    </>
  );
}
