import { useCallback, useEffect, useState } from 'react';
import { errorText } from '../../lib/errors';
import {
  EMERGENCY_STATUS,
  acceptContact,
  answerRecovery,
  askForAccess,
  confirmContact,
  contactKey,
  emergencyVault,
  grantedAccess,
  inviteContact,
  reinviteContact,
  removeContact,
  takeOver,
  trustedContacts,
  type Contact,
} from '../../lib/features';
import { N_, t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import { Row, save } from './controls';

const STATUS: Record<number, string> = {
  0: N_('Eingeladen'),
  1: N_('Angenommen – bestätigen'),
  2: N_('Bestätigt'),
  3: N_('Fragt Zugriff an'),
  4: N_('Zugriff freigegeben'),
};

type Dialog =
  | { kind: 'invite' }
  | { kind: 'confirm'; contact: Contact; publicKey: string; phrase: string }
  | { kind: 'view'; contact: Contact; vault: string }
  | { kind: 'takeover'; contact: Contact }
  | null;

/**
 * Emergency access: people who may see (or take over) the vault if they ask and nobody says no
 * within the waiting time — and, the other way round, the vaults others entrusted to you.
 */
export function EmergencySettings({ mail }: { mail: boolean }) {
  useLanguage();
  const [trusted, setTrusted] = useState<Contact[]>([]);
  const [granted, setGranted] = useState<Contact[]>([]);
  const [dialog, setDialog] = useState<Dialog>(null);

  const reload = useCallback(async () => {
    try {
      const [mine, theirs] = await Promise.all([trustedContacts(), grantedAccess()]);
      setTrusted(mine);
      setGranted(theirs);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }, []);

  useEffect(() => void reload(), [reload]);

  const act = async (work: () => Promise<unknown>, done: string) => {
    try {
      await work();
      toast(done);
      await reload();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const who = (contact: Contact) => contact.name || contact.email || '?';
  const kind = (contact: Contact) => (contact.type === 1 ? t('Übernehmen') : t('Ansehen'));

  return (
    <>
      <p className="settings-lead">
        {t(
          'Vertrauenspersonen können im Notfall auf deinen Tresor zugreifen: Sie fragen an, und wenn du nicht innerhalb der Wartezeit ablehnst, bekommen sie Zugriff. Sie brauchen ein Konto auf diesem Server.',
        )}
      </p>

      <h3 className="settings-heading">{t('Meine Vertrauenspersonen')}</h3>
      {trusted.map((contact) => (
        <Row
          key={contact.id}
          label={who(contact)}
          description={`${t(STATUS[contact.status] ?? '')} · ${kind(contact)} · ${t('{n} Tage Wartezeit', { n: contact.waitTimeDays })}`}
        >
          {contact.status === EMERGENCY_STATUS.accepted && (
            <button
              className="primary"
              onClick={() =>
                void contactKey(contact).then(
                  (key) => setDialog({ kind: 'confirm', contact, ...key }),
                  (e) => toast(errorText(e), 'error'),
                )
              }
            >
              {t('Bestätigen …')}
            </button>
          )}
          {contact.status === EMERGENCY_STATUS.invited && mail && (
            <button
              onClick={() =>
                void act(() => reinviteContact(contact.id), t('Einladung neu verschickt.'))
              }
            >
              {t('Nochmal einladen')}
            </button>
          )}
          {contact.status === EMERGENCY_STATUS.asked && (
            <button
              className="primary"
              onClick={() => void act(() => answerRecovery(contact.id, true), t('Freigegeben.'))}
            >
              {t('Freigeben')}
            </button>
          )}
          {(contact.status === EMERGENCY_STATUS.asked ||
            contact.status === EMERGENCY_STATUS.approved) && (
            <button
              className="danger"
              onClick={() => void act(() => answerRecovery(contact.id, false), t('Abgelehnt.'))}
            >
              {t('Ablehnen')}
            </button>
          )}
          <button
            className="quiet danger-text"
            onClick={() => void act(() => removeContact(contact.id), t('Entfernt.'))}
          >
            {t('Entfernen')}
          </button>
        </Row>
      ))}
      <Row label={t('Vertrauensperson hinzufügen')}>
        <button onClick={() => setDialog({ kind: 'invite' })}>{t('Einladen …')}</button>
      </Row>

      {granted.length > 0 && (
        <>
          <h3 className="settings-heading">{t('Mir anvertraut')}</h3>
          {granted.map((contact) => (
            <Row
              key={contact.id}
              label={who(contact)}
              description={`${t(STATUS[contact.status] ?? '')} · ${kind(contact)} · ${t('{n} Tage Wartezeit', { n: contact.waitTimeDays })}`}
            >
              {contact.status === EMERGENCY_STATUS.invited && (
                <button
                  className="primary"
                  onClick={() => void act(() => acceptContact(contact.id, ''), t('Angenommen ✧'))}
                >
                  {t('Annehmen')}
                </button>
              )}
              {contact.status === EMERGENCY_STATUS.confirmed && (
                <button
                  onClick={() =>
                    void act(
                      () => askForAccess(contact.id),
                      t('Angefragt. Du bekommst eine Mail, sobald der Zugriff frei ist.'),
                    )
                  }
                >
                  {t('Zugriff anfragen')}
                </button>
              )}
              {contact.status === EMERGENCY_STATUS.approved && contact.type === 0 && (
                <button
                  className="primary"
                  onClick={() =>
                    void emergencyVault(contact.id).then(
                      (vault) => setDialog({ kind: 'view', contact, vault }),
                      (e) => toast(errorText(e), 'error'),
                    )
                  }
                >
                  {t('Tresor ansehen')}
                </button>
              )}
              {contact.status === EMERGENCY_STATUS.approved && contact.type === 1 && (
                <button className="danger" onClick={() => setDialog({ kind: 'takeover', contact })}>
                  {t('Übernehmen …')}
                </button>
              )}
              <button
                className="quiet danger-text"
                onClick={() => void act(() => removeContact(contact.id), t('Entfernt.'))}
              >
                {t('Entfernen')}
              </button>
            </Row>
          ))}
        </>
      )}

      {dialog?.kind === 'invite' && (
        <Invite
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            void reload();
          }}
        />
      )}
      {dialog?.kind === 'confirm' && (
        <Modal
          title={t('Vertrauensperson bestätigen')}
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="primary"
                onClick={() => {
                  const { contact, publicKey } = dialog;
                  setDialog(null);
                  void act(() => confirmContact(contact, publicKey), t('Bestätigt ✧'));
                }}
              >
                {t('Bestätigen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Vergleiche diesen Satz mit {who}. Er steht in deren Einstellungen unter Konto → Fingerabdruck. Nur wenn er gleich ist, bestätige.',
              { who: who(dialog.contact) },
            )}
          </p>
          <p className="fingerprint">{dialog.phrase}</p>
        </Modal>
      )}
      {dialog?.kind === 'view' && (
        <EmergencyVault
          contact={dialog.contact}
          vault={dialog.vault}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === 'takeover' && (
        <Takeover
          contact={dialog.contact}
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            toast(t('Neues Master-Passwort gesetzt.'));
          }}
        />
      )}
    </>
  );
}

function Invite({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  useLanguage();
  const [email, setEmail] = useState('');
  const [type, setType] = useState<0 | 1>(0);
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await inviteContact(email.trim(), type, days);
      toast(t('Eingeladen ✧'));
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Vertrauensperson einladen')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            className="primary"
            disabled={busy || !email.includes('@')}
            onClick={() => void submit()}
          >
            {t('Einladen')}
          </button>
        </>
      }
    >
      <div className="form">
        <label className="field">
          <span>{t('E-Mail-Adresse ihres Kontos')}</span>
          <input type="email" value={email} autoFocus onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="field">
          <span>{t('Darf im Notfall')}</span>
          <select
            className="select"
            value={type}
            onChange={(e) => setType(Number(e.target.value) as 0 | 1)}
          >
            <option value={0}>{t('den Tresor ansehen')}</option>
            <option value={1}>{t('das Konto übernehmen (neues Master-Passwort setzen)')}</option>
          </select>
        </label>
        <label className="field">
          <span>{t('Wartezeit')}</span>
          <select className="select" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[1, 2, 3, 7, 14, 30, 90].map((n) => (
              <option key={n} value={n}>
                {n === 1 ? t('1 Tag') : t('{n} Tage', { n })}
              </option>
            ))}
          </select>
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

type ExportedItem = {
  id: string;
  name: string;
  notes: string | null;
  login?: {
    username: string | null;
    password: string | null;
    uris?: { uri: string }[];
    totp: string | null;
  };
};

function EmergencyVault({
  contact,
  vault,
  onClose,
}: {
  contact: Contact;
  vault: string;
  onClose: () => void;
}) {
  useLanguage();
  const items = (JSON.parse(vault) as { items: ExportedItem[] }).items ?? [];
  return (
    <Modal
      title={t('Tresor von {who}', { who: contact.name || contact.email || '?' })}
      size="wide"
      onCancel={onClose}
      footer={
        <>
          <button
            onClick={() =>
              save(
                new Blob([vault], { type: 'application/json' }),
                `uwulock-${contact.email ?? 'vault'}.json`,
              )
            }
          >
            {t('Als Bitwarden-JSON speichern')}
          </button>
          <span className="spacer" />
          <button className="primary" onClick={onClose}>
            {t('Schließen')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">{t('Nur ansehen: Ändern kannst du hier nichts.')}</p>
      <ul className="emergency-items">
        {items.map((item) => (
          <li key={item.id}>
            <strong>{item.name}</strong>
            {item.login?.username && <span>{item.login.username}</span>}
            {item.login?.password && <code className="mono">{item.login.password}</code>}
            {item.login?.uris?.[0]?.uri && <span className="muted">{item.login.uris[0].uri}</span>}
            {item.notes && <span className="multiline">{item.notes}</span>}
          </li>
        ))}
      </ul>
    </Modal>
  );
}

function Takeover({
  contact,
  onClose,
  onDone,
}: {
  contact: Contact;
  onClose: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = password.length >= 12 && password === again;
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await takeOver(contact, password);
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Konto von {who} übernehmen', { who: contact.name || contact.email || '?' })}
      tone="warning"
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="danger" disabled={busy || !ok} onClick={() => void submit()}>
            {t('Master-Passwort setzen')}
          </button>
        </>
      }
    >
      <div className="form">
        <p className="dialog-lead">
          {t(
            'Du setzt ein neues Master-Passwort für dieses Konto. Alle Geräte werden abgemeldet, die Zwei-Schritt-Anmeldung ausgeschaltet. Melde dich danach mit der Adresse des Kontos und dem neuen Passwort an.',
          )}
        </p>
        <label className="field">
          <span>{t('Neues Master-Passwort (mindestens 12 Zeichen)')}</span>
          <PasswordInput
            value={password}
            onChange={setPassword}
            autoComplete="new-password"
            autoFocus
          />
        </label>
        <label className="field">
          <span>{t('Noch einmal')}</span>
          <PasswordInput value={again} onChange={setAgain} autoComplete="new-password" />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
