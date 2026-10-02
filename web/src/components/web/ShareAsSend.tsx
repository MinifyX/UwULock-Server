import { useEffect, useState } from 'react';
import { useFeature } from '../../lib/branding';
import { errorText } from '../../lib/errors';
import {
  sendLink,
  setSendDomain,
  shareableFields,
  shareItem,
  type ShareableField,
} from '../../lib/features';
import { t, useLanguage } from '../../lib/i18n';
import { IDENTITY_LABEL } from '../../lib/items';
import { domainOf } from '../../lib/links';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { SendDomainField, useDefaultSendDomain, useSendDomains } from './SendDomainSelect';
import { SendAccess, splitAddresses } from './SendsView';

/** What each value is called in the Send's text, in the sender's language. */
function labelOf(field: ShareableField): string {
  const { name } = field;
  if (name.startsWith('field:')) return field.label || t('Feld');
  if (name.startsWith('uri:')) return t('Website');
  if (name === 'totp') return t('Einmal-Code (TOTP)');
  if (name.startsWith('identity:')) {
    const key = name.slice('identity:'.length);
    return IDENTITY_LABEL[key] ? t(IDENTITY_LABEL[key]) : key;
  }
  const labels: Record<string, string> = {
    username: t('Benutzername'),
    password: t('Passwort'),
    notes: t('Notizen'),
    'card-name': t('Karteninhaber'),
    'card-number': t('Kartennummer'),
    'card-expiry': t('Gültig bis'),
    'card-code': t('Prüfnummer'),
    'ssh-public': t('Öffentlicher Schlüssel'),
    'ssh-private': t('Privater Schlüssel'),
    'ssh-fingerprint': t('Fingerabdruck'),
  };
  return labels[name] ?? name;
}

/** What the choice shows: a website with its address, so several can be told apart. */
function choiceOf(field: ShareableField): string {
  if (field.uri) return `${t('Website')} · ${field.uri}`;
  if (field.name === 'totp') return t('Einmal-Codes (nur die Codes, nie der Schlüssel)');
  return labelOf(field);
}

/**
 * What is ticked at first: a login's name, password and website; anything else all of it. Never
 * the one-time codes: those are a choice of their own.
 */
export function ticked(fields: ShareableField[]): Set<string> {
  const login = fields.filter(
    ({ name }) => name === 'username' || name === 'password' || name === 'uri:0',
  );
  const all = fields.filter(({ entryOnly }) => !entryOnly);
  return new Set((login.length ? login : all).map(({ name }) => name));
}

const DAYS = [1, 2, 3, 7, 14, 30];

/**
 * "Share as Send": the chosen values of an item as a new entry Send — an ordinary text Send, so
 * the official apps show it too, whose last line lets UwULock's Send page show it as an entry
 * with copy buttons. The one-time codes only when chosen, and then only as live codes on that
 * page: the readable text never holds the authenticator key. It opens once and goes after a
 * day, unless changed here.
 */
export function ShareAsSend({
  itemId,
  itemName,
  onClose,
}: {
  itemId: string;
  itemName: string;
  onClose: () => void;
}) {
  useLanguage();
  const [fields, setFields] = useState<ShareableField[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [name, setName] = useState(itemName);
  const [days, setDays] = useState(1);
  const [maxAccess, setMaxAccess] = useState('1');
  const [access, setAccess] = useState<0 | 1 | 2>(2);
  const [password, setPassword] = useState('');
  const [emails, setEmails] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<string | null>(null);
  const mailOk = useFeature('send-emails');
  const domains = useSendDomains();
  const fallback = useDefaultSendDomain(domains.length > 0);
  const [domain, setDomain] = useState<string | null | undefined>(undefined);
  const chosenDomain = domain === undefined ? fallback.value : domain;

  useEffect(() => {
    shareableFields(itemId).then(
      (found) => {
        setFields(found);
        setChosen(ticked(found));
      },
      (e) => setError(errorText(e)),
    );
  }, [itemId]);

  const addresses = splitAddresses(emails);
  const ready =
    fallback.ready &&
    chosen.size > 0 &&
    name.trim() &&
    (access !== 1 || password) &&
    (access !== 0 || addresses.length > 0);

  const submit = async () => {
    if (!ready || busy || !fields) return;
    setBusy(true);
    setError(null);
    const until = new Date(Date.now() + days * 86_400_000).toISOString();
    try {
      const made = await shareItem({
        itemId,
        fields: fields
          .filter((field) => chosen.has(field.name))
          .map((field) => ({ name: field.name, label: labelOf(field) })),
        name: name.trim(),
        hidden: false,
        maxAccessCount: maxAccess ? Math.max(1, Number(maxAccess)) : null,
        deletionDate: until,
        expirationDate: until,
        password: access === 1 ? password : null,
        emails: access === 0 ? addresses : [],
        hideEmail: false,
        entry: true,
      });
      // New Sends start on the account's default domain; another one is set afterwards.
      if (domains.length > 0 && chosenDomain !== fallback.value)
        await setSendDomain(made.id, chosenDomain).catch((e) => toast(errorText(e), 'error'));
      setLink(sendLink(made, domainOf(domains, chosenDomain)));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!link) return;
    await navigator.clipboard.writeText(link);
    toast(t('Link kopiert ✧'));
  };

  if (link) {
    return (
      <Modal
        title={t('Send angelegt ✧')}
        onCancel={onClose}
        footer={
          <>
            <span className="spacer" />
            <button onClick={onClose}>{t('Fertig')}</button>
            <button className="primary" data-autofocus onClick={() => void copy()}>
              <Icon name="copy" size={15} />
              {t('Link kopieren')}
            </button>
          </>
        }
      >
        <p className="dialog-lead">
          {t(
            'Schick den Link auf einem anderen Weg als das Passwort, falls es eins hat. Der Send steht auch unter Sends.',
          )}
        </p>
        <label className="field">
          <span>{t('Link')}</span>
          <input readOnly value={link} onFocus={(e) => e.target.select()} />
        </label>
      </Modal>
    );
  }

  return (
    <Modal
      title={t('Als Send teilen')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="primary" disabled={!ready || busy} onClick={() => void submit()}>
            {busy ? t('Einen Moment …') : t('Send anlegen')}
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
            'Die gewählten Felder kommen in einen neuen Send. Auf der Send-Seite von UwULock erscheinen sie als Eintrag mit Kopier-Knöpfen, in den Bitwarden-Apps als Text.',
          )}
        </p>
        <fieldset className="field send-access">
          <legend>{t('Was soll hinein?')}</legend>
          {fields === null ? (
            <p className="field-hint">{t('Lädt …')}</p>
          ) : fields.length === 0 ? (
            <p className="field-hint">{t('Dieser Eintrag hat nichts, was sich teilen lässt.')}</p>
          ) : (
            <div className="share-fields">
              {fields.map((field) => (
                <label key={field.name} className="check">
                  <input
                    type="checkbox"
                    checked={chosen.has(field.name)}
                    onChange={(e) => {
                      const next = new Set(chosen);
                      if (e.target.checked) next.add(field.name);
                      else next.delete(field.name);
                      setChosen(next);
                    }}
                  />
                  <span className={field.uri ? 'share-choice uri' : 'share-choice'}>
                    {choiceOf(field)}
                  </span>
                </label>
              ))}
            </div>
          )}
          {chosen.has('totp') && (
            <p className="field-hint" data-totp-hint>
              {t(
                'Die Send-Seite zeigt nur die aktuellen Codes. Der Schlüssel dafür steckt aber verschlüsselt im Send: Teile ihn nur mit jemandem, dem du die Zwei-Schritt-Anmeldung auch so anvertrauen würdest.',
              )}
            </p>
          )}
        </fieldset>
        <label className="field">
          <span>{t('Name des Sends')}</span>
          <input value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="field-pair">
          <label className="field">
            <span>{t('Gilt für')}</span>
            <select
              className="select"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              {DAYS.map((n) => (
                <option key={n} value={n}>
                  {n === 1 ? t('1 Tag') : t('{n} Tage', { n })}
                </option>
              ))}
            </select>
          </label>
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
        </div>
        {domains.length > 0 && (
          <SendDomainField
            label={t('Adresse des Links')}
            value={chosenDomain}
            onChange={setDomain}
            domains={domains}
            disabled={!fallback.ready}
          />
        )}
        <SendAccess
          value={access}
          onChange={setAccess}
          mailOk={mailOk}
          hasPassword={false}
          password={password}
          onPassword={setPassword}
          emails={emails}
          onEmails={setEmails}
        />
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}
