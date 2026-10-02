import { useState } from 'react';
import { renderSVG } from 'uqr';
import { type Status } from '../../lib/api';
import {
  account,
  authenticatorKey,
  disableTwoFactor,
  enableAuthenticator,
  enableEmailCodes,
  recoveryCode,
  sendSetupCode,
  type AccountInfo,
} from '../../lib/account';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import { PasswordPrompt, Row } from './controls';
import {
  addSecurityKey,
  removeSecurityKey,
  securityKeys,
  type SecurityKey,
} from '../../lib/features';
import { available } from '../../lib/web/webauthn';

type Props = {
  status: Status;
  info: AccountInfo | null;
  onInfo: (info: AccountInfo | null) => void;
};

const AUTHENTICATOR = 0;
const EMAIL = 1;
const WEBAUTHN = 7;

type Dialog = 'authenticator' | 'email' | 'recovery' | 'keys' | { disable: number } | null;

/**
 * Two-step login: an authenticator app, codes by mail, and the recovery code for the day the
 * phone is gone. Setting one up shows the first code has to work before it is on.
 */
export function TwoFactorSettings({ status, info, onInfo }: Props) {
  useLanguage();
  const [dialog, setDialog] = useState<Dialog>(null);
  const on = (kind: number) => info?.twoFactor.includes(kind) ?? false;
  // While travelling, two-step login is what switches travel mode off: the server keeps it as it is.
  const travelling = info?.travel?.enabled ?? false;
  const refresh = async () => onInfo(await account());
  const done = async (message: string) => {
    setDialog(null);
    toast(message, 'info');
    await refresh();
  };

  return (
    <>
      <p className="settings-lead">
        {t(
          'Mit einem zweiten Schritt reicht dein Master-Passwort allein nicht mehr zum Anmelden. Die Browser-Erweiterung, die Apps und UwULock fragen dann zusätzlich nach einem Code.',
        )}
      </p>
      {travelling && (
        <p className="settings-lead" role="status">
          {t(
            'Der Reisemodus ist an. Bis du ihn ausschaltest, bleibt die Zwei-Schritt-Anmeldung, wie sie ist: nichts lässt sich einrichten, ausschalten oder anzeigen.',
          )}
        </p>
      )}
      <Row
        label={t('Authenticator-App')}
        description={
          on(AUTHENTICATOR)
            ? t('An.')
            : t('Ein Code aus einer App wie Aegis, 2FAS oder Google Authenticator.')
        }
      >
        {on(AUTHENTICATOR) ? (
          <button
            className="danger"
            onClick={() => setDialog({ disable: AUTHENTICATOR })}
            disabled={travelling}
          >
            {t('Ausschalten …')}
          </button>
        ) : (
          <button
            className="primary"
            onClick={() => setDialog('authenticator')}
            disabled={travelling}
          >
            {t('Einrichten …')}
          </button>
        )}
      </Row>
      <Row
        label={t('Codes per Mail')}
        description={
          on(EMAIL)
            ? t('An.')
            : info?.mail
              ? t('Bei jeder Anmeldung kommt ein Code per Mail.')
              : t('Geht erst, wenn der Server Mails verschicken kann.')
        }
      >
        {on(EMAIL) ? (
          <button
            className="danger"
            onClick={() => setDialog({ disable: EMAIL })}
            disabled={travelling}
          >
            {t('Ausschalten …')}
          </button>
        ) : (
          <button onClick={() => setDialog('email')} disabled={!info?.mail || travelling}>
            {t('Einrichten …')}
          </button>
        )}
      </Row>
      <Row
        label={t('Sicherheitsschlüssel')}
        description={
          on(WEBAUTHN)
            ? t('An.')
            : available()
              ? t('Ein FIDO2-Schlüssel wie ein YubiKey, oder ein Passkey auf deinem Gerät.')
              : t('Dieser Browser kann keine Sicherheitsschlüssel.')
        }
      >
        <button onClick={() => setDialog('keys')} disabled={!available() || travelling}>
          {on(WEBAUTHN) ? t('Verwalten …') : t('Einrichten …')}
        </button>
      </Row>
      <Row
        label={t('Wiederherstellungscode')}
        description={t(
          'Schaltet die Zwei-Schritt-Anmeldung aus, wenn du keinen Code mehr bekommst. Schreib ihn auf und heb ihn getrennt vom Rechner auf.',
        )}
      >
        <button
          onClick={() => setDialog('recovery')}
          disabled={!info?.twoFactor.length || travelling}
        >
          {t('Anzeigen …')}
        </button>
      </Row>

      {dialog === 'authenticator' && (
        <SetUpAuthenticator
          email={status.email ?? ''}
          onCancel={() => setDialog(null)}
          onDone={() => void done(t('Die Authenticator-App ist eingerichtet ✧'))}
        />
      )}
      {dialog === 'email' && (
        <SetUpEmail
          email={status.email ?? ''}
          onCancel={() => setDialog(null)}
          onDone={() => void done(t('Codes per Mail sind eingerichtet ✧'))}
        />
      )}
      {dialog === 'recovery' && <Recovery onClose={() => setDialog(null)} />}
      {dialog === 'keys' && (
        <SecurityKeys
          onClose={() => {
            setDialog(null);
            void refresh();
          }}
        />
      )}
      {dialog && typeof dialog === 'object' && (
        <PasswordPrompt
          title={t('Ausschalten?')}
          tone="warning"
          lead={t('Danach genügt dafür wieder das Master-Passwort allein.')}
          confirm={t('Ausschalten')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await disableTwoFactor(password, dialog.disable);
            await done(t('Ausgeschaltet.'));
          }}
        />
      )}
    </>
  );
}

function SetUpAuthenticator({
  email,
  onCancel,
  onDone,
}: {
  email: string;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [key, setKey] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const uri = key
    ? `otpauth://totp/${encodeURIComponent(`UwULock:${email}`)}?secret=${key}&issuer=UwULock&algorithm=SHA1&digits=6&period=30`
    : '';
  return (
    <Modal
      title={t('Authenticator-App einrichten')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          {key ? (
            <button
              className="primary"
              disabled={busy || code.trim().length < 6}
              onClick={() =>
                void run(async () => {
                  await enableAuthenticator(password, key, code);
                  onDone();
                })
              }
            >
              {t('Einschalten')}
            </button>
          ) : (
            <button
              className="primary"
              disabled={busy || !password}
              onClick={() => void run(async () => setKey((await authenticatorKey(password)).key))}
            >
              {t('Weiter')}
            </button>
          )}
        </>
      }
    >
      <div className="form">
        {!key ? (
          <label className="field">
            <span>{t('Master-Passwort')}</span>
            <PasswordInput
              label={t('Master-Passwort')}
              value={password}
              onChange={setPassword}
              autoFocus
              disabled={busy}
            />
          </label>
        ) : (
          <>
            <p className="dialog-lead">
              {t(
                'Scanne den Code mit deiner Authenticator-App, oder gib den Schlüssel dort von Hand ein.',
              )}
            </p>
            <div
              className="qr"
              dangerouslySetInnerHTML={{
                __html: renderSVG(uri, {
                  border: 2,
                  whiteColor: '#ffffff',
                  blackColor: '#1c1420',
                }),
              }}
            />
            <code className="secret-key">{key.match(/.{1,4}/g)?.join(' ')}</code>
            <label className="field">
              <span>{t('Code aus der App')}</span>
              <input
                className="code-input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
              />
            </label>
          </>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

function SetUpEmail({
  email: own,
  onCancel,
  onDone,
}: {
  email: string;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState(own);
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Codes per Mail einrichten')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          {sent ? (
            <button
              className="primary"
              disabled={busy || !code.trim()}
              onClick={() =>
                void run(async () => {
                  await enableEmailCodes(password, email, code);
                  onDone();
                })
              }
            >
              {t('Einschalten')}
            </button>
          ) : (
            <button
              className="primary"
              disabled={busy || !password || !email.includes('@')}
              onClick={() =>
                void run(async () => {
                  await sendSetupCode(password, email);
                  setSent(true);
                })
              }
            >
              {t('Code senden')}
            </button>
          )}
        </>
      }
    >
      <div className="form">
        <label className="field">
          <span>{t('Codes gehen an')}</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={busy || sent}
          />
        </label>
        <label className="field">
          <span>{t('Master-Passwort')}</span>
          <PasswordInput
            label={t('Master-Passwort')}
            value={password}
            onChange={setPassword}
            autoFocus
            disabled={busy || sent}
          />
        </label>
        {sent && (
          <label className="field">
            <span>{t('Code aus der Mail')}</span>
            <input
              className="code-input"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
            />
          </label>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

function Recovery({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [code, setCode] = useState<string | null>(null);
  if (code === null) {
    return (
      <PasswordPrompt
        title={t('Wiederherstellungscode')}
        lead={t(
          'Mit diesem Code kommst du auch ohne zweiten Schritt in dein Konto. Bewahre ihn sicher auf.',
        )}
        confirm={t('Anzeigen')}
        onCancel={onClose}
        action={async (password) => setCode((await recoveryCode(password)).code ?? '')}
      />
    );
  }
  return (
    <Modal
      title={t('Wiederherstellungscode')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="primary" data-autofocus onClick={onClose}>
            {t('Fertig')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t('Schreib ihn ab. Einmal benutzt, schaltet er jeden zweiten Schritt aus.')}
      </p>
      <code className="secret-key big">{code.match(/.{1,4}/g)?.join(' ')}</code>
    </Modal>
  );
}

/**
 * Security keys for the second step: up to five, each in a slot of its own. The master password
 * is asked once and kept while the dialog is open.
 */
function SecurityKeys({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [password, setPassword] = useState<string | null>(null);
  const [keys, setKeys] = useState<SecurityKey[]>([]);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (password === null) {
    return (
      <PasswordPrompt
        title={t('Sicherheitsschlüssel')}
        lead={t('Zuerst dein Master-Passwort.')}
        confirm={t('Weiter')}
        onCancel={onClose}
        action={async (given) => {
          setKeys(await securityKeys(given));
          setPassword(given);
        }}
      />
    );
  }

  const free = [1, 2, 3, 4, 5].find((slot) => !keys.some((key) => key.id === slot));
  const run = async (work: () => Promise<void>, done: string) => {
    setBusy(true);
    setError(null);
    try {
      await work();
      setKeys(await securityKeys(password));
      toast(done);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('Sicherheitsschlüssel')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="primary" onClick={onClose}>
            {t('Fertig')}
          </button>
        </>
      }
    >
      <div className="form">
        {keys.map((key) => (
          <Row key={key.id} label={key.name || t('Schlüssel {n}', { n: key.id })}>
            <button
              className="quiet danger-text"
              disabled={busy}
              onClick={() => void run(() => removeSecurityKey(key.id, password), t('Entfernt.'))}
            >
              {t('Entfernen')}
            </button>
          </Row>
        ))}
        {free !== undefined && (
          <>
            <label className="field">
              <span>{t('Name des neuen Schlüssels')}</span>
              <input value={name} maxLength={50} onChange={(e) => setName(e.target.value)} />
            </label>
            <div className="form-actions">
              <span className="spacer" />
              <button
                className="primary"
                disabled={busy || !name.trim()}
                onClick={() =>
                  void run(async () => {
                    await addSecurityKey(name.trim(), password, free);
                    setName('');
                  }, t('Sicherheitsschlüssel eingerichtet ✧'))
                }
              >
                {busy ? t('Berühre den Schlüssel …') : t('Schlüssel hinzufügen')}
              </button>
            </div>
          </>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
