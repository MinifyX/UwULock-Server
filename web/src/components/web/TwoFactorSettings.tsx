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

type Props = {
  status: Status;
  info: AccountInfo | null;
  onInfo: (info: AccountInfo | null) => void;
};

const AUTHENTICATOR = 0;
const EMAIL = 1;

type Dialog = 'authenticator' | 'email' | 'recovery' | { disable: number } | null;

/**
 * Two-step login: an authenticator app, codes by mail, and the recovery code for the day the
 * phone is gone. Setting one up shows the first code has to work before it is on.
 */
export function TwoFactorSettings({ status, info, onInfo }: Props) {
  useLanguage();
  const [dialog, setDialog] = useState<Dialog>(null);
  const on = (kind: number) => info?.twoFactor.includes(kind) ?? false;
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
      <Row
        label={t('Authenticator-App')}
        description={
          on(AUTHENTICATOR)
            ? t('An.')
            : t('Ein Code aus einer App wie Aegis, 2FAS oder Google Authenticator.')
        }
      >
        {on(AUTHENTICATOR) ? (
          <button className="danger" onClick={() => setDialog({ disable: AUTHENTICATOR })}>
            {t('Ausschalten …')}
          </button>
        ) : (
          <button className="primary" onClick={() => setDialog('authenticator')}>
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
          <button className="danger" onClick={() => setDialog({ disable: EMAIL })}>
            {t('Ausschalten …')}
          </button>
        ) : (
          <button onClick={() => setDialog('email')} disabled={!info?.mail}>
            {t('Einrichten …')}
          </button>
        )}
      </Row>
      <Row
        label={t('Wiederherstellungscode')}
        description={t(
          'Schaltet die Zwei-Schritt-Anmeldung aus, wenn du keinen Code mehr bekommst. Schreib ihn auf und heb ihn getrennt vom Rechner auf.',
        )}
      >
        <button onClick={() => setDialog('recovery')} disabled={!info?.twoFactor.length}>
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
            <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
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
