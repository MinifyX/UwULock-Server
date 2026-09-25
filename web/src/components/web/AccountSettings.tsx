import { useEffect, useState } from 'react';
import { logout, syncNow, type Status } from '../../lib/api';
import {
  changeEmail,
  changeKdf,
  changePassword,
  DEFAULT_KDFS,
  deleteAccount,
  kdfOf,
  logOutEverywhere,
  prelogin,
  requestEmailChange,
  rotateKeys,
  saveName,
  setLanguage,
  type AccountInfo,
  type Kdf,
} from '../../lib/account';
import { errorText } from '../../lib/errors';
import { ago } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import { PasswordPrompt, ResultLine, Row, Segmented, type Result } from './controls';

type Props = {
  status: Status;
  info: AccountInfo | null;
  onInfo: (info: AccountInfo | null) => void;
  onClose: () => void;
};

type Dialog = 'password' | 'kdf' | 'email' | 'rotate' | 'everywhere' | 'delete' | null;

function kdfLabel(kdf: Kdf): string {
  return kdf.kind === 'pbkdf2'
    ? t('PBKDF2, {n} Runden', { n: kdf.iterations.toLocaleString() })
    : t('Argon2id, {memory} MiB, {iterations} Durchläufe, {parallelism} Threads', {
        memory: kdf.memory,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
      });
}

/**
 * The account: its name, the language of its mails, and everything that changes how it is
 * unlocked. Each of those ends every session, this one too, and asks for the master password.
 */
export function AccountSettings({ status, info, onInfo, onClose }: Props) {
  useLanguage();
  const [name, setName] = useState(status.name ?? '');
  const [kdf, setKdf] = useState<Kdf | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);

  useEffect(() => {
    if (status.email) void prelogin(status.email).then((text) => setKdf(kdfOf(text)));
  }, [status.email]);

  const ended = (message: string) => {
    onClose();
    toast(message, 'info');
  };

  return (
    <>
      <Row label={t('Angemeldet als')} description={status.server ?? undefined}>
        <span className="setting-value">{status.email}</span>
      </Row>
      <Row label={t('Name')} description={t('So nennen dich die Bitwarden-Apps und Mails.')}>
        <span className="inline-form">
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={50} />
          <button
            disabled={busy || name.trim() === (status.name ?? '')}
            onClick={async () => {
              setBusy(true);
              try {
                await saveName(name);
                await syncNow();
                setResult({ tone: 'info', text: t('Gespeichert ✧') });
              } catch (e) {
                setResult({ tone: 'error', text: errorText(e) });
              } finally {
                setBusy(false);
              }
            }}
          >
            {t('Speichern')}
          </button>
        </span>
      </Row>
      {info && (
        <Row
          label={t('Sprache der Mails')}
          description={t('Codes, Hinweise und Einladungen kommen in dieser Sprache.')}
        >
          <Segmented
            label={t('Sprache der Mails')}
            value={info.language}
            onChange={async (language) => {
              try {
                await setLanguage(language);
                onInfo({ ...info, language });
              } catch (e) {
                setResult({ tone: 'error', text: errorText(e) });
              }
            }}
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </Row>
      )}
      <Row
        label={t('Synchronisieren')}
        description={t('Zuletzt {when}.', { when: ago(status.lastSync) })}
      >
        <button
          disabled={busy || status.syncing}
          onClick={async () => {
            setBusy(true);
            setResult(null);
            try {
              await syncNow();
              setResult({ tone: 'info', text: t('Synchronisiert ✧') });
            } catch (e) {
              setResult({ tone: 'error', text: errorText(e) });
            } finally {
              setBusy(false);
            }
          }}
        >
          {t('Jetzt synchronisieren')}
        </button>
      </Row>
      <ResultLine result={result} />

      <h3 className="settings-heading">{t('Anmeldung')}</h3>
      <Row
        label={t('Master-Passwort ändern')}
        description={t('Danach meldest du dich überall neu an – mit dem neuen Passwort.')}
      >
        <button onClick={() => setDialog('password')}>{t('Ändern …')}</button>
      </Row>
      <Row label={t('Schlüsselableitung')} description={kdf ? kdfLabel(kdf) : t('Wird geladen …')}>
        <button onClick={() => setDialog('kdf')} disabled={!kdf}>
          {t('Ändern …')}
        </button>
      </Row>
      <Row
        label={t('E-Mail-Adresse ändern')}
        description={
          info?.mail
            ? t('Die neue Adresse bekommt einen Code, der den Umzug bestätigt.')
            : t('Geht erst, wenn der Server Mails verschicken kann.')
        }
      >
        <button onClick={() => setDialog('email')} disabled={!info?.mail}>
          {t('Ändern …')}
        </button>
      </Row>
      <Row
        label={t('Neue Schlüssel')}
        description={t(
          'Verschlüsselt jeden Eintrag neu, mit einem neuen Schlüssel. Sinnvoll, wenn du fürchtest, jemand hatte deinen entsperrten Tresor.',
        )}
      >
        <button onClick={() => setDialog('rotate')}>{t('Neu verschlüsseln …')}</button>
      </Row>

      <h3 className="settings-heading">{t('Sitzungen')}</h3>
      <Row
        label={t('Überall abmelden')}
        description={t('Jedes Gerät und jeder Browser muss sich neu anmelden, dieser auch.')}
      >
        <button onClick={() => setDialog('everywhere')}>{t('Überall abmelden …')}</button>
      </Row>
      <Row label={t('Abmelden')} description={t('Nur dieser Browser.')}>
        <button
          onClick={async () => {
            onClose();
            await logout();
          }}
        >
          {t('Abmelden')}
        </button>
      </Row>

      <h3 className="settings-heading danger-text">{t('Gefahrenzone')}</h3>
      <Row
        label={t('Konto löschen')}
        description={t(
          'Das Konto und der ganze Tresor sind danach weg, auch auf dem Server. Das lässt sich nicht rückgängig machen.',
        )}
      >
        <button className="danger" onClick={() => setDialog('delete')}>
          {t('Konto löschen …')}
        </button>
      </Row>

      {dialog === 'password' && (
        <NewPassword
          hasHint={info?.hasHint ?? false}
          onCancel={() => setDialog(null)}
          onDone={() => ended(t('Master-Passwort geändert. Melde dich mit dem neuen an.'))}
        />
      )}
      {dialog === 'kdf' && kdf && (
        <NewKdf
          current={kdf}
          onCancel={() => setDialog(null)}
          onDone={() => ended(t('Schlüsselableitung geändert. Melde dich neu an.'))}
        />
      )}
      {dialog === 'email' && (
        <NewEmail
          onCancel={() => setDialog(null)}
          onDone={() => ended(t('Adresse geändert. Melde dich mit der neuen an.'))}
        />
      )}
      {dialog === 'rotate' && (
        <PasswordPrompt
          title={t('Tresor neu verschlüsseln?')}
          tone="warning"
          lead={
            <>
              <p>
                {t(
                  'Jeder Eintrag und jeder Ordner bekommt einen neuen Schlüssel. Alle Geräte müssen sich danach neu anmelden.',
                )}
              </p>
              <p>
                {t(
                  'Wichtig: Lass dabei kein anderes Gerät Einträge speichern. Was während der Umstellung woanders gespeichert wird, geht verloren.',
                )}
              </p>
            </>
          }
          confirm={t('Neu verschlüsseln')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await rotateKeys(password);
            ended(t('Dein Tresor hat neue Schlüssel. Melde dich neu an.'));
          }}
        />
      )}
      {dialog === 'everywhere' && (
        <PasswordPrompt
          title={t('Überall abmelden?')}
          lead={t('Jedes Gerät muss sich neu anmelden, auch dieser Browser.')}
          confirm={t('Überall abmelden')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await logOutEverywhere(password);
            ended(t('Überall abgemeldet.'));
          }}
        />
      )}
      {dialog === 'delete' && (
        <PasswordPrompt
          title={t('Konto wirklich löschen?')}
          tone="warning"
          lead={t(
            'Dein Konto und jeder Eintrag darin werden gelöscht. Exportiere vorher, was du behalten willst. Das lässt sich nicht rückgängig machen.',
          )}
          confirm={t('Endgültig löschen')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await deleteAccount(password);
            ended(t('Dein Konto ist gelöscht. Mach’s gut ✧'));
          }}
        />
      )}
    </>
  );
}

function NewPassword({
  hasHint,
  onCancel,
  onDone,
}: {
  hasHint: boolean;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [hint, setHint] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = current && next.length >= 12 && next === repeat && !(hint && next.includes(hint));
  return (
    <Modal
      title={t('Master-Passwort ändern')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          <button
            className="primary"
            disabled={busy || !ready}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await changePassword(current, next, hint);
                onDone();
              } catch (e) {
                setError(errorText(e));
                setBusy(false);
              }
            }}
          >
            {busy ? t('Einen Moment …') : t('Ändern')}
          </button>
        </>
      }
    >
      <div className="form">
        <label className="field">
          <span>{t('Aktuelles Master-Passwort')}</span>
          <PasswordInput value={current} onChange={setCurrent} autoFocus disabled={busy} />
        </label>
        <label className="field">
          <span>{t('Neues Master-Passwort')}</span>
          <PasswordInput
            value={next}
            onChange={setNext}
            autoComplete="new-password"
            disabled={busy}
          />
          {next && next.length < 12 && (
            <small className="field-hint">{t('Mindestens 12 Zeichen.')}</small>
          )}
        </label>
        <label className="field">
          <span>{t('Neues Master-Passwort wiederholen')}</span>
          <PasswordInput
            value={repeat}
            onChange={setRepeat}
            autoComplete="new-password"
            disabled={busy}
          />
          {repeat && repeat !== next && (
            <small className="field-hint">{t('Die beiden stimmen nicht überein.')}</small>
          )}
        </label>
        <label className="field">
          <span>{t('Neuer Hinweis (freiwillig)')}</span>
          <input
            value={hint}
            onChange={(e) => setHint(e.target.value)}
            maxLength={50}
            disabled={busy}
          />
          {hasHint && (
            <small className="field-hint">
              {t('Leer lassen entfernt den bisherigen Hinweis.')}
            </small>
          )}
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

function NewKdf({
  current,
  onCancel,
  onDone,
}: {
  current: Kdf;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [kdf, setKdf] = useState<Kdf>(current);
  const set = (change: Partial<Record<string, number>>) => setKdf({ ...kdf, ...change } as Kdf);
  return (
    <PasswordPrompt
      title={t('Schlüsselableitung ändern')}
      lead={t(
        'Wie aus deinem Master-Passwort der Schlüssel wird. Stärker heißt: schwerer zu erraten, aber etwas längeres Warten beim Entsperren.',
      )}
      confirm={t('Ändern')}
      onCancel={onCancel}
      action={async (password) => {
        await changeKdf(password, kdf);
        onDone();
      }}
    >
      <div className="segmented wide" role="radiogroup" aria-label={t('Schlüsselableitung')}>
        {(['argon2id', 'pbkdf2'] as const).map((kind) => (
          <button
            key={kind}
            type="button"
            role="radio"
            aria-checked={kdf.kind === kind}
            onClick={() => setKdf(kind === current.kind ? current : DEFAULT_KDFS[kind])}
          >
            {kind === 'argon2id' ? 'Argon2id' : 'PBKDF2'}
          </button>
        ))}
      </div>
      {kdf.kind === 'pbkdf2' ? (
        <label className="field">
          <span>{t('Runden')}</span>
          <input
            type="number"
            min={100000}
            max={2000000}
            step={50000}
            value={kdf.iterations}
            onChange={(e) => set({ iterations: Number(e.target.value) })}
          />
        </label>
      ) : (
        <div className="field-grid">
          <label className="field">
            <span>{t('Speicher (MiB)')}</span>
            <input
              type="number"
              min={15}
              max={1024}
              value={kdf.memory}
              onChange={(e) => set({ memory: Number(e.target.value) })}
            />
          </label>
          <label className="field">
            <span>{t('Durchläufe')}</span>
            <input
              type="number"
              min={2}
              max={10}
              value={kdf.iterations}
              onChange={(e) => set({ iterations: Number(e.target.value) })}
            />
          </label>
          <label className="field">
            <span>{t('Threads')}</span>
            <input
              type="number"
              min={1}
              max={16}
              value={kdf.parallelism}
              onChange={(e) => set({ parallelism: Number(e.target.value) })}
            />
          </label>
        </div>
      )}
    </PasswordPrompt>
  );
}

function NewEmail({ onCancel, onDone }: { onCancel: () => void; onDone: () => void }) {
  useLanguage();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
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
      title={t('E-Mail-Adresse ändern')}
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
                  await changeEmail(password, email, code);
                  onDone();
                })
              }
            >
              {t('Umziehen')}
            </button>
          ) : (
            <button
              className="primary"
              disabled={busy || !email.includes('@') || !password}
              onClick={() =>
                void run(async () => {
                  await requestEmailChange(password, email);
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
        <p className="dialog-lead">
          {t(
            'Die Adresse ist auch das Salz deines Schlüssels: Er wird dabei neu verpackt, und alle Geräte melden sich neu an.',
          )}
        </p>
        <label className="field">
          <span>{t('Neue Adresse')}</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={busy || sent}
            autoFocus
          />
        </label>
        <label className="field">
          <span>{t('Master-Passwort')}</span>
          <PasswordInput value={password} onChange={setPassword} disabled={busy || sent} />
        </label>
        {sent && (
          <label className="field">
            <span>{t('Code aus der Mail an die neue Adresse')}</span>
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
