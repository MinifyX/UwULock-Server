import { useEffect, useState } from 'react';
import { logout, type Status } from '../../lib/api';
import {
  changeKdf,
  kdfForMinimum,
  kdfOf,
  prelogin,
  type AccountInfo,
  type Kdf,
} from '../../lib/account';
import { locale, t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import type { SettingsSection } from '../SettingsDialog';
import { PasswordPrompt, Segmented } from './controls';
import { TwoFactorSettings } from './TwoFactorSettings';

/** The account has to set up two-step login, and has not yet. */
export const lacksTwoFactor = (info: AccountInfo | null) =>
  Boolean(info?.policy?.twoFactorRequired && info.twoFactor.length === 0);

function day(iso: string | null | undefined): string {
  const date = iso ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(locale(), { dateStyle: 'long', timeStyle: 'short' });
}

/**
 * What the server's rules ask of this account, above the vault: two-step login from a date on,
 * and a key derivation that is weaker than it takes for new ones.
 */
export function PolicyBanners({
  status,
  info,
  onSettings,
}: {
  status: Status;
  info: AccountInfo | null;
  onSettings: (section: SettingsSection) => void;
}) {
  useLanguage();
  const [upgrading, setUpgrading] = useState(false);
  const policy = info?.policy;
  if (!policy) return null;
  return (
    <>
      {lacksTwoFactor(info) && !policy.twoFactorEnforced && (
        <div className="notice policy-banner" role="status">
          <Icon name="shield" size={16} />
          <span className="policy-banner-text">
            {t(
              'Dieser Server verlangt ab {date} die Zwei-Schritt-Anmeldung. Danach melden dich Apps, Erweiterungen und die CLI erst wieder an, wenn sie eingerichtet ist.',
              { date: day(policy.twoFactorDeadline) },
            )}
          </span>
          <button onClick={() => onSettings('two-factor')}>{t('Einrichten')}</button>
        </div>
      )}
      {policy.kdfBelowMinimum && (
        <div className="notice policy-banner" role="status">
          <Icon name="key" size={16} />
          <span className="policy-banner-text">
            {t(
              'Deine Schlüsselableitung ist schwächer, als dieser Server für neue Konten verlangt. Stell sie um: Dein Master-Passwort wird dadurch schwerer zu erraten.',
            )}
          </span>
          <button onClick={() => setUpgrading(true)}>{t('Jetzt umstellen')}</button>
        </div>
      )}
      {upgrading && status.email && (
        <UpgradeKdf
          email={status.email}
          info={info}
          onCancel={() => setUpgrading(false)}
          onDone={() => toast(t('Schlüsselableitung umgestellt. Melde dich neu an.'), 'info')}
        />
      )}
    </>
  );
}

/** A key derivation that meets the minimum, after the master password. Every session ends. */
function UpgradeKdf({
  email,
  info,
  onCancel,
  onDone,
}: {
  email: string;
  info: AccountInfo | null;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [current, setCurrent] = useState<Kdf | null>(null);
  const [keep, setKeep] = useState(false);
  useEffect(() => {
    void prelogin(email).then((text) => setCurrent(kdfOf(text)));
  }, [email]);
  const minimum = info?.policy?.minimumKdf;
  if (!current || !minimum) return null;
  const target = kdfForMinimum(current, minimum, keep);
  return (
    <PasswordPrompt
      title={t('Schlüsselableitung umstellen')}
      lead={
        <>
          <p>
            {target.kind === 'argon2id'
              ? t(
                  'Neu: Argon2id mit {memory} MiB, {iterations} Durchläufen und {parallelism} Threads. Das Entsperren dauert danach etwas länger.',
                  {
                    memory: target.memory,
                    iterations: target.iterations,
                    parallelism: target.parallelism,
                  },
                )
              : t('Neu: PBKDF2 mit {n} Runden.', { n: target.iterations.toLocaleString() })}
          </p>
          <p>{t('Danach meldest du dich überall neu an, auch hier.')}</p>
        </>
      }
      confirm={t('Umstellen')}
      onCancel={onCancel}
      action={async (password) => {
        await changeKdf(password, target);
        onDone();
      }}
    >
      {current.kind === 'pbkdf2' && (
        <Segmented
          label={t('Verfahren')}
          value={keep ? 'pbkdf2' : 'argon2id'}
          onChange={(kind) => setKeep(kind === 'pbkdf2')}
          options={[
            { value: 'argon2id', label: t('Argon2id (empfohlen)') },
            { value: 'pbkdf2', label: t('PBKDF2 behalten') },
          ]}
        />
      )}
    </PasswordPrompt>
  );
}

/**
 * All the vault shows once two-step login is required and the date has passed: why, and the
 * setup. Once a way is on, the account is fetched again and the vault opens.
 */
export function TwoFactorRequired({
  status,
  info,
  onInfo,
}: {
  status: Status;
  info: AccountInfo;
  onInfo: (info: AccountInfo | null) => void;
}) {
  useLanguage();
  const deadline = day(info.policy?.twoFactorDeadline);
  return (
    <div className="lock">
      <div className="lock-card required-card">
        <h1 className="card-title">{t('Zwei-Schritt-Anmeldung einrichten')}</h1>
        <p className="dialog-lead">
          {deadline
            ? t(
                'Dieser Server verlangt seit {date} einen zweiten Schritt beim Anmelden. Bis du einen eingerichtet hast, zeigt der Web-Tresor nur das hier, und Apps, Browser-Erweiterungen und die CLI melden dich nicht an.',
                { date: deadline },
              )
            : t(
                'Dieser Server verlangt einen zweiten Schritt beim Anmelden. Bis du einen eingerichtet hast, zeigt der Web-Tresor nur das hier, und Apps, Browser-Erweiterungen und die CLI melden dich nicht an.',
              )}
        </p>
        <div className="required-setup">
          <TwoFactorSettings status={status} info={info} onInfo={onInfo} />
        </div>
        <div className="form-actions">
          <span className="spacer" />
          <button onClick={() => void logout()}>{t('Abmelden')}</button>
        </div>
      </div>
    </div>
  );
}
