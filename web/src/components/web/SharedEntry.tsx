import { useEffect, useState, type ReactNode } from 'react';
import { copyGenerated, type TotpCode } from '../../lib/api';
import { entryCodes, type SharedEntry } from '../../lib/entrySend';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { Colored } from '../ItemDetail';
import { TotpCodes } from '../Totp';

async function copy(text: string, done = t('Kopiert ✧')) {
  try {
    await copyGenerated(text);
    toast(done);
  } catch (e) {
    toast(errorText(e), 'error');
  }
}

function CopyButton({ value, label }: { value: string; label: string }) {
  useLanguage();
  return (
    <button
      type="button"
      className="icon-button"
      onClick={() => void copy(value)}
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

/** A secret value: dots until the eye is clicked. */
function SecretRow({ label, value, colored }: { label: string; value: string; colored?: boolean }) {
  useLanguage();
  const [shown, setShown] = useState(false);
  return (
    <Row
      label={label}
      mono
      actions={
        <>
          <button
            type="button"
            className="icon-button"
            onClick={() => setShown(!shown)}
            aria-label={shown ? t('{label} verbergen', { label }) : t('{label} zeigen', { label })}
            aria-pressed={shown}
            title={shown ? t('Verbergen') : t('Zeigen')}
          >
            <Icon name={shown ? 'eyeOff' : 'eye'} size={15} />
          </button>
          <CopyButton value={value} label={label} />
        </>
      }
    >
      {!shown ? (
        <span className="masked">••••••••••••</span>
      ) : colored ? (
        <Colored text={value} />
      ) : (
        value
      )}
    </Row>
  );
}

/**
 * The live one-time codes of the entry's authenticator key: the code, its countdown and, in the
 * last seconds, the next one. Never the key itself, nor a QR code of it.
 */
function CodesRow({ secret }: { secret: string }) {
  useLanguage();
  const [code, setCode] = useState<TotpCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const next = await entryCodes(secret);
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
  }, [secret]);
  return (
    <Row
      label={t('Einmal-Code (TOTP)')}
      mono
      actions={
        code && (
          <button
            type="button"
            className="icon-button"
            onClick={() => void copy(code.code, t('Code kopiert ✧'))}
            aria-label={t('{label} kopieren', { label: t('Code') })}
            title={t('Kopieren')}
          >
            <Icon name="copy" size={15} />
          </button>
        )
      }
    >
      {error ? (
        <span className="detail-error">{error}</span>
      ) : code ? (
        <TotpCodes
          code={code}
          onCopyNext={() => void copy(code.next, t('Nächster Code kopiert ✧'))}
        />
      ) : (
        '…'
      )}
    </Row>
  );
}

/**
 * An entry Send on the Send page: the shared item laid out like an item in the vault — its
 * values with copy buttons, secrets behind the eye, live one-time codes.
 */
export function SharedEntryView({ entry, openable }: { entry: SharedEntry; openable: boolean[] }) {
  useLanguage();
  const login = entry.username || entry.password || entry.totp;
  return (
    <div className="shared-entry" data-shared-entry>
      {login && (
        <section className="detail-card">
          {entry.username && (
            <Row
              label={t('Benutzername')}
              actions={<CopyButton value={entry.username} label={t('Benutzername')} />}
            >
              {entry.username}
            </Row>
          )}
          {entry.password && <SecretRow label={t('Passwort')} value={entry.password} colored />}
          {entry.totp && <CodesRow secret={entry.totp} />}
        </section>
      )}
      {entry.websites.length > 0 && (
        <section className="detail-card">
          <h2 className="detail-card-title">
            {entry.websites.length === 1 ? t('Website') : t('Websites')}
          </h2>
          {entry.websites.map((uri, index) => (
            <Row
              key={index}
              label={t('Adresse')}
              actions={
                <>
                  {/* Only web addresses become links (core `entry_send::openable`); anything else is text to copy. */}
                  {openable[index] === true && (
                    <a
                      className="icon-button"
                      href={uri.trim()}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      aria-label={t('{uri} im Browser öffnen', { uri })}
                      title={t('Im Browser öffnen')}
                    >
                      <Icon name="external" size={15} />
                    </a>
                  )}
                  <CopyButton value={uri} label={t('Adresse')} />
                </>
              }
            >
              <span className="uri">{uri}</span>
            </Row>
          ))}
        </section>
      )}
      {entry.fields.length > 0 && (
        <section className="detail-card">
          {entry.fields.map((field, index) =>
            field.hidden ? (
              <SecretRow key={index} label={field.name || t('Feld')} value={field.value} />
            ) : (
              <Row
                key={index}
                label={field.name || t('Feld')}
                actions={<CopyButton value={field.value} label={field.name || t('Feld')} />}
              >
                <span className="multiline">{field.value}</span>
              </Row>
            ),
          )}
        </section>
      )}
      {entry.notes && (
        <section className="detail-card">
          <h2 className="detail-card-title">{t('Notizen')}</h2>
          <div className="notes">
            <p>{entry.notes}</p>
            <CopyButton value={entry.notes} label={t('Notizen')} />
          </div>
        </section>
      )}
    </div>
  );
}
