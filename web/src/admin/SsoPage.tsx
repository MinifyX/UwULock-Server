import { useEffect, useState } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import { ResultLine, Row, Toggle, type Result } from '../components/web/controls';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import {
  newScimToken,
  pairSso,
  saveScimOnDelete,
  saveSso,
  ssoSettings,
  testSso,
  unpairSso,
  type Signups,
  type SsoSettings,
} from '../lib/sso';
import { copyGenerated } from '../lib/api';
import { useSwitch } from '../lib/switches';
import { ApiError } from '../lib/web/http';

/**
 * *Anmeldung*: logging in through UwUAuth or another OpenID Connect provider (docs/sso.md) —
 * paired with UwUAuth by a code, or set up by hand — and SCIM, over which the provider disables
 * and removes accounts.
 */
export function SsoPage({ sso: loggedInWithSso }: { sso: boolean }) {
  // SCIM is a feature switch of its own (the Features tab); switched off, its settings wait.
  const scimOn = useSwitch('scim');
  useLanguage();
  const [current, setCurrent] = useState<SsoSettings | null>(null);
  const [draft, setDraft] = useState<SsoSettings | null>(null);
  const [secret, setSecret] = useState('');
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);
  const [pairUrl, setPairUrl] = useState('');
  const [pairCode, setPairCode] = useState('');
  const [scimToken, setScimToken] = useState<string | null>(null);

  const loaded = (settings: SsoSettings) => {
    setCurrent(settings);
    setDraft(settings);
    setSecret('');
  };

  useEffect(() => {
    ssoSettings().then(loaded, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, []);

  if (!draft || !current) return <ResultLine result={result} />;
  const set = (change: Partial<SsoSettings>) => setDraft({ ...draft, ...change });
  const dirty = secret !== '' || JSON.stringify(draft) !== JSON.stringify(current);

  const run = async (work: () => Promise<string | null>) => {
    setBusy(true);
    setResult(null);
    try {
      const text = await work();
      if (text) setResult({ tone: 'info', text });
    } catch (e) {
      const code = e instanceof ApiError ? (e.body as { code?: string } | null)?.code : null;
      const text =
        code === 'invalid_code'
          ? t('UwUAuth kennt diesen Code nicht (mehr). Mach dort einen neuen.')
          : code === 'not_uwuauth'
            ? t('Unter dieser Adresse antwortet kein UwUAuth, das koppeln kann (ab 0.4).')
            : errorText(e);
      setResult({ tone: 'error', text });
    } finally {
      setBusy(false);
    }
  };

  const pair = () =>
    run(async () => {
      loaded(await pairSso(pairUrl.trim(), pairCode.trim()));
      setPairCode('');
      return t('Mit UwUAuth gekoppelt ✧ Probier die Anmeldung in einem privaten Fenster aus.');
    });

  const unpair = () =>
    run(async () => {
      const manage = current.paired?.manageUrl;
      loaded(await unpairSso());
      return manage
        ? t('Entkoppelt. Die App in UwUAuth löschst du dort: {url}', { url: manage })
        : t('Entkoppelt.');
    });

  const save = () =>
    run(async () => {
      loaded(await saveSso({ ...draft, clientSecret: secret || null }));
      return t('Gespeichert ✧');
    });

  const test = () =>
    run(async () => {
      const answer = await testSso(draft.issuer);
      if (!answer.ok) throw new Error(answer.error ?? '?');
      return t('Der Anbieter antwortet, seine Schlüssel sind lesbar ✧');
    });

  const makeScimToken = () =>
    run(async () => {
      const made = await newScimToken();
      setScimToken(made.token);
      setCurrent({ ...current, scimTokenSet: true });
      setDraft({ ...draft, scimTokenSet: true });
      return null;
    });

  const onDelete = (value: 'disable' | 'delete') =>
    run(async () => {
      await saveScimOnDelete(value);
      setCurrent({ ...current, scimOnDelete: value });
      setDraft({ ...draft, scimOnDelete: value });
      return t('Gespeichert ✧');
    });

  const group = (value: string) => (value.trim() ? value : null);

  return (
    <div className="admin-settings">
      <h2 className="settings-heading">{t('Mit UwUAuth koppeln')}</h2>
      {current.paired ? (
        <>
          <p className="settings-lead">
            {t('Gekoppelt mit {url} seit {date}.', {
              url: current.paired.url,
              date: when(current.paired.date) ?? current.paired.date,
            })}{' '}
            {t(
              'Wer die Rolle „user“ hat, darf sich einen Tresor anlegen; die Rolle „admin“ macht zum Admin. Beides stellst du in UwUAuth ein.',
            )}
          </p>
          <div className="form-actions">
            {current.paired.manageUrl && (
              <a
                className="button-link"
                href={current.paired.manageUrl}
                target="_blank"
                rel="noreferrer"
              >
                {t('In UwUAuth öffnen')}
              </a>
            )}
            <span className="spacer" />
            <button type="button" onClick={() => void unpair()} disabled={busy}>
              {t('Entkoppeln')}
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="settings-lead">
            {t(
              'In UwUAuth unter Apps → UwUSuite-App koppeln einen Code machen und hier eingeben (oder den Text des QR-Codes einfügen). Client-ID, Geheimnis, Adressen und SCIM stellen sich dann von selbst ein.',
            )}
          </p>
          <div className="field-grid wide">
            <label className="field">
              <span>{t('Adresse von UwUAuth')}</span>
              <input
                value={pairUrl}
                onChange={(e) => setPairUrl(e.target.value)}
                placeholder="https://auth.example.com"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Code')}</span>
              <input
                value={pairCode}
                onChange={(e) => setPairCode(e.target.value)}
                placeholder="7KQ4-M2XD-9HFT"
                spellCheck={false}
              />
            </label>
          </div>
          <div className="form-actions">
            <span className="spacer" />
            <button
              className="primary"
              type="button"
              onClick={() => void pair()}
              disabled={busy || !pairCode.trim()}
            >
              {t('Koppeln')}
            </button>
          </div>
        </>
      )}

      <h2 className="settings-heading">{t('OpenID Connect')}</h2>
      <p className="settings-lead">
        {t(
          'Für jeden anderen Anbieter (Keycloak, Authentik, Entra ID, …) von Hand. Beim Anbieter trägst du diese Rückleitungsadresse ein: {uri}',
          { uri: current.redirectUri ?? '' },
        )}
      </p>
      <Row
        label={t('Anmeldung über SSO')}
        description={t(
          'Ein Knopf auf der Anmeldeseite des Web-Tresors und des Admin-Portals, und „Mit SSO anmelden“ in den Bitwarden-Apps (die SSO-Kennung ist egal). Der Tresor öffnet sich weiter nur mit dem Master-Passwort.',
        )}
      >
        <Toggle
          label={t('Anmeldung über SSO')}
          checked={draft.enabled}
          onChange={(enabled) => set({ enabled })}
        />
      </Row>
      <div className="field-grid wide">
        <label className="field">
          <span>{t('Issuer')}</span>
          <input
            value={draft.issuer}
            onChange={(e) => set({ issuer: e.target.value })}
            placeholder="https://auth.example.com"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t('Client-ID')}</span>
          <input
            value={draft.clientId}
            onChange={(e) => set({ clientId: e.target.value })}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>
            {current.clientSecretSet
              ? t('Client-Geheimnis (leer lassen: bleibt)')
              : t('Client-Geheimnis')}
          </span>
          <PasswordInput value={secret} onChange={setSecret} autoComplete="off" />
        </label>
        <label className="field">
          <span>{t('Scopes')}</span>
          <input
            value={draft.scopes.join(' ')}
            onChange={(e) => set({ scopes: e.target.value.split(/\s+/).filter(Boolean) })}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t('Beschriftung des Knopfs')}</span>
          <input value={draft.label} onChange={(e) => set({ label: e.target.value })} />
        </label>
        <label className="field">
          <span>{t('SSO-Kennung für die Bitwarden-Apps')}</span>
          <input
            value={draft.identifier}
            onChange={(e) => set({ identifier: e.target.value })}
            spellCheck={false}
          />
        </label>
      </div>

      <Row
        label={t('Wer sich ohne Einladung einen Tresor anlegen darf')}
        description={t(
          'Beim ersten Mal legt man sein Master-Passwort selbst fest. Einladungen gehen immer, und Adressen, die SCIM angelegt hat, auch.',
        )}
      >
        <select
          aria-label={t('Wer sich ohne Einladung einen Tresor anlegen darf')}
          value={draft.signups}
          onChange={(e) => set({ signups: e.target.value as Signups })}
        >
          <option value="off">{t('Niemand – nur bestehende Konten')}</option>
          <option value="invitation">{t('Nur mit Einladung oder über SCIM')}</option>
          <option value="group">{t('Wer in der Nutzergruppe ist')}</option>
        </select>
      </Row>
      <div className="field-grid wide">
        <label className="field">
          <span>{t('Nutzergruppe (leer: alle, die der Anbieter durchlässt)')}</span>
          <input
            value={draft.userGroup ?? ''}
            onChange={(e) => set({ userGroup: group(e.target.value) })}
            placeholder="vault-users"
          />
        </label>
        <label className="field">
          <span>{t('Admin-Gruppe (leer: Admins bleiben, wie sie sind)')}</span>
          <input
            value={draft.adminGroup ?? ''}
            onChange={(e) => set({ adminGroup: group(e.target.value) })}
            placeholder="vault-admins"
          />
        </label>
        <label className="field">
          <span>{t('Claim mit den Gruppen')}</span>
          <input
            value={draft.groupsClaim}
            onChange={(e) => set({ groupsClaim: e.target.value })}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t('Claim mit den Rollen (statt der Gruppen)')}</span>
          <input
            value={draft.rolesClaim ?? ''}
            onChange={(e) => set({ rolesClaim: group(e.target.value) })}
            placeholder="roles"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>
            {t('Weitere Browser-Erweiterungen (IDs, eine pro Zeile; nur für selbst gebaute)')}
          </span>
          <textarea
            rows={2}
            value={(draft.extensionIds ?? []).join('\n')}
            onChange={(e) => set({ extensionIds: e.target.value.split('\n') })}
            spellCheck={false}
          />
        </label>
      </div>
      <Row
        label={t('Nur noch über SSO anmelden')}
        description={t(
          'Die Anmeldung mit Passwort (und Passkey) geht dann nur noch für Admins und mit dem API-Key der CLI.',
        )}
      >
        <Toggle
          label={t('Nur noch über SSO anmelden')}
          checked={draft.only}
          onChange={(only) => set({ only })}
        />
      </Row>
      <Row
        label={t('Admin-Portal nur nach Anmeldung über SSO')}
        description={
          loggedInWithSso
            ? t('Auch Admins kommen dann nur noch über SSO ins Admin-Portal.')
            : t(
                'Auch Admins kommen dann nur noch über SSO ins Admin-Portal. Einschalten kannst du es, sobald du selbst über SSO angemeldet bist.',
              )
        }
      >
        <Toggle
          label={t('Admin-Portal nur nach Anmeldung über SSO')}
          checked={draft.adminsOnlyWithSso}
          onChange={(adminsOnlyWithSso) => set({ adminsOnlyWithSso })}
        />
      </Row>
      <Row
        label={t('Unbestätigten Adressen trauen')}
        description={t(
          'Sonst findet und verknüpft eine Anmeldung ein Konto nur über eine Adresse, die der Anbieter als bestätigt meldet (email_verified).',
        )}
      >
        <Toggle
          label={t('Unbestätigten Adressen trauen')}
          checked={draft.trustUnverifiedEmail}
          onChange={(trustUnverifiedEmail) => set({ trustUnverifiedEmail })}
        />
      </Row>
      <div className="form-actions">
        <button type="button" onClick={() => void test()} disabled={busy || !draft.issuer.trim()}>
          {t('Anbieter testen')}
        </button>
        <span className="spacer" />
        <button
          type="button"
          className="quiet"
          onClick={() => loaded(current)}
          disabled={busy || !dirty}
        >
          {t('Verwerfen')}
        </button>
        <button
          className="primary"
          type="button"
          onClick={() => void save()}
          disabled={busy || !dirty}
        >
          {t('Speichern')}
        </button>
      </div>

      {scimOn && (
        <>
          <h2 className="settings-heading">{t('SCIM')}</h2>
          <p className="settings-lead">
            {t(
              'Darüber sperrt oder entfernt der Anbieter Konten und legt Adressen an, die sich anmelden dürfen. Adresse: {url}',
              { url: current.scimUrl ?? '' },
            )}
          </p>
          <Row
            label={t('Wenn der Anbieter jemanden löscht')}
            description={t(
              'Sperren lässt den Tresor da (ein Admin kann ihn wieder freigeben); Löschen löscht Konto und Tresor. Das letzte Admin-Konto bleibt immer.',
            )}
          >
            <select
              aria-label={t('Wenn der Anbieter jemanden löscht')}
              value={current.scimOnDelete ?? 'disable'}
              onChange={(e) => void onDelete(e.target.value as 'disable' | 'delete')}
              disabled={busy}
            >
              <option value="disable">{t('Konto sperren')}</option>
              <option value="delete">{t('Konto und Tresor löschen')}</option>
            </select>
          </Row>
          <Row
            label={t('SCIM-Token')}
            description={
              current.scimTokenSet
                ? t('Es gibt eines. Ein neues ersetzt es.')
                : t('Noch keines. Beim Koppeln mit UwUAuth kommt es von selbst.')
            }
          >
            <button type="button" onClick={() => void makeScimToken()} disabled={busy}>
              {current.scimTokenSet ? t('Neues Token') : t('Token erzeugen')}
            </button>
          </Row>
          {scimToken && (
            <div className="field">
              <span>{t('Das Token – nur jetzt zu sehen:')}</span>
              <div className="form-actions">
                <code className="send-link">{scimToken}</code>
                <button type="button" onClick={() => void copyGenerated(scimToken)}>
                  {t('Kopieren')}
                </button>
              </div>
            </div>
          )}
        </>
      )}
      <ResultLine result={result} />
    </div>
  );
}
