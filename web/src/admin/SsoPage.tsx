import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { PasswordInput } from '../components/PasswordInput';
import {
  Button,
  ButtonRow,
  Callout,
  DangerZone,
  Field,
  FormRow,
  Modal,
  Section,
  Select,
  SettingRow,
  TextField,
  Toggle,
} from '../components/ui';
import { PasswordPrompt, ResultLine, type Result } from '../components/web/controls';
import { copyGenerated } from '../lib/api';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import {
  newScimToken,
  pairSso,
  saveScimOnDelete,
  saveSso,
  ssoNeedsPassword,
  ssoSettings,
  testSso,
  unpairSso,
  type Signups,
  type SsoSettings,
} from '../lib/sso';
import { ApiError } from '../lib/web/http';
import { Explain } from './fields';

/**
 * Logging in through UwUAuth or another OpenID Connect provider (docs/sso.md) — paired with
 * UwUAuth by a code, or set up by hand — and SCIM, over which the provider disables and removes
 * accounts. Three tabs (the provider, its rules, SCIM) share one state: what is typed in one is
 * still there in the other, and one Save keeps both.
 */
type Sso = {
  current: SsoSettings | null;
  draft: SsoSettings | null;
  secret: string;
  setSecret: (secret: string) => void;
  set: (change: Partial<SsoSettings>) => void;
  loaded: (settings: SsoSettings) => void;
  setCurrent: (settings: SsoSettings) => void;
  result: Result;
  busy: boolean;
  /** Runs `work`; what it returns is shown as the result, and a thrown error in words. */
  run: (work: () => Promise<string | null>) => Promise<void>;
  load: () => void;
};

const Context = createContext<Sso | null>(null);

export function SsoProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<SsoSettings | null>(null);
  const [draft, setDraft] = useState<SsoSettings | null>(null);
  const [secret, setSecret] = useState('');
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);
  const [asked, setAsked] = useState(false);
  const load = useCallback(() => setAsked(true), []);

  const loaded = (settings: SsoSettings) => {
    setCurrent(settings);
    setDraft(settings);
    setSecret('');
  };

  // Only once a tab of it is opened: with SSO switched off there is nothing to load.
  useEffect(() => {
    if (!asked) return;
    ssoSettings().then(loaded, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, [asked]);

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

  return (
    <Context.Provider
      value={{
        current,
        draft,
        secret,
        setSecret,
        set: (change) => setDraft((d) => (d ? { ...d, ...change } : d)),
        loaded,
        setCurrent: (settings) => {
          setCurrent(settings);
          setDraft((d) => (d ? { ...d, ...pickServerSide(settings) } : settings));
        },
        result,
        busy,
        run,
        load,
      }}
    >
      {children}
    </Context.Provider>
  );
}

/** What changes on the server without the Save button: the SCIM token and what SCIM deletes. */
function pickServerSide(settings: SsoSettings): Partial<SsoSettings> {
  return { scimTokenSet: settings.scimTokenSet, scimOnDelete: settings.scimOnDelete };
}

function useSso(): Sso {
  const sso = useContext(Context);
  if (!sso) throw new Error('SsoProvider missing');
  const { load } = sso;
  useEffect(load, [load]);
  return sso;
}

/** Save and discard for the provider and its rules, and the test of the provider. */
function SsoActions({ test }: { test?: boolean }) {
  useLanguage();
  const { current, draft, secret, loaded, run, busy, result } = useSso();
  const [asking, setAsking] = useState(false);
  if (!current || !draft) return null;
  const dirty = secret !== '' || JSON.stringify(draft) !== JSON.stringify(current);
  const store = (password?: string) =>
    run(async () => {
      loaded(await saveSso({ ...draft, clientSecret: secret || null }, password));
      return t('Gespeichert ✧');
    });
  return (
    <>
      <ButtonRow>
        {test && (
          <Button
            onClick={() =>
              void run(async () => {
                const answer = await testSso(draft.issuer);
                if (!answer.ok) throw new Error(answer.error ?? '?');
                return t('Der Anbieter antwortet, seine Schlüssel sind lesbar ✧');
              })
            }
            disabled={busy || !draft.issuer.trim()}
          >
            {t('Anbieter testen')}
          </Button>
        )}
        <span className="spacer" />
        <Button variant="quiet" onClick={() => loaded(current)} disabled={busy || !dirty}>
          {t('Verwerfen')}
        </Button>
        <Button
          variant="primary"
          onClick={() =>
            ssoNeedsPassword(current, draft, secret) ? setAsking(true) : void store()
          }
          disabled={busy || !dirty}
        >
          {t('Speichern')}
        </Button>
      </ButtonRow>
      {asking && (
        <PasswordPrompt
          title={t('SSO-Anbieter ändern?')}
          tone="warning"
          lead={t(
            'Der Anbieter entscheidet, wer sich als wer anmeldet. Deshalb fragt der Server hier nach deinem Master-Passwort.',
          )}
          confirm={t('Speichern')}
          onCancel={() => setAsking(false)}
          action={async (password) => {
            setAsking(false);
            await store(password);
          }}
        />
      )}
      {dirty && (
        <p className="field-hint">
          {t('Speichern nimmt die Änderungen unter „SSO-Anbieter“ und „SSO-Regeln“ zusammen.')}
        </p>
      )}
      <ResultLine result={result} />
    </>
  );
}

/** *Sicherheit → SSO-Anbieter*: pairing with UwUAuth, or any OpenID Connect provider by hand. */
export function SsoProviderTab() {
  useLanguage();
  const { current, draft, secret, setSecret, set, loaded, run, busy, result } = useSso();
  const [pairUrl, setPairUrl] = useState('');
  const [pairCode, setPairCode] = useState('');
  const [unpairing, setUnpairing] = useState(false);
  const [pairing, setPairing] = useState(false);
  if (!draft || !current) return <ResultLine result={result} />;

  const pair = (password: string) =>
    run(async () => {
      loaded(await pairSso(pairUrl.trim(), pairCode.trim(), password));
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

  return (
    <>
      <Section
        heading={t('Mit UwUAuth koppeln')}
        lead={
          current.paired
            ? `${t('Gekoppelt mit {url} seit {date}.', {
                url: current.paired.url,
                date: when(current.paired.date) ?? current.paired.date,
              })} ${t(
                'Wer die Rolle „user“ hat, darf sich einen Tresor anlegen; die Rolle „admin“ macht zum Admin. Beides stellst du in UwUAuth ein.',
              )}`
            : t(
                'In UwUAuth unter Apps → UwUSuite-App koppeln einen Code machen und hier eingeben (oder den Text des QR-Codes einfügen). Client-ID, Geheimnis, Adressen und SCIM stellen sich dann von selbst ein.',
              )
        }
      >
        {current.paired ? (
          <ButtonRow>
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
            <Button variant="quiet-danger" onClick={() => setUnpairing(true)} disabled={busy}>
              {t('Entkoppeln …')}
            </Button>
          </ButtonRow>
        ) : (
          <>
            <FormRow min="wide">
              <TextField
                label={t('Adresse von UwUAuth')}
                value={pairUrl}
                onChange={setPairUrl}
                placeholder="https://auth.example.com"
                spellCheck={false}
              />
              <TextField
                label={t('Code')}
                value={pairCode}
                onChange={setPairCode}
                placeholder="7KQ4-M2XD-9HFT"
                spellCheck={false}
              />
            </FormRow>
            <ButtonRow end>
              <Button onClick={() => setPairing(true)} disabled={busy || !pairCode.trim()}>
                {t('Koppeln')}
              </Button>
            </ButtonRow>
          </>
        )}
      </Section>

      <Section
        heading={t('Anbieter von Hand (OpenID Connect)')}
        lead={t(
          'Für jeden anderen Anbieter (Keycloak, Authentik, Entra ID, …). Beim Anbieter trägst du diese Rückleitungsadresse ein: {uri}',
          { uri: current.redirectUri ?? '' },
        )}
      >
        <SettingRow
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
        </SettingRow>
        <FormRow min="wide">
          <TextField
            label={t('Issuer')}
            hint={t('Die Adresse des Anbieters.')}
            value={draft.issuer}
            onChange={(issuer) => set({ issuer })}
            placeholder="https://auth.example.com"
            spellCheck={false}
          />
          <TextField
            label={t('Client-ID')}
            value={draft.clientId}
            onChange={(clientId) => set({ clientId })}
            spellCheck={false}
          />
          <Field
            label={
              current.clientSecretSet
                ? t('Client-Geheimnis (leer lassen: bleibt)')
                : t('Client-Geheimnis')
            }
          >
            <PasswordInput value={secret} onChange={setSecret} autoComplete="off" />
          </Field>
        </FormRow>
        <FormRow min="wide">
          <TextField
            label={t('Scopes')}
            hint={t('Durch Leerzeichen getrennt.')}
            value={draft.scopes.join(' ')}
            onChange={(scopes) => set({ scopes: scopes.split(/\s+/).filter(Boolean) })}
            spellCheck={false}
          />
          <TextField
            label={t('Beschriftung des Knopfs')}
            value={draft.label}
            onChange={(label) => set({ label })}
          />
          <TextField
            label={t('SSO-Kennung für die Bitwarden-Apps')}
            value={draft.identifier}
            onChange={(identifier) => set({ identifier })}
            spellCheck={false}
          />
        </FormRow>
        <Field
          label={t('Weitere Browser-Erweiterungen (IDs, eine pro Zeile; nur für selbst gebaute)')}
        >
          <textarea
            rows={2}
            value={(draft.extensionIds ?? []).join('\n')}
            onChange={(e) => set({ extensionIds: e.target.value.split('\n') })}
            spellCheck={false}
          />
        </Field>
      </Section>
      <SsoActions test />

      {pairing && (
        <PasswordPrompt
          title={t('Mit UwUAuth koppeln')}
          lead={t(
            'Der Anbieter entscheidet, wer sich als wer anmeldet. Deshalb fragt der Server hier nach deinem Master-Passwort.',
          )}
          confirm={t('Koppeln')}
          onCancel={() => setPairing(false)}
          action={async (password) => {
            setPairing(false);
            await pair(password);
          }}
        />
      )}
      {unpairing && (
        <Modal
          title={t('Von UwUAuth entkoppeln?')}
          tone="warning"
          onCancel={() => setUnpairing(false)}
          footer={
            <>
              <span className="spacer" />
              <Button data-autofocus data-secondary onClick={() => setUnpairing(false)}>
                {t('Abbrechen')}
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  setUnpairing(false);
                  void unpair();
                }}
              >
                {t('Entkoppeln')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Danach meldet sich niemand mehr über UwUAuth an, bis du wieder koppelst oder einen Anbieter von Hand einträgst. Konten und Tresore bleiben.',
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

/** *Sicherheit → SSO-Regeln*: who gets in through SSO, and who only through it. */
export function SsoRulesTab({ sso: loggedInWithSso }: { sso: boolean }) {
  useLanguage();
  const { current, draft, set, result } = useSso();
  if (!draft || !current) return <ResultLine result={result} />;
  const group = (value: string) => (value.trim() ? value : null);
  return (
    <>
      <Section
        heading={t('Wer über SSO einen Tresor bekommt')}
        lead={t(
          'Beim ersten Mal legt man sein Master-Passwort selbst fest. Einladungen gehen immer, und Adressen, die SCIM angelegt hat, auch.',
        )}
      >
        <SettingRow
          label={t('Wer sich ohne Einladung einen Tresor anlegen darf')}
          description={t('Wer schon ein Konto hat, meldet sich in jedem Fall an.')}
        >
          <Select
            label={t('Wer sich ohne Einladung einen Tresor anlegen darf')}
            value={draft.signups}
            onChange={(signups: Signups) => set({ signups })}
            options={[
              { value: 'off', label: t('Niemand – nur bestehende Konten') },
              { value: 'invitation', label: t('Nur mit Einladung oder über SCIM') },
              { value: 'group', label: t('Wer in der Nutzergruppe ist') },
            ]}
          />
        </SettingRow>
        <FormRow min="wide">
          <TextField
            label={t('Nutzergruppe (leer: alle, die der Anbieter durchlässt)')}
            value={draft.userGroup ?? ''}
            onChange={(value) => set({ userGroup: group(value) })}
            placeholder="vault-users"
          />
          <TextField
            label={t('Admin-Gruppe (leer: Admins bleiben, wie sie sind)')}
            value={draft.adminGroup ?? ''}
            onChange={(value) => set({ adminGroup: group(value) })}
            placeholder="vault-admins"
          />
        </FormRow>
        <FormRow min="wide">
          <TextField
            label={t('Claim mit den Gruppen')}
            hint={t('Das Feld im Token des Anbieters, in dem die Gruppen stehen.')}
            value={draft.groupsClaim}
            onChange={(groupsClaim) => set({ groupsClaim })}
            spellCheck={false}
          />
          <TextField
            label={t('Claim mit den Rollen (statt der Gruppen)')}
            value={draft.rolesClaim ?? ''}
            onChange={(value) => set({ rolesClaim: group(value) })}
            placeholder="roles"
            spellCheck={false}
          />
        </FormRow>
      </Section>
      <DangerZone
        heading={t('Strenge Regeln')}
        lead={t(
          'Sie können Leute aussperren: erst einschalten, wenn die Anmeldung über SSO sicher klappt.',
        )}
      >
        <SettingRow
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
        </SettingRow>
        <SettingRow
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
        </SettingRow>
        <SettingRow
          label={t('Unbestätigten Adressen trauen')}
          description={
            <Explain recommended={t('aus')}>
              {t(
                'Sonst findet und verknüpft eine Anmeldung ein Konto nur über eine Adresse, die der Anbieter als bestätigt meldet (email_verified).',
              )}
            </Explain>
          }
        >
          <Toggle
            label={t('Unbestätigten Adressen trauen')}
            checked={draft.trustUnverifiedEmail}
            onChange={(trustUnverifiedEmail) => set({ trustUnverifiedEmail })}
          />
        </SettingRow>
      </DangerZone>
      <SsoActions />
    </>
  );
}

/** *Sicherheit → SCIM*: the provider disables and removes accounts; its token. */
export function ScimTab() {
  useLanguage();
  const { current, setCurrent, run, busy, result } = useSso();
  const [scimToken, setScimToken] = useState<string | null>(null);
  if (!current) return <ResultLine result={result} />;
  return (
    <Section
      heading={t('Konten vom Anbieter verwalten lassen (SCIM)')}
      lead={t(
        'Darüber sperrt oder entfernt der Anbieter Konten und legt Adressen an, die sich anmelden dürfen. Adresse: {url}',
        { url: current.scimUrl ?? '' },
      )}
    >
      <SettingRow
        label={t('Wenn der Anbieter jemanden löscht')}
        description={
          <Explain recommended={t('Konto sperren')}>
            {t(
              'Sperren lässt den Tresor da (ein Admin kann ihn wieder freigeben); Löschen löscht Konto und Tresor. Das letzte Admin-Konto bleibt immer.',
            )}
          </Explain>
        }
      >
        <Select
          label={t('Wenn der Anbieter jemanden löscht')}
          value={current.scimOnDelete ?? 'disable'}
          onChange={(value: 'disable' | 'delete') =>
            void run(async () => {
              await saveScimOnDelete(value);
              setCurrent({ ...current, scimOnDelete: value });
              return t('Gespeichert ✧');
            })
          }
          disabled={busy}
          options={[
            { value: 'disable', label: t('Konto sperren') },
            { value: 'delete', label: t('Konto und Tresor löschen') },
          ]}
        />
      </SettingRow>
      <SettingRow
        label={t('SCIM-Token')}
        description={
          current.scimTokenSet
            ? t('Es gibt eines. Ein neues ersetzt es.')
            : t('Noch keines. Beim Koppeln mit UwUAuth kommt es von selbst.')
        }
      >
        <Button
          onClick={() =>
            void run(async () => {
              const made = await newScimToken();
              setScimToken(made.token);
              setCurrent({ ...current, scimTokenSet: true });
              return null;
            })
          }
          disabled={busy}
        >
          {current.scimTokenSet ? t('Neues Token') : t('Token erzeugen')}
        </Button>
      </SettingRow>
      {scimToken && (
        <Callout
          tone="accent"
          title={t('Das Token – nur jetzt zu sehen:')}
          actions={
            <Button size="small" icon="copy" onClick={() => void copyGenerated(scimToken)}>
              {t('Kopieren')}
            </Button>
          }
        >
          <code className="send-link">{scimToken}</code>
        </Callout>
      )}
      <ResultLine result={result} />
    </Section>
  );
}
