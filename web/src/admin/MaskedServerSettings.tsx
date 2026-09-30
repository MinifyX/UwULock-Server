import { useState } from 'react';
import { Button, ButtonRow, Card, FormRow, Section, TextField } from '../components/ui';
import { checkMaskedServer, type MaskedServerCheck } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { SettingsTab } from './draft';

type Server = { url: string; name: string };

/** What a check found, in one line. */
function checkText(check: MaskedServerCheck): string {
  if (check.discovery && check.maskedScope && check.registration)
    return t('In Ordnung ✧ Konten können sich damit verbinden.');
  if (!check.discovery)
    return t('Keine OAuth-Beschreibung unter /.well-known/oauth-authorization-server gefunden.');
  if (!check.maskedScope)
    return t('Der Server kennt den Scope „maskedemail“ nicht. Braucht es ein neueres UwUMail?');
  return check.error
    ? t('Anmelden bei UwUMail hat nicht geklappt: {error}', { error: check.error })
    : t('Anmelden bei UwUMail hat nicht geklappt.');
}

/**
 * The UwUMail servers accounts may connect for masked addresses (§13, §21.8). This server talks
 * only to these, and they may be on private addresses: the admin trusts them.
 */
export function MaskedServerSettings() {
  useLanguage();
  const [checks, setChecks] = useState<
    Record<number, { busy: boolean; text: string; ok: boolean }>
  >({});

  const check = async (index: number, url: string) => {
    setChecks((all) => ({ ...all, [index]: { busy: true, text: t('Einen Moment …'), ok: true } }));
    try {
      const found = await checkMaskedServer(url.trim());
      const ok = found.discovery && found.maskedScope && found.registration;
      setChecks((all) => ({ ...all, [index]: { busy: false, text: checkText(found), ok } }));
    } catch (e) {
      setChecks((all) => ({ ...all, [index]: { busy: false, text: errorText(e), ok: false } }));
    }
  };

  return (
    <SettingsTab>
      {({ draft, setDraft }) => {
        const servers: Server[] = draft.masked?.servers ?? [];
        const set = (next: Server[]) => {
          setDraft({ ...draft, masked: { ...draft.masked, servers: next } });
          setChecks({});
        };
        return (
          <Section
            heading={t('UwUMail-Server für maskierte Adressen')}
            lead={t(
              'Mit diesen UwUMail-Servern dürfen Konten sich verbinden, um für jede Website eine eigene Mail-Adresse anzulegen – auch aus den Bitwarden-Apps heraus. Mit anderen spricht dieser Server nicht. Leer: keine maskierten Adressen.',
            )}
          >
            <div className="card-list">
              {servers.map((server, index) => {
                const result = checks[index];
                return (
                  <Card key={index} className="channel-card">
                    <FormRow min="wide">
                      <TextField
                        label={t('Adresse')}
                        value={server.url}
                        spellCheck={false}
                        placeholder="https://mail.example.com"
                        onChange={(url) =>
                          set(servers.map((s, i) => (i === index ? { ...s, url } : s)))
                        }
                      />
                      <TextField
                        label={t('Name, wie ihn Nutzer sehen')}
                        value={server.name}
                        maxLength={60}
                        placeholder="UwUMail"
                        onChange={(name) =>
                          set(servers.map((s, i) => (i === index ? { ...s, name } : s)))
                        }
                      />
                    </FormRow>
                    {result && (
                      <p
                        className="channel-status"
                        data-alarm={!result.ok || undefined}
                        role="status"
                      >
                        {result.text}
                      </p>
                    )}
                    <ButtonRow>
                      <Button
                        size="small"
                        disabled={!server.url.trim() || result?.busy}
                        onClick={() => void check(index, server.url)}
                      >
                        {t('Prüfen')}
                        <span className="sr-only">{server.url}</span>
                      </Button>
                      <span className="spacer" />
                      <Button
                        size="small"
                        variant="quiet-danger"
                        onClick={() => set(servers.filter((_, i) => i !== index))}
                      >
                        {t('Entfernen')}
                        <span className="sr-only">{server.url}</span>
                      </Button>
                    </ButtonRow>
                  </Card>
                );
              })}
            </div>
            <ButtonRow>
              <Button icon="plus" onClick={() => set([...servers, { url: '', name: '' }])}>
                {t('UwUMail-Server hinzufügen')}
              </Button>
            </ButtonRow>
            {servers.length > 0 && (
              <p className="field-hint">
                {t(
                  'Prüfen geht auch vor dem Speichern. Erst nach dem Speichern können Konten sich verbinden.',
                )}
              </p>
            )}
          </Section>
        );
      }}
    </SettingsTab>
  );
}
