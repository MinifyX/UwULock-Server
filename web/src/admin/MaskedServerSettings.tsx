import { useState } from 'react';
import { Icon } from '../components/Icon';
import { checkMaskedServer, type MaskedServerCheck, type Settings } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';

type Props = { draft: Settings; setDraft: (next: Settings) => void };

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
export function MaskedServerSettings({ draft, setDraft }: Props) {
  useLanguage();
  const servers: Server[] = draft.masked?.servers ?? [];
  const [checks, setChecks] = useState<
    Record<number, { busy: boolean; text: string; ok: boolean }>
  >({});
  const set = (next: Server[]) => {
    setDraft({ ...draft, masked: { ...draft.masked, servers: next } });
    setChecks({});
  };

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
    <>
      <h2 className="settings-heading">{t('Maskierte Adressen (UwUMail)')}</h2>
      <p className="settings-lead">
        {t(
          'Mit diesen UwUMail-Servern dürfen Konten sich verbinden, um für jede Website eine eigene Mail-Adresse anzulegen – auch aus den Bitwarden-Apps heraus. Mit anderen spricht dieser Server nicht. Leer: keine maskierten Adressen.',
        )}
      </p>
      {servers.map((server, index) => {
        const result = checks[index];
        return (
          <div className="channel-card" key={index}>
            <div className="field-grid wide">
              <label className="field">
                <span>{t('Adresse')}</span>
                <input
                  value={server.url}
                  spellCheck={false}
                  placeholder="https://mail.example.com"
                  onChange={(e) =>
                    set(servers.map((s, i) => (i === index ? { ...s, url: e.target.value } : s)))
                  }
                />
              </label>
              <label className="field">
                <span>{t('Name, wie ihn Nutzer sehen')}</span>
                <input
                  value={server.name}
                  maxLength={60}
                  placeholder="UwUMail"
                  onChange={(e) =>
                    set(servers.map((s, i) => (i === index ? { ...s, name: e.target.value } : s)))
                  }
                />
              </label>
            </div>
            {result && (
              <p className="channel-status" data-alarm={!result.ok || undefined} role="status">
                {result.text}
              </p>
            )}
            <div className="form-actions">
              <button
                type="button"
                disabled={!server.url.trim() || result?.busy}
                onClick={() => void check(index, server.url)}
              >
                {t('Prüfen')}
                <span className="sr-only">{server.url}</span>
              </button>
              <span className="spacer" />
              <button
                type="button"
                className="quiet danger-text"
                onClick={() => set(servers.filter((_, i) => i !== index))}
              >
                {t('Entfernen')}
                <span className="sr-only">{server.url}</span>
              </button>
            </div>
          </div>
        );
      })}
      <div className="form-actions">
        <button type="button" onClick={() => set([...servers, { url: '', name: '' }])}>
          <Icon name="plus" size={15} />
          {t('UwUMail-Server hinzufügen')}
        </button>
      </div>
      {servers.length > 0 && (
        <p className="field-hint">
          {t(
            'Prüfen geht auch vor dem Speichern. Erst nach dem Speichern können Konten sich verbinden.',
          )}
        </p>
      )}
    </>
  );
}
