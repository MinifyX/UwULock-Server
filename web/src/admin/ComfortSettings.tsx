import { useEffect, useState } from 'react';
import { Button, ButtonRow, Section, SettingRow, Toggle } from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import { clearIconCache, iconStatus, refreshIconLibrary, type IconStatus } from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { useSwitch } from '../lib/switches';
import { SettingsTab } from './draft';
import { Explain } from './fields';
import { IconDatabases } from './IconDatabases';

/**
 * *Tresor → Icons & Passwortprüfung*: what the server fetches or looks up for the vault — the
 * websites' icons, the icon library and databases, and the check against Have I Been Pwned.
 */
export function ComfortSettings() {
  useLanguage();
  const [status, setStatus] = useState<IconStatus | null>(null);
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);
  // The icon library is a feature switch (the Features tab); switched off, its setting waits
  // here unseen.
  const libraryOn = useSwitch('icon-library');
  const load = () => iconStatus().then(setStatus, () => setStatus(null));
  useEffect(() => {
    void load();
  }, []);

  const act = async (work: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setResult(null);
    try {
      await work();
      setResult({ tone: 'info', text: done });
      await load();
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsTab>
      {({ draft, setDraft }) => {
        const icons = draft.icons;
        return (
          <>
            <Section
              heading={t('Website-Icons')}
              lead={t('Die kleinen Logos neben den Einträgen im Tresor und in den Apps.')}
            >
              <SettingRow
                label={t('Website-Icons holen')}
                description={t(
                  'Der Server holt die Icons der Websites selbst und liefert sie an den Web-Tresor und die Apps; die Websites sehen nur die Adresse des Servers. Adressen im lokalen Netz fragt er nie. Dafür erfährt der Server, welche Websites in den Tresoren stehen (wie bei Bitwarden), und wer viele Adressen durchprobiert, kann ungefähr sehen, welche schon einmal gefragt wurden.',
                )}
              >
                <Toggle
                  label={t('Website-Icons holen')}
                  checked={icons.automatic}
                  onChange={(automatic) => setDraft({ ...draft, icons: { ...icons, automatic } })}
                />
              </SettingRow>
              {libraryOn && (
                <SettingRow
                  label={t('Icon-Bibliothek')}
                  description={t(
                    'selfh.st Icons (CC BY 4.0) und Dashboard Icons: der Server spiegelt den Index von selfh.st, die Suche läuft im Tresor.',
                  )}
                >
                  <Toggle
                    label={t('Icon-Bibliothek')}
                    checked={icons.library}
                    onChange={(library) => setDraft({ ...draft, icons: { ...icons, library } })}
                  />
                </SettingRow>
              )}
              {status && (
                <p className="field-hint">
                  {t(
                    '{n} Websites im Cache ({size}, höchstens {max}; darüber gehen die ältesten), eigene Icons {own}.',
                    {
                      n: status.cached,
                      size: bytes(status.cacheBytes),
                      max: bytes(status.cacheMaxBytes),
                      own: bytes(status.ownBytes),
                    },
                  )}{' '}
                  {libraryOn &&
                    (status.libraryUpdated
                      ? t('Bibliothek: {n} Icons, Stand {when}.', {
                          n: status.libraryIcons,
                          when: when(status.libraryUpdated) ?? '',
                        })
                      : t('Die Bibliothek ist noch nicht geladen.'))}
                </p>
              )}
              <ButtonRow>
                <Button
                  variant="quiet"
                  disabled={busy}
                  onClick={() => void act(clearIconCache, t('Cache geleert.'))}
                >
                  {t('Icon-Cache leeren')}
                </Button>
                {libraryOn && (
                  <Button
                    variant="quiet"
                    disabled={busy || !icons.library}
                    onClick={() =>
                      void act(
                        refreshIconLibrary,
                        t('Die Bibliothek wird im Hintergrund neu geladen.'),
                      )
                    }
                  >
                    {t('Bibliothek neu laden')}
                  </Button>
                )}
              </ButtonRow>
              <ResultLine result={result} />
            </Section>
            <IconDatabases draft={draft} setDraft={setDraft} status={status} />
            <Section
              heading={t('Passwörter in Datenlecks')}
              lead={t(
                'Die Passwortprüfung im Tresor sagt, welche Passwörter schon in einem Datenleck aufgetaucht sind.',
              )}
            >
              <SettingRow
                label={t('Datenlecks prüfen')}
                description={
                  <Explain recommended={t('an')}>
                    {t(
                      'Fragt Have I Been Pwned über diesen Server – nur die ersten fünf Zeichen eines Hashes verlassen ihn, nie ein Passwort.',
                    )}
                  </Explain>
                }
              >
                <Toggle
                  label={t('Datenlecks prüfen')}
                  checked={draft.hibp}
                  onChange={(hibp) => setDraft({ ...draft, hibp })}
                />
              </SettingRow>
            </Section>
          </>
        );
      }}
    </SettingsTab>
  );
}
