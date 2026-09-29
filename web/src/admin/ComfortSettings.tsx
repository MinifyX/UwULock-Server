import { useEffect, useState } from 'react';
import { ResultLine, Row, Toggle, type Result } from '../components/web/controls';
import {
  clearIconCache,
  iconStatus,
  refreshIconLibrary,
  type IconStatus,
  type Settings,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { useSwitch } from '../lib/switches';

type Props = { draft: Settings; setDraft: (next: Settings) => void };

/** Earlier versions of items, and icons: what the server keeps and fetches for the vault. */
export function ComfortSettings({ draft, setDraft }: Props) {
  useLanguage();
  const [status, setStatus] = useState<IconStatus | null>(null);
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);
  // Versions and the icon library are feature switches (the Features tab); switched off, their
  // settings wait here unseen.
  const versionsOn = useSwitch('versions');
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

  const versions = draft.versions;
  const icons = draft.icons;
  return (
    <>
      {versionsOn && (
        <>
          <h2 className="settings-heading">{t('Versionen von Einträgen')}</h2>
          <p className="settings-lead">
            {t(
              'Bei jeder Änderung hebt der Server den Stand davor auf, verschlüsselt wie der Eintrag. Zählt zum Speicher des Kontos.',
            )}
          </p>
          <Row label={t('Versionen pro Eintrag')} description={t('0 schaltet Versionen aus.')}>
            <input
              type="number"
              min={0}
              max={100}
              className="narrow-number"
              aria-label={t('Versionen pro Eintrag')}
              value={versions.perItem}
              onChange={(e) =>
                setDraft({ ...draft, versions: { ...versions, perItem: Number(e.target.value) } })
              }
            />
          </Row>
          <Row label={t('Aufheben für Tage')} description={t('0: ohne Grenze.')}>
            <input
              type="number"
              min={0}
              max={3650}
              className="narrow-number"
              aria-label={t('Aufheben für Tage')}
              value={versions.days}
              onChange={(e) =>
                setDraft({ ...draft, versions: { ...versions, days: Number(e.target.value) } })
              }
            />
          </Row>
        </>
      )}

      <h2 className="settings-heading">{t('Icons')}</h2>
      <Row
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
      </Row>
      {libraryOn && (
        <Row
          label={t('Icon-Bibliothek')}
          description={t(
            'selfh.st Icons (CC BY 4.0): der Server spiegelt den Index, die Suche läuft im Tresor.',
          )}
        >
          <Toggle
            label={t('Icon-Bibliothek')}
            checked={icons.library}
            onChange={(library) => setDraft({ ...draft, icons: { ...icons, library } })}
          />
        </Row>
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
      <div className="comfort-actions">
        <button
          type="button"
          className="quiet"
          disabled={busy}
          onClick={() => void act(clearIconCache, t('Cache geleert.'))}
        >
          {t('Icon-Cache leeren')}
        </button>
        {libraryOn && (
          <button
            type="button"
            className="quiet"
            disabled={busy || !icons.library}
            onClick={() =>
              void act(refreshIconLibrary, t('Die Bibliothek wird im Hintergrund neu geladen.'))
            }
          >
            {t('Bibliothek neu laden')}
          </button>
        )}
      </div>
      <ResultLine result={result} />
    </>
  );
}
