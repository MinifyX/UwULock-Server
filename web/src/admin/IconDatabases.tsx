import { Section, SettingRow, Table, Toggle } from '../components/ui';
import type { IconDatabase, IconStatus, Settings } from '../lib/admin';
import { bytes } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';

type Props = {
  draft: Settings;
  setDraft: (next: Settings) => void;
  status: IconStatus | null;
};

/** The databases the server knows, in its order, with what each is for in plain words. */
const KNOWN: { id: string; name: string; what: string }[] = [
  {
    id: '2fa-directory',
    name: '2FA Directory',
    what: N_('Logos für Websites ohne eigenes Icon, nach ihrer Domain.'),
  },
  {
    id: 'simple-icons',
    name: 'Simple Icons',
    what: N_('Markenzeichen in der Farbe der Marke, wenn 2FA Directory die Website nicht kennt.'),
  },
  {
    id: 'dashboard-icons',
    name: 'Dashboard Icons',
    what: N_(
      'Logos selbst gehosteter Apps: für Geräte im Heimnetz nach ihrem Namen (etwa jellyfin.local) und in der Icon-Bibliothek.',
    ),
  },
];

/** selfh.st is mirrored, not bundled, but belongs in the same list of credits. */
const SELFHST = {
  name: 'selfh.st Icons',
  url: 'https://selfh.st/icons/',
  license: 'CC BY 4.0',
  licenseUrl: 'https://creativecommons.org/licenses/by/4.0/',
  attribution: 'Icons by selfh.st',
};

/**
 * The icon databases that come with the server: one switch each, and who made them under which
 * licence (docs/icons.md). Kept apart from the other icon settings.
 */
export function IconDatabases({ draft, setDraft, status }: Props) {
  useLanguage();
  const icons = draft.icons;
  const on = icons.databases ?? [];
  const known = new Map((status?.databases ?? []).map((database) => [database.id, database]));
  const set = (id: string, enabled: boolean) => {
    const databases = KNOWN.map((database) => database.id).filter((each) =>
      each === id ? enabled : on.includes(each),
    );
    setDraft({ ...draft, icons: { ...icons, databases } });
  };
  const credits: (Pick<IconDatabase, 'name' | 'url' | 'license' | 'licenseUrl' | 'attribution'> & {
    commit?: string;
  })[] = [...(status?.databases ?? []), SELFHST];

  return (
    <Section
      heading={t('Icon-Datenbanken')}
      lead={t(
        'Kommen mit dem Server und liegen in ihm: für Websites ohne eigenes Icon und für Geräte im Heimnetz. Nachgeschaut wird nur auf diesem Server, nichts wird dafür abgerufen.',
      )}
    >
      {KNOWN.map((database) => {
        const bundled = known.get(database.id);
        return (
          <SettingRow
            key={database.id}
            label={database.name}
            description={
              <>
                {t(database.what)}
                {bundled &&
                  ` ${t('{n} Icons, {size}.', { n: bundled.icons, size: bytes(bundled.bytes) })}`}
              </>
            }
          >
            <Toggle
              label={database.name}
              checked={on.includes(database.id)}
              disabled={!icons.automatic && database.id !== 'dashboard-icons'}
              onChange={(enabled) => set(database.id, enabled)}
            />
          </SettingRow>
        );
      })}
      <Table
        label={t('Herkunft und Lizenzen der Icons')}
        head={
          <>
            <th>{t('Quelle')}</th>
            <th>{t('Lizenz')}</th>
            <th>{t('Von')}</th>
          </>
        }
      >
        {credits.map((credit) => (
          <tr key={credit.name}>
            <td>
              <a href={credit.url} target="_blank" rel="noreferrer noopener">
                {credit.name}
              </a>
              {credit.commit && <span className="field-hint"> · {credit.commit.slice(0, 7)}</span>}
            </td>
            <td>
              <a href={credit.licenseUrl} target="_blank" rel="noreferrer noopener">
                {credit.license}
              </a>
            </td>
            <td>{credit.attribution}</td>
          </tr>
        ))}
      </Table>
      <p className="field-hint">
        {t(
          'Alle Logos sind Marken ihrer Inhaber. Die vollständigen Lizenztexte stehen in THIRD-PARTY-NOTICES.txt im Image und im Repository.',
        )}
      </p>
    </Section>
  );
}
