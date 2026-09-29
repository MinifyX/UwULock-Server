import { Row } from '../components/web/controls';
import type { OrgRules, Settings } from '../lib/admin';
import { t, useLanguage } from '../lib/i18n';

type Props = { draft: Settings; setDraft: (next: Settings) => void };

/** Families (§16.4): who may make one, how many members it has, how many one account owns. */
export function FamilySettings({ draft, setDraft }: Props) {
  useLanguage();
  const rules = draft.families;
  const set = (next: Partial<OrgRules>) => setDraft({ ...draft, families: { ...rules, ...next } });
  return (
    <>
      <h2 className="settings-heading">{t('Familien')}</h2>
      <p className="settings-lead">
        {t(
          'Eine Familie teilt Einträge in Sammlungen, mit Lese- oder Schreibrecht pro Mitglied – wie Bitwardens „Families“, auch in den offiziellen Apps. Neue Leute kommen über die Einladungsregeln oben dazu.',
        )}
      </p>
      <Row label={t('Wer darf eine Familie anlegen')}>
        <select
          className="select"
          aria-label={t('Wer darf eine Familie anlegen')}
          value={rules.whoMayCreate}
          onChange={(e) => set({ whoMayCreate: e.target.value as OrgRules['whoMayCreate'] })}
        >
          <option value="everyone">{t('Alle')}</option>
          <option value="admins">{t('Nur Admins')}</option>
          <option value="nobody">{t('Niemand')}</option>
        </select>
      </Row>
      <Row
        label={t('Mitglieder pro Familie')}
        description={t('Eingeladene zählen mit. Bitwarden hat 6.')}
      >
        <input
          type="number"
          min={2}
          max={50}
          className="narrow-number"
          aria-label={t('Mitglieder pro Familie')}
          value={rules.maxMembers}
          onChange={(e) => set({ maxMembers: Number(e.target.value) })}
        />
      </Row>
      <Row label={t('Familien pro Konto')} description={t('Wie viele ein Konto besitzen darf.')}>
        <input
          type="number"
          min={0}
          max={10}
          className="narrow-number"
          aria-label={t('Familien pro Konto')}
          value={rules.perUser}
          onChange={(e) => set({ perUser: Number(e.target.value) })}
        />
      </Row>
    </>
  );
}
