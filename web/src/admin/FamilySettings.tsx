import { Section, Select, SettingRow } from '../components/ui';
import type { OrgRules } from '../lib/admin';
import { t, useLanguage } from '../lib/i18n';
import { SettingsTab } from './draft';
import { Explain, NumberInput } from './fields';

/** Families (§16.4): who may make one, how many members it has, how many one account owns. */
export function FamilySettings() {
  useLanguage();
  return (
    <SettingsTab>
      {({ draft, setDraft }) => {
        const rules = draft.families;
        const set = (next: Partial<OrgRules>) =>
          setDraft({ ...draft, families: { ...rules, ...next } });
        return (
          <Section
            heading={t('Regeln für Familien')}
            lead={t(
              'Eine Familie teilt Einträge in Sammlungen, mit Lese- oder Schreibrecht pro Mitglied – wie Bitwardens „Families“, auch in den offiziellen Apps. Neue Leute kommen über Einladungen dazu.',
            )}
          >
            <SettingRow
              label={t('Wer darf eine Familie anlegen')}
              description={t('Wer keine anlegen darf, kann trotzdem in eine eingeladen werden.')}
            >
              <Select
                label={t('Wer darf eine Familie anlegen')}
                value={rules.whoMayCreate}
                onChange={(whoMayCreate) => set({ whoMayCreate })}
                options={[
                  { value: 'everyone', label: t('Alle') },
                  { value: 'admins', label: t('Nur Admins') },
                  { value: 'nobody', label: t('Niemand') },
                ]}
              />
            </SettingRow>
            <SettingRow
              label={t('Mitglieder pro Familie')}
              description={
                <Explain recommended="6">{t('Eingeladene zählen mit. Bitwarden hat 6.')}</Explain>
              }
            >
              <NumberInput
                label={t('Mitglieder pro Familie')}
                min={2}
                max={50}
                value={rules.maxMembers}
                onChange={(maxMembers) => set({ maxMembers: maxMembers ?? 0 })}
              />
            </SettingRow>
            <SettingRow
              label={t('Familien pro Konto')}
              description={t('Wie viele ein Konto besitzen darf.')}
            >
              <NumberInput
                label={t('Familien pro Konto')}
                min={0}
                max={10}
                value={rules.perUser}
                onChange={(perUser) => set({ perUser: perUser ?? 0 })}
              />
            </SettingRow>
          </Section>
        );
      }}
    </SettingsTab>
  );
}
