import { useState } from 'react';
import { exportVault } from '../../lib/account';
import { t, useLanguage } from '../../lib/i18n';
import { reportExport } from '../../lib/notices';
import { Button, Segmented, SettingRow } from '@uwusuite/design';
import { PasswordPrompt, save } from './controls';
import { ImportSettings } from './ImportSettings';

/**
 * In and out. In: from Bitwarden's formats and from other password managers (ImportSettings).
 * Out: Bitwarden's JSON (everything) and its CSV (logins and notes). An export is not
 * encrypted — it holds every password in plain text.
 */
export function TransferSettings() {
  useLanguage();
  const [format, setFormat] = useState<'json' | 'csv'>('json');
  const [exporting, setExporting] = useState(false);

  return (
    <>
      <ImportSettings />
      <SettingRow
        label={t('Exportieren')}
        description={t(
          'JSON enthält alles, CSV nur Logins und Notizen. Die Datei ist nicht verschlüsselt: Lösch sie, sobald du sie nicht mehr brauchst.',
        )}
      >
        <div className="flex flex-wrap items-center gap-2">
          <Segmented
            label={t('Format')}
            value={format}
            onChange={setFormat}
            options={[
              { value: 'json', label: 'JSON' },
              { value: 'csv', label: 'CSV' },
            ]}
          />
          <Button onClick={() => setExporting(true)}>{t('Exportieren …')}</Button>
        </div>
      </SettingRow>
      {exporting && (
        <PasswordPrompt
          title={t('Tresor exportieren?')}
          tone="warning"
          lead={t('Die Datei enthält jedes Passwort im Klartext.')}
          confirm={t('Exportieren')}
          onCancel={() => setExporting(false)}
          action={async (password) => {
            const blob = await exportVault(format, password);
            const day = new Date().toISOString().slice(0, 10);
            save(blob, `uwulock-export-${day}.${format}`);
            // A security notice for the account, and a mail: an export holds every password.
            reportExport(format);
            setExporting(false);
          }}
        />
      )}
    </>
  );
}
