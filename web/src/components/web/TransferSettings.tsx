import { useRef, useState } from 'react';
import { exportVault, importVault } from '../../lib/account';
import { syncNow } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { PasswordPrompt, ResultLine, Row, Segmented, save, type Result } from './controls';

/**
 * In and out, in Bitwarden's formats: its JSON (everything) and its CSV (logins and notes).
 * An export is not encrypted — it holds every password in plain text.
 */
export function TransferSettings() {
  useLanguage();
  const [format, setFormat] = useState<'json' | 'csv'>('json');
  const [exporting, setExporting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const file = useRef<HTMLInputElement>(null);

  const pick = async (chosen: File | undefined) => {
    if (!chosen) return;
    setBusy(true);
    setResult(null);
    try {
      const text = await chosen.text();
      const kind = chosen.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
      const count = await importVault(kind, text);
      await syncNow();
      setResult({ tone: 'info', text: t('{n} Einträge importiert ✧', { n: count }) });
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
      if (file.current) file.current.value = '';
    }
  };

  return (
    <>
      <Row
        label={t('Importieren')}
        description={t(
          'Aus einem Export von Bitwarden, Vaultwarden oder UwULock: JSON (unverschlüsselt) oder CSV. Ordner kommen mit.',
        )}
      >
        <input
          ref={file}
          type="file"
          accept=".json,.csv,application/json,text/csv"
          hidden
          onChange={(e) => void pick(e.target.files?.[0])}
        />
        <button onClick={() => file.current?.click()} disabled={busy}>
          {busy ? t('Importiert …') : t('Datei wählen …')}
        </button>
      </Row>
      <Row
        label={t('Exportieren')}
        description={t(
          'JSON enthält alles, CSV nur Logins und Notizen. Die Datei ist nicht verschlüsselt: Lösch sie, sobald du sie nicht mehr brauchst.',
        )}
      >
        <Segmented
          label={t('Format')}
          value={format}
          onChange={setFormat}
          options={[
            { value: 'json', label: 'JSON' },
            { value: 'csv', label: 'CSV' },
          ]}
        />
        <button onClick={() => setExporting(true)}>{t('Exportieren …')}</button>
      </Row>
      <ResultLine result={result} />
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
            setExporting(false);
          }}
        />
      )}
    </>
  );
}
