import { useState } from 'react';
import pkg from '../../package.json';
import { lock, openProjectPage, type ProjectPage, type Status } from '../lib/api';
import { type AccountInfo } from '../lib/account';
import { N_, t, useLanguage } from '../lib/i18n';
import { updateSettings, useSettings, type AutoLock, type ClipboardClear } from '../lib/settings';
import { Modal } from './Modal';
import { Nyu } from './nyu/Nyu';
import { AccountSettings } from './web/AccountSettings';
import { Row, Segmented, Toggle } from './web/controls';
import { DeviceSettings } from './web/DeviceSettings';
import { TransferSettings } from './web/TransferSettings';
import { TwoFactorSettings } from './web/TwoFactorSettings';

export type SettingsSection =
  'appearance' | 'security' | 'account' | 'two-factor' | 'devices' | 'transfer' | 'about';

const SECTIONS: { id: SettingsSection; label: string; needsLogin: boolean }[] = [
  { id: 'appearance', label: N_('Darstellung'), needsLogin: false },
  { id: 'security', label: N_('Sicherheit'), needsLogin: true },
  { id: 'account', label: N_('Konto'), needsLogin: true },
  { id: 'two-factor', label: N_('Zwei-Schritt-Anmeldung'), needsLogin: true },
  { id: 'devices', label: N_('Geräte'), needsLogin: true },
  { id: 'transfer', label: N_('Import & Export'), needsLogin: true },
  { id: 'about', label: N_('Über UwULock'), needsLogin: false },
];

type Props = {
  initial?: SettingsSection;
  status: Status;
  info: AccountInfo | null;
  onInfo: (info: AccountInfo | null) => void;
  onClose: () => void;
};

function Appearance() {
  const settings = useSettings();
  return (
    <>
      <Row
        label="Sprache · Language"
        description="„System“ folgt der Sprache des Browsers. · “System” follows the browser."
      >
        <Segmented
          label="Sprache · Language"
          value={settings.language}
          onChange={(language) => updateSettings({ language })}
          options={[
            { value: 'system', label: 'System' },
            { value: 'de', label: 'Deutsch' },
            { value: 'en', label: 'English' },
          ]}
        />
      </Row>
      <Row label={t('Farbschema')}>
        <Segmented
          label={t('Farbschema')}
          value={settings.theme}
          onChange={(theme) => updateSettings({ theme })}
          options={[
            { value: 'system', label: t('System') },
            { value: 'light', label: t('Hell') },
            { value: 'dark', label: t('Dunkel') },
          ]}
        />
      </Row>
      <Row label={t('Animationen')} description={t('„System“ folgt der Einstellung des Systems.')}>
        <Segmented
          label={t('Animationen')}
          value={settings.motion}
          onChange={(motion) => updateSettings({ motion })}
          options={[
            { value: 'system', label: t('System') },
            { value: 'on', label: t('An') },
            { value: 'off', label: t('Aus') },
          ]}
        />
      </Row>
      <Row
        label={t('Papierkorb zeigen')}
        description={t('Gelöschte Einträge in einem eigenen Bereich der Seitenleiste.')}
      >
        <Toggle
          label={t('Papierkorb zeigen')}
          checked={settings.showTrash}
          onChange={(showTrash) => updateSettings({ showTrash })}
        />
      </Row>
    </>
  );
}

function Security({ onClose }: { onClose: () => void }) {
  const settings = useSettings();
  const minutes = (n: number) => (n === 1 ? t('1 Minute') : t('{n} Minuten', { n }));
  return (
    <>
      <Row
        label={t('Automatisch sperren')}
        description={t(
          'Nach so langer Zeit ohne Eingabe sperrt UwULock den Tresor und vergisst alles Entschlüsselte. Beim Neuladen oder Schließen des Tabs ist er immer gesperrt.',
        )}
      >
        <select
          className="select"
          value={settings.autoLock}
          aria-label={t('Automatisch sperren')}
          onChange={(e) => updateSettings({ autoLock: Number(e.target.value) as AutoLock })}
        >
          {([1, 5, 15, 30, 60, 240] as const).map((n) => (
            <option key={n} value={n}>
              {n < 60 ? minutes(n) : n === 60 ? t('1 Stunde') : t('{n} Stunden', { n: n / 60 })}
            </option>
          ))}
          <option value={0}>{t('Nie (nur beim Schließen des Tabs)')}</option>
        </select>
      </Row>
      <Row
        label={t('Zwischenablage leeren')}
        description={t(
          'Kopierte Werte verschwinden danach wieder, solange der Tab offen ist – aber nur, wenn inzwischen nichts anderes kopiert wurde.',
        )}
      >
        <select
          className="select"
          value={settings.clipboardClear}
          aria-label={t('Zwischenablage leeren')}
          onChange={(e) =>
            updateSettings({ clipboardClear: Number(e.target.value) as ClipboardClear })
          }
        >
          {([10, 30, 60, 120] as const).map((n) => (
            <option key={n} value={n}>
              {t('nach {n} Sekunden', { n })}
            </option>
          ))}
          <option value={0}>{t('Nie')}</option>
        </select>
      </Row>
      <Row label={t('Jetzt sperren')} description={t('Auch mit Strg+L.')}>
        <button
          onClick={() => {
            onClose();
            void lock();
          }}
        >
          {t('Sperren')}
        </button>
      </Row>
    </>
  );
}

function About() {
  useLanguage();
  const open = (page: ProjectPage) => void openProjectPage(page).catch(() => undefined);
  return (
    <div className="about">
      <Nyu size={88} mood="happy" title="Nyu" />
      <p className="about-name">
        <span>UwU</span>Lock
      </p>
      <p className="about-version">{t('Version {version}', { version: pkg.version })}</p>
      <p className="about-text">
        {t(
          'Der Web-Tresor von UwULock Server. Freie Software unter der GNU AGPL v3.0: Nutzen, ändern, weitergeben – geänderte Versionen bleiben offen, auch wenn sie nur als Dienst laufen. Kein Tracking.',
        )}
      </p>
      <p className="about-text">
        {t(
          'Spricht das Protokoll von Bitwarden und Vaultwarden, mit derselben Verschlüsselung wie die offiziellen Apps. Nicht verbunden mit Bitwarden Inc.',
        )}
      </p>
      <div className="about-actions">
        <button onClick={() => open('source')}>{t('Quellcode auf GitHub')}</button>
        <button onClick={() => open('releases')}>{t('Versionen')}</button>
        <button onClick={() => open('license')}>{t('Lizenz')}</button>
        <button onClick={() => open('suite')}>UwUSuite</button>
      </div>
    </div>
  );
}

export function SettingsDialog({ initial = 'appearance', status, info, onInfo, onClose }: Props) {
  useLanguage();
  const [section, setSection] = useState<SettingsSection>(initial);
  const loggedIn = status.state === 'unlocked';
  const sections = SECTIONS.filter((s) => loggedIn || !s.needsLogin);
  return (
    <Modal title={t('Einstellungen')} size="wide" onCancel={onClose}>
      <div className="settings">
        <nav className="settings-nav" aria-label={t('Bereiche')}>
          {sections.map(({ id, label }) => (
            <button
              key={id}
              type="button"
              aria-current={section === id ? 'page' : undefined}
              onClick={() => setSection(id)}
            >
              {t(label)}
            </button>
          ))}
        </nav>
        <div className="settings-content">
          {section === 'appearance' && <Appearance />}
          {section === 'security' && loggedIn && <Security onClose={onClose} />}
          {section === 'account' && loggedIn && (
            <AccountSettings status={status} info={info} onInfo={onInfo} onClose={onClose} />
          )}
          {section === 'two-factor' && loggedIn && (
            <TwoFactorSettings status={status} info={info} onInfo={onInfo} />
          )}
          {section === 'devices' && loggedIn && <DeviceSettings onClose={onClose} />}
          {section === 'transfer' && loggedIn && <TransferSettings />}
          {section === 'about' && <About />}
        </div>
      </div>
      <button className="settings-close icon-button" onClick={onClose} aria-label={t('Schließen')}>
        ×
      </button>
    </Modal>
  );
}
