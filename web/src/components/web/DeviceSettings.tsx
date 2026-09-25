import { useCallback, useEffect, useState } from 'react';
import { devices, forgetDevice, type Device } from '../../lib/account';
import { logout } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { ago } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { Icon, type IconName } from '../Icon';
import { ResultLine, type Result } from './controls';

function iconOf(type: number): IconName {
  if (type <= 1 || type === 15) return 'grid';
  if ([2, 3, 4, 5, 19, 20].includes(type)) return 'layers';
  if ([6, 7, 8].includes(type)) return 'monitor';
  if (type >= 23 && type <= 25) return 'terminal';
  return 'globe';
}

/** Where the account is logged in: each browser extension, app, CLI and web vault tab. */
export function DeviceSettings({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [list, setList] = useState<Device[] | null>(null);
  const [result, setResult] = useState<Result>(null);
  const load = useCallback(() => {
    devices().then(setList, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <p className="settings-lead">
        {t(
          'Hier ist dein Konto angemeldet. Was du nicht kennst, meldest du ab – das Gerät muss sich dann neu anmelden.',
        )}
      </p>
      <ResultLine result={result} />
      <ul className="device-list">
        {list?.map((device) => (
          <li key={device.id} className="device">
            <Icon name={iconOf(device.type)} size={20} />
            <span className="device-text">
              <b>
                {device.name} <small>· {device.typeName}</small>
                {device.current && <span className="badge">{t('dieser Browser')}</span>}
              </b>
              <small>
                {t('Zuletzt {when}', {
                  when: ago(Date.parse(device.lastSeen) / 1000),
                })}
                {device.lastIp ? ` · ${device.lastIp}` : ''}
                {device.remembered ? ` · ${t('Zwei-Schritt-Anmeldung gemerkt')}` : ''}
              </small>
            </span>
            <button
              onClick={async () => {
                try {
                  if (device.current) {
                    onClose();
                    await logout();
                    return;
                  }
                  await forgetDevice(device.id);
                  setResult({
                    tone: 'info',
                    text: t('{name} ist abgemeldet.', { name: device.name }),
                  });
                  load();
                } catch (e) {
                  setResult({ tone: 'error', text: errorText(e) });
                }
              }}
            >
              {t('Abmelden')}
            </button>
          </li>
        ))}
        {list?.length === 0 && <li className="empty-note">{t('Keine Geräte.')}</li>}
      </ul>
    </>
  );
}
