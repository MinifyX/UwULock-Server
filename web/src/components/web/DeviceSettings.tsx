import { useCallback, useEffect, useState } from 'react';
import {
  deleteSuiteSpace,
  devices,
  forgetDevice,
  suiteSpaces,
  type Device,
  type SuiteSpace,
} from '../../lib/account';
import { logout } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { ago, bytes } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { suiteAppName } from '../../lib/notices';
import { Icon, type IconName } from '../Icon';
import { PasswordPrompt, ResultLine, type Result } from './controls';

function iconOf(type: number, app: string | null): IconName {
  if (app) return 'terminal';
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
            <Icon name={iconOf(device.type, device.app)} size={20} />
            <span className="device-text">
              <b>
                {device.name}{' '}
                <small>· {device.app ? suiteAppName(device.app) : device.typeName}</small>
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
      <SuiteSpaces />
    </>
  );
}

/** A suite space by its name (docs/suite.md): whose records it holds. */
function spaceName(space: string): string {
  const apps: Record<string, string> = { ssh: 'uwussh', rdp: 'uwurdp', mail: 'uwumail' };
  return apps[space] ? suiteAppName(apps[space]) : t('Andere UwU-Apps');
}

/**
 * The suite vault's spaces: what UwUSSH and UwURDP keep here. Only the apps can open the records;
 * the account can see how much there is and delete a space. Hidden while it has none, or while
 * the admin switched the suite vault off.
 */
function SuiteSpaces() {
  useLanguage();
  const [spaces, setSpaces] = useState<SuiteSpace[]>([]);
  const [deleting, setDeleting] = useState<SuiteSpace | null>(null);
  const [result, setResult] = useState<Result>(null);
  const load = useCallback(() => {
    suiteSpaces().then(setSpaces, () => setSpaces([]));
  }, []);
  useEffect(load, [load]);
  if (spaces.length === 0) return <ResultLine result={result} />;

  return (
    <>
      <h3 className="settings-heading">{t('Suite-Tresor')}</h3>
      <p className="settings-lead">
        {t(
          'Was UwUSSH und UwURDP hier speichern; ansehen und bearbeiten kannst du es in der Seitenleiste unter UwU-Apps. Hier siehst du, wie viel es ist.',
        )}
      </p>
      <ResultLine result={result} />
      <ul className="device-list">
        {spaces.map((space) => (
          <li key={space.space} className="device">
            <Icon name="terminal" size={20} />
            <span className="device-text">
              <b>{spaceName(space.space)}</b>
              <small>
                {t('{count} Einträge · {size}', {
                  count: space.records,
                  size: bytes(space.bytes),
                })}
                {' · '}
                {t('Zuletzt {when}', { when: ago(Date.parse(space.revisionDate) / 1000) })}
              </small>
            </span>
            <button className="danger" onClick={() => setDeleting(space)}>
              {t('Löschen')}
            </button>
          </li>
        ))}
      </ul>
      {deleting && (
        <PasswordPrompt
          title={t('{name} im Suite-Tresor löschen?', { name: spaceName(deleting.space) })}
          lead={t(
            'Alle {count} Einträge sind danach vom Server fort, für jedes Gerät. Lösche den Bereich nur, wenn die App sie nicht mehr braucht.',
            { count: deleting.records },
          )}
          confirm={t('Löschen')}
          tone="warning"
          onCancel={() => setDeleting(null)}
          action={async (password) => {
            await deleteSuiteSpace(deleting.space, password);
            setResult({
              tone: 'info',
              text: t('{name} ist gelöscht.', { name: spaceName(deleting.space) }),
            });
            setDeleting(null);
            load();
          }}
        />
      )}
    </>
  );
}
