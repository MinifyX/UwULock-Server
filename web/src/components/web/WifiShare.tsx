import { useEffect, useState } from 'react';
import { renderSVG } from 'uqr';
import { revealField } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { securityLabel } from '../../lib/items';
import { wifiQr, type WifiView } from '../../lib/wifi';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { Button, Callout, Masked } from '../ui';

/**
 * A Wi-Fi network as a QR code, for a phone to join it with its camera. The code is made here,
 * in the browser (uqr, MIT); nothing about the network leaves the page. The password is fetched
 * from the vault for the code and forgotten when the dialog closes.
 */
export function WifiShare({
  itemId,
  wifi,
  onClose,
}: {
  itemId: string;
  wifi: WifiView;
  onClose: () => void;
}) {
  useLanguage();
  const open = wifi.security === 'None';
  const passwordField = wifi.from.password;
  const needsPassword = !open && passwordField !== undefined && Boolean(wifi.password?.hasValue);
  const [password, setPassword] = useState<string | null>(needsPassword ? null : '');
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (!needsPassword) return;
    let stopped = false;
    revealField(itemId, `field:${passwordField}`).then(
      (value) => !stopped && setPassword(value),
      (e) => !stopped && setError(errorText(e)),
    );
    return () => {
      stopped = true;
    };
  }, [itemId, passwordField, needsPassword]);

  const code =
    password === null
      ? null
      : wifiQr({
          ssid: wifi.ssid,
          password,
          security: wifi.security,
          hidden: wifi.hidden,
          eap: wifi.eap,
          phase2: wifi.phase2,
          identity: wifi.identity,
          anonymous: wifi.anonymous,
        });

  return (
    <Modal
      title={t('WLAN teilen')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <Button variant="primary" data-autofocus onClick={onClose}>
            {t('Fertig')}
          </Button>
        </>
      }
    >
      <p className="dialog-lead">
        {open
          ? t('Mit der Kamera scannen, um „{ssid}“ beizutreten.', { ssid: wifi.ssid })
          : t(
              'Mit der Kamera scannen, um „{ssid}“ beizutreten. Wer den Code sieht, kennt das Passwort.',
              { ssid: wifi.ssid },
            )}
      </p>
      {error && <Callout tone="error">{error}</Callout>}
      {!wifi.ssid.trim() ? (
        <Callout tone="warning">
          {t('Ohne Netzwerknamen (SSID) gibt es keinen Code. Trag ihn im Eintrag ein.')}
        </Callout>
      ) : (
        code && (
          <div
            className="qr"
            role="img"
            aria-label={t('QR-Code für das WLAN {ssid}', { ssid: wifi.ssid })}
            data-wifi-qr
            dangerouslySetInnerHTML={{
              __html: renderSVG(code, { border: 2, whiteColor: '#ffffff', blackColor: '#1c1420' }),
            }}
          />
        )
      )}
      <dl className="wifi-share">
        <dt>{t('Netzwerkname (SSID)')}</dt>
        <dd className="mono">{wifi.ssid || '—'}</dd>
        <dt>{t('Sicherheit')}</dt>
        <dd>{t(securityLabel(wifi.security)) || '—'}</dd>
        {!open && (
          <>
            <dt>{t('Passwort')}</dt>
            <dd className="mono wifi-share-password">
              {password === null ? (
                <span>…</span>
              ) : shown ? (
                <span>{password || '—'}</span>
              ) : (
                <Masked />
              )}
              {password && (
                <button
                  type="button"
                  className="icon-button"
                  aria-pressed={shown}
                  aria-label={t('Passwort zeigen')}
                  title={shown ? t('Passwort verbergen') : t('Passwort zeigen')}
                  onClick={() => setShown(!shown)}
                >
                  <Icon name={shown ? 'eyeOff' : 'eye'} size={15} />
                </button>
              )}
            </dd>
          </>
        )}
      </dl>
    </Modal>
  );
}
