import { useCallback, useEffect, useState } from 'react';
import { listen } from '../../lib/events';
import { errorText } from '../../lib/errors';
import {
  answerRequest,
  pendingRequests,
  requestPhrase,
  type DeviceRequest,
} from '../../lib/features';
import { when } from '../../lib/format';
import { t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Modal } from '../Modal';

/** How often an open vault asks whether a device wants in. */
const EVERY = 20_000;

/**
 * A device that asks to log in with this one: shown with the phrase it shows too, so the person
 * can check it is theirs before letting it in.
 */
export function DeviceRequests({ email }: { email: string }) {
  useLanguage();
  const [asking, setAsking] = useState<{ request: DeviceRequest; phrase: string } | null>(null);
  const [answered, setAnswered] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const look = useCallback(async () => {
    if (asking || document.hidden) return;
    try {
      const next = (await pendingRequests()).find((request) => !answered.has(request.id));
      if (next) setAsking({ request: next, phrase: await requestPhrase(email, next.publicKey) });
    } catch {
      // Asked again soon.
    }
  }, [asking, answered, email]);

  useEffect(() => {
    void look();
    const timer = window.setInterval(() => void look(), EVERY);
    const onFocus = () => void look();
    window.addEventListener('focus', onFocus);
    // The hub says at once when a device asks; the timer is for when it is not connected.
    const stop = listen('auth-request', () => void look());
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', onFocus);
      void stop.then((unlisten) => unlisten());
    };
  }, [look]);

  if (!asking) return null;
  const answer = async (approve: boolean) => {
    setBusy(true);
    try {
      await answerRequest(asking.request.id, asking.request.publicKey, approve);
      toast(approve ? t('Das Gerät ist jetzt angemeldet ✧') : t('Abgelehnt.'));
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setAnswered((done) => new Set(done).add(asking.request.id));
      setAsking(null);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Ein Gerät möchte sich anmelden')}
      tone="warning"
      onCancel={() => {
        // Not now: this tab leaves it alone; another device can still answer it.
        setAnswered((done) => new Set(done).add(asking.request.id));
        setAsking(null);
      }}
      footer={
        <>
          <button className="danger" disabled={busy} onClick={() => void answer(false)}>
            {t('Ablehnen')}
          </button>
          <span className="spacer" />
          <button className="primary" disabled={busy} onClick={() => void answer(true)}>
            {t('Anmelden lassen')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t(
          '{device} von {ip}, {when}. Lass es nur herein, wenn es deins ist und dort derselbe Satz steht:',
          {
            device: asking.request.requestDeviceType,
            ip: asking.request.requestIpAddress,
            when: when(asking.request.creationDate) ?? '',
          },
        )}
      </p>
      <p className="fingerprint">{asking.phrase}</p>
    </Modal>
  );
}
