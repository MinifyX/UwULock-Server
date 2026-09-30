import { useEffect, useState } from 'react';
import { Button, Callout, Modal, Section, SettingRow, Toggle } from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import { loadServerInfo } from '../lib/branding';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import {
  adminSwitches,
  saveSwitches,
  SWITCH_GROUPS,
  SWITCH_TEXTS,
  type SwitchId,
  type SwitchState,
} from '../lib/switches';

/**
 * The admin portal's "Features" tab: every extra of UwULock on or off, grouped, each with one
 * line anybody understands. The vault itself and everything Bitwarden's apps know are always
 * there; so are the website icons, which have their own switch under *Icons & Passwortprüfung*.
 */
export function Features() {
  useLanguage();
  const [list, setList] = useState<SwitchState[] | null>(null);
  const [busy, setBusy] = useState<SwitchId | null>(null);
  const [result, setResult] = useState<Result>(null);
  /** A feature in use, about to be switched off: asked first. */
  const [asking, setAsking] = useState<SwitchState | null>(null);

  useEffect(() => {
    adminSwitches().then(setList, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, []);

  const change = async (id: SwitchId, on: boolean) => {
    setBusy(id);
    setResult(null);
    try {
      setList(await saveSwitches({ [id]: on }));
      // The portal's own pages and the vault's info follow at once.
      await loadServerInfo(true);
      setResult({
        tone: 'info',
        text: on
          ? t('„{name}“ ist an ✧', { name: t(SWITCH_TEXTS[id].label) })
          : t('„{name}“ ist aus. Nichts wurde gelöscht.', { name: t(SWITCH_TEXTS[id].label) }),
      });
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(null);
    }
  };

  if (!list) return <ResultLine result={result} />;
  const byId = new Map(list.map((state) => [state.id, state]));

  return (
    <>
      <Callout>
        {t(
          'Der Tresor und alles, was die Bitwarden-Apps kennen, ist immer da. Was UwULock dazu kann, schaltest du hier an oder aus. Aus heißt: nicht zu sehen und nicht erreichbar – gelöscht wird nichts, und angeschaltet ist alles wieder da.',
        )}
      </Callout>
      <ResultLine result={result} />
      {SWITCH_GROUPS.map((group) => {
        const states = list.filter((state) => state.group === group.id);
        if (!states.length) return null;
        return (
          <Section key={group.id} heading={t(group.label)}>
            {states.map((state) => {
              const text = SWITCH_TEXTS[state.id];
              const needs = state.requires ? byId.get(state.requires) : null;
              const notes = [
                state.on && !state.works && needs
                  ? t('Wirkt erst, wenn auch „{name}“ an ist.', {
                      name: t(SWITCH_TEXTS[needs.id].label),
                    })
                  : null,
                state.inUse ? t('Wird benutzt oder ist eingerichtet.') : null,
              ].filter(Boolean);
              return (
                <SettingRow
                  key={state.id}
                  label={t(text.label)}
                  description={
                    <>
                      {t(text.description)}
                      {notes.length > 0 && (
                        <span data-feature-note={state.id}> {notes.join(' ')}</span>
                      )}
                    </>
                  }
                >
                  <Toggle
                    label={t(text.label)}
                    checked={state.on}
                    disabled={busy !== null}
                    onChange={(on) =>
                      !on && state.inUse ? setAsking(state) : void change(state.id, on)
                    }
                  />
                </SettingRow>
              );
            })}
          </Section>
        );
      })}
      {asking && (
        <Modal
          title={t('„{name}“ ausschalten?', { name: t(SWITCH_TEXTS[asking.id].label) })}
          tone="warning"
          onCancel={() => setAsking(null)}
          footer={
            <>
              <span className="spacer" />
              <Button data-autofocus data-secondary onClick={() => setAsking(null)}>
                {t('Abbrechen')}
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  const id = asking.id;
                  setAsking(null);
                  void change(id, false);
                }}
              >
                {t('Ausschalten')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Auf diesem Server wird das gerade benutzt. Ausgeschaltet sehen es die Nutzer nicht mehr, und die Apps bekommen es nicht mehr; die Daten bleiben und sind wieder da, sobald du es einschaltest.',
            )}
          </p>
        </Modal>
      )}
    </>
  );
}
