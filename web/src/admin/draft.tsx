import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { Button, Callout } from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import { saveSettings, settings as load, type Settings } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import { ApiError } from '../lib/web/http';

/**
 * The server's settings, as the tabs change them: loaded once, changed in any tab, saved together
 * with one button that shows up as soon as something differs. Going to another tab keeps what
 * was typed.
 */
type Draft = {
  draft: Settings;
  current: Settings;
  setDraft: (next: Settings) => void;
  dirty: boolean;
  /** Counts saves and discards: the text boxes that keep their own text start again then. */
  generation: number;
};

type State = {
  value: Draft | null;
  busy: boolean;
  result: Result;
  save: () => Promise<void>;
  discard: () => void;
};

const Context = createContext<State | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    load().then(
      (loaded) => {
        setCurrent(loaded);
        setDraft(loaded);
      },
      (e) => setResult({ tone: 'error', text: errorText(e) }),
    );
  }, []);

  const dirty = Boolean(draft && current && JSON.stringify(draft) !== JSON.stringify(current));

  const save = async () => {
    if (!draft) return;
    setBusy(true);
    setResult(null);
    try {
      const body: Settings = { ...draft, smtp: draft.smtp?.host.trim() ? draft.smtp : null };
      // Rows left empty are not servers.
      if (draft.masked)
        body.masked = {
          servers: draft.masked.servers
            .filter((server) => server.url.trim())
            .map((server) => ({
              url: server.url.trim().replace(/\/+$/, ''),
              name: server.name.trim(),
            })),
        };
      const saved = await saveSettings(body);
      setCurrent(saved);
      setDraft(saved);
      setGeneration((n) => n + 1);
      toast(t('Gespeichert ✧'), 'info');
    } catch (e) {
      const code = e instanceof ApiError ? (e.body as { code?: string } | null)?.code : null;
      setResult({
        tone: 'error',
        text:
          code === 'would_lock_out'
            ? `${errorText(e)} ${t('Nichts gespeichert: Du hättest dich selbst ausgesperrt.')}`
            : errorText(e),
      });
    } finally {
      setBusy(false);
    }
  };

  const discard = () => {
    setDraft(current);
    setGeneration((n) => n + 1);
    setResult(null);
  };

  const value =
    draft && current
      ? { draft, current, setDraft: (next: Settings) => setDraft(next), dirty, generation }
      : null;
  return (
    <Context.Provider value={{ value, busy, result, save, discard }}>{children}</Context.Provider>
  );
}

function useState_(): State {
  const state = useContext(Context);
  if (!state) throw new Error('SettingsProvider missing');
  return state;
}

/** The settings being changed; `null` while they load (or when loading failed). */
export function useDraft(): Draft | null {
  return useState_().value;
}

/** A tab made of settings: its content once they are loaded, or why they are not. */
export function SettingsTab({ children }: { children: (draft: Draft) => ReactNode }) {
  const state = useState_();
  if (!state.value) return <ResultLine result={state.result} />;
  return <>{children(state.value)}</>;
}

/**
 * At the foot of the page, while a setting differs from the saved one — in whichever tab it was
 * changed: save everything, or throw the changes away. What went wrong stays in it.
 */
export function SaveBar() {
  useLanguage();
  const { value, busy, result, save, discard } = useState_();
  if (!value) return null;
  if (!value.dirty) return null;
  return (
    <div className="save-bar" role="region" aria-label={t('Ungespeicherte Änderungen')}>
      {result?.tone === 'error' ? (
        <Callout tone="error">{result.text}</Callout>
      ) : (
        <p className="save-bar-text">
          {t('Du hast Einstellungen geändert, die noch nicht gespeichert sind.')}
        </p>
      )}
      <span className="spacer" />
      <Button disabled={busy} onClick={discard} data-secondary>
        {t('Verwerfen')}
      </Button>
      <Button variant="primary" disabled={busy} onClick={() => void save()}>
        {busy ? t('Speichert …') : t('Speichern')}
      </Button>
    </div>
  );
}
