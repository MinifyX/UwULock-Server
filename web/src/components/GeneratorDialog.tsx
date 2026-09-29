import { useCallback, useEffect, useState } from 'react';
import { copyGenerated, generatePassword, type GeneratorOptions } from '../lib/api';
import { useFeature } from '../lib/branding';
import { errorText, maskedErrorText } from '../lib/errors';
import { copiedText } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import {
  createMasked,
  defaultDomainOf,
  forDomainOf,
  reloadMaskedLinks,
  useUsableMasked,
  type MaskedConnection,
} from '../lib/masked';
import { getSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { Icon } from './Icon';
import { Colored } from './ItemDetail';
import { Modal } from './Modal';
import { Segmented } from './web/controls';
import { MaskedDomainField } from './web/MaskedSettings';

const KEY = 'uwulock.generator';

const DEFAULTS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

/** Only the options are remembered, never a password. */
function loadOptions(): GeneratorOptions {
  try {
    const raw = JSON.parse(window.localStorage.getItem(KEY) ?? '{}') as Partial<GeneratorOptions>;
    const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);
    return {
      length:
        typeof raw.length === 'number' ? Math.min(128, Math.max(5, Math.round(raw.length))) : 20,
      lowercase: bool(raw.lowercase, DEFAULTS.lowercase),
      uppercase: bool(raw.uppercase, DEFAULTS.uppercase),
      digits: bool(raw.digits, DEFAULTS.digits),
      symbols: bool(raw.symbols, DEFAULTS.symbols),
      avoidAmbiguous: bool(raw.avoidAmbiguous, DEFAULTS.avoidAmbiguous),
    };
  } catch {
    return DEFAULTS;
  }
}

function strength(bits: number): { level: 1 | 2 | 3 | 4; label: string } {
  if (bits < 50) return { level: 1, label: t('schwach') };
  if (bits < 75) return { level: 2, label: t('okay') };
  if (bits < 100) return { level: 3, label: t('stark') };
  return { level: 4, label: t('sehr stark ✧') };
}

export function GeneratorDialog({
  onClose,
  onUse,
}: {
  onClose: () => void;
  /** Opened from the editor: the password goes into the field instead. */
  onUse?: (password: string) => void;
}) {
  useLanguage();
  const [options, setOptions] = useState<GeneratorOptions>(loadOptions);
  const [result, setResult] = useState<{ password: string; bits: number } | null>(null);
  // Masked addresses, when UwUMail is connected — not from the editor's password field.
  const masked = useUsableMasked(useFeature('masked-addresses') && !onUse);
  const [mode, setMode] = useState<'password' | 'masked'>('password');
  const maker = useMaskedMaker(masked);

  const roll = useCallback(async (next: GeneratorOptions) => {
    try {
      setResult(await generatePassword(next));
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }, []);

  useEffect(() => {
    void roll(options);
    try {
      window.localStorage.setItem(KEY, JSON.stringify(options));
    } catch {
      // Remembering is a convenience.
    }
  }, [options, roll]);

  const set = (patch: Partial<GeneratorOptions>) => {
    const next = { ...options, ...patch };
    // At least one set stays on.
    if (!next.lowercase && !next.uppercase && !next.digits && !next.symbols) return;
    setOptions(next);
  };

  const copy = async () => {
    if (!result) return;
    try {
      await copyGenerated(result.password);
      toast(copiedText('password', getSettings().clipboardClear));
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const meter = result ? strength(result.bits) : null;
  const sets: { key: 'uppercase' | 'lowercase' | 'digits' | 'symbols'; label: string }[] = [
    { key: 'uppercase', label: 'A–Z' },
    { key: 'lowercase', label: 'a–z' },
    { key: 'digits', label: '0–9' },
    { key: 'symbols', label: '!@#$%^&*' },
  ];

  if (masked && mode === 'masked') {
    return (
      <Modal
        title={t('Maskierte Adresse')}
        onCancel={onClose}
        footer={
          <>
            <span className="spacer" />
            <button onClick={onClose}>{t('Schließen')}</button>
            <button disabled={maker.busy} onClick={() => void maker.create()}>
              <Icon name="plus" size={15} />
              {maker.made ? t('Noch eine anlegen') : t('Adresse anlegen')}
            </button>
            <button className="primary" disabled={!maker.made} onClick={() => void maker.copy()}>
              <Icon name="copy" size={15} />
              {t('Kopieren')}
            </button>
          </>
        }
      >
        <div className="generator">
          <ModeSwitch mode={mode} onChange={setMode} />
          <output className="generated mono" aria-live="polite">
            {maker.busy ? t('Einen Moment …') : (maker.made ?? '…')}
          </output>
          {maker.error && (
            <p className="form-error" role="alert">
              {maker.error}
            </p>
          )}
          <MaskedDomainField connection={masked} value={maker.domain} onChange={maker.setDomain} />
          <label className="field">
            <span>{t('Für die Website (freiwillig)')}</span>
            <input
              value={maker.website}
              spellCheck={false}
              placeholder="shop.example.com"
              onChange={(e) => maker.setWebsite(e.target.value)}
            />
          </label>
          <p className="field-hint">
            {t(
              'UwUMail legt die Adresse beim Klick an; sie bekommt Mails, bis du sie unter Einstellungen → Maskierte Adressen abschaltest.',
            )}
          </p>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      title={t('Passwort-Generator')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button onClick={onClose}>{t('Schließen')}</button>
          <button onClick={() => void roll(options)}>
            <Icon name="dice" size={15} />
            {t('Neu würfeln')}
          </button>
          {onUse ? (
            <button
              className="primary"
              data-autofocus
              disabled={!result}
              onClick={() => result && onUse(result.password)}
            >
              <Icon name="check" size={15} />
              {t('Übernehmen')}
            </button>
          ) : (
            <button className="primary" data-autofocus onClick={() => void copy()}>
              <Icon name="copy" size={15} />
              {t('Kopieren')}
            </button>
          )}
        </>
      }
    >
      <div className="generator">
        {masked && <ModeSwitch mode={mode} onChange={setMode} />}
        <output className="generated" aria-live="polite">
          {result ? <Colored text={result.password} /> : '…'}
        </output>
        {meter && (
          <div className="meter" data-level={meter.level}>
            <span className="meter-bar">
              <span />
              <span />
              <span />
              <span />
            </span>
            <span className="meter-label">
              {meter.label} · {t('{bits} Bit', { bits: result?.bits ?? 0 })}
            </span>
          </div>
        )}
        <label className="field">
          <span>
            {t('Länge')} <b>{options.length}</b>
          </span>
          <input
            type="range"
            min={5}
            max={64}
            value={Math.min(options.length, 64)}
            onChange={(e) => set({ length: Number(e.target.value) })}
          />
        </label>
        <div className="generator-sets" role="group" aria-label={t('Zeichen')}>
          {sets.map(({ key, label }) => (
            <label key={key} className="check chip-check">
              <input
                type="checkbox"
                checked={options[key]}
                onChange={(e) => set({ [key]: e.target.checked })}
              />
              <span className="mono">{label}</span>
            </label>
          ))}
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={options.avoidAmbiguous}
            onChange={(e) => set({ avoidAmbiguous: e.target.checked })}
          />
          <span>{t('Verwechselbare Zeichen weglassen (l, 1, I, O, 0)')}</span>
        </label>
      </div>
    </Modal>
  );
}

function ModeSwitch({
  mode,
  onChange,
}: {
  mode: 'password' | 'masked';
  onChange: (mode: 'password' | 'masked') => void;
}) {
  useLanguage();
  return (
    <Segmented
      label={t('Was erzeugen')}
      value={mode}
      onChange={onChange}
      options={[
        { value: 'password', label: t('Passwort') },
        { value: 'masked', label: t('Maskierte Adresse (UwUMail)') },
      ]}
    />
  );
}

/** A masked address as a username: made at UwUMail on the click, then ready to copy. */
function useMaskedMaker(connection: MaskedConnection | null) {
  const [domain, setDomain] = useState(defaultDomainOf(connection));
  const [website, setWebsite] = useState('');
  const [made, setMade] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const forDomain = forDomainOf(website);
      const address = await createMasked({
        forDomain,
        description: forDomain.replace(/^https?:\/\//, ''),
        domain: domain || null,
        cipherId: null,
      });
      setMade(address.email);
      void reloadMaskedLinks();
    } catch (e) {
      setError(maskedErrorText(e));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!made) return;
    try {
      await copyGenerated(made);
      toast(t('Kopiert ✧'));
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  return { domain, setDomain, website, setWebsite, made, busy, error, create, copy };
}
