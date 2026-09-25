import { useCallback, useEffect, useState } from 'react';
import { copyGenerated, generatePassword, type GeneratorOptions } from '../lib/api';
import { errorText } from '../lib/errors';
import { copiedText } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { getSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { Icon } from './Icon';
import { Colored } from './ItemDetail';
import { Modal } from './Modal';

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

  return (
    <Modal
      title={t('Passwort-Generator')}
      onCancel={onClose}
      footer={
        <>
          <button className="quiet" onClick={onClose}>
            {t('Schließen')}
          </button>
          <span className="spacer" />
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
