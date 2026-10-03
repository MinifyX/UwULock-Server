import { useCallback, useEffect, useState } from 'react';
import { copyGenerated, generatePassword, type Generated, type GeneratorOptions } from '../lib/api';
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
import {
  effectiveLength,
  GENERATOR_SETS,
  loadGenerator,
  MAX_MINIMUM,
  requiredLength,
  saveGenerator,
} from '../lib/generator';
import { getSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { Icon } from './Icon';
import { Colored } from './ItemDetail';
import { Modal } from './Modal';
import { Segmented } from './web/controls';
import { MaskedDomainField } from './web/MaskedSettings';

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
  const [options, setOptions] = useState<GeneratorOptions>(loadGenerator);
  const [result, setResult] = useState<Generated | null>(null);
  /** How often it rolled: so the announcement changes, and is heard again, with each roll. */
  const [rolls, setRolls] = useState(0);
  // Masked addresses, when UwUMail is connected — not from the editor's password field.
  const masked = useUsableMasked(useFeature('masked-addresses') && !onUse);
  const [mode, setMode] = useState<'password' | 'masked'>('password');
  const maker = useMaskedMaker(masked);

  const roll = useCallback(async (next: GeneratorOptions) => {
    try {
      setResult(await generatePassword(next));
      setRolls((n) => n + 1);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  }, []);

  useEffect(() => {
    void roll(options);
    saveGenerator(options);
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
  const required = requiredLength(options);
  const length = effectiveLength(options);
  const [showMinimums, setShowMinimums] = useState(() =>
    GENERATOR_SETS.some((set) => options[set.min] > 1),
  );

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
        {/* The password itself stays out of the live region: a screen reader would read it out
            loud with every roll. It only hears that there is a new one (R1-24). */}
        <output className="generated" aria-live="off">
          {result ? <Colored text={result.password} /> : '…'}
        </output>
        <span className="sr-only" role="status">
          {result ? t('Neues Passwort erzeugt') + (rolls % 2 ? '\u00a0' : '') : ''}
        </span>
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
            {t('Länge')} <b>{length}</b>
          </span>
          <input
            type="range"
            min={5}
            max={64}
            value={Math.min(length, 64)}
            onChange={(e) => set({ length: Number(e.target.value) })}
          />
        </label>
        {length > options.length && (
          <p className="field-hint" data-generator-raised>
            {t('Für die Mindestzahlen braucht es {n} Zeichen – die Länge ist darum {n}.', {
              n: required,
            })}
          </p>
        )}
        <div className="generator-sets" role="group" aria-label={t('Zeichen')}>
          {GENERATOR_SETS.map(({ key, label }) => (
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
        <button
          type="button"
          className="quiet history-toggle"
          aria-expanded={showMinimums}
          onClick={() => setShowMinimums(!showMinimums)}
        >
          <Icon name="sliders" size={15} />
          {t('Mindestens je Zeichenart')}
          <Icon name="chevron" size={14} className={showMinimums ? 'turned' : undefined} />
        </button>
        {showMinimums && (
          <div
            className="generator-minimums"
            role="group"
            aria-label={t('Mindestens je Zeichenart')}
          >
            {GENERATOR_SETS.map(({ key, min, label }) => (
              <label key={min} className="field">
                <span className="mono">{label}</span>
                <input
                  type="number"
                  inputMode="numeric"
                  min={0}
                  max={MAX_MINIMUM}
                  disabled={!options[key]}
                  value={options[key] ? Math.max(1, options[min]) : 0}
                  aria-label={t('Mindestens {set}', { set: label })}
                  onChange={(e) =>
                    set({
                      [min]: Math.min(
                        MAX_MINIMUM,
                        Math.max(0, Math.round(Number(e.target.value) || 0)),
                      ),
                    })
                  }
                />
              </label>
            ))}
            <p className="field-hint">
              {t('Jede eingeschaltete Zeichenart kommt mindestens einmal vor.')}
            </p>
          </div>
        )}
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
