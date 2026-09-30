import type { ReactNode } from 'react';
import { Badge } from '../components/ui';
import { t, useLanguage } from '../lib/i18n';

/**
 * The line under a setting: what it does in plain words, and — where there is one — the value
 * this server recommends, on a pill of its own so it is found at a glance.
 */
export function Explain({ children, recommended }: { children?: ReactNode; recommended?: string }) {
  useLanguage();
  return (
    <>
      {children}
      {recommended && (
        <>
          {' '}
          <span className="recommended">
            <Badge tone="ok">{t('Empfohlen: {value}', { value: recommended })}</Badge>
          </span>
        </>
      )}
    </>
  );
}

/** A number with its unit spelled out after it ("Tage", "Megabyte"): the unit is part of the name. */
export function NumberInput({
  label,
  unit,
  value,
  onChange,
  min,
  max,
  step,
  placeholder,
}: {
  /** The field's name for screen readers: the setting's label. */
  label: string;
  unit?: string;
  value: number | null;
  onChange: (value: number | null) => void;
  min?: number;
  max?: number;
  step?: number;
  placeholder?: string;
}) {
  return (
    <span className="number-input">
      <input
        type="number"
        className="narrow-number"
        min={min}
        max={max}
        step={step}
        placeholder={placeholder}
        aria-label={unit ? `${label} (${unit})` : label}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
      />
      {unit && (
        <span className="number-unit" aria-hidden>
          {unit}
        </span>
      )}
    </span>
  );
}
