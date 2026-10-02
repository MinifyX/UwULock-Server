import { useId, useState } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';

type Props = {
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  id?: string;
  label?: string;
  /** The form's error is about this field: marked, and read out with it. */
  invalid?: boolean;
  /** The id of the text that explains the field or its error. */
  describedBy?: string;
  /** What a Field around it hands down (its hint and error), like `describedBy` and `invalid`. */
  'aria-describedby'?: string;
  'aria-invalid'?: boolean | 'true' | 'false';
};

/**
 * A password field with an eye to peek, and a hint when Caps Lock is on.
 *
 * Inside a `<label>` that wraps it, give it `label` too: a wrapping label names the field with
 * everything in it, the eye's "Passwort zeigen" and a strength line included, and a screen reader
 * read all that as the field's name.
 */
export function PasswordInput({
  value,
  onChange,
  autoFocus,
  disabled,
  autoComplete = 'current-password',
  id,
  label,
  invalid,
  describedBy,
  'aria-describedby': fieldDescribedBy,
  'aria-invalid': fieldInvalid,
}: Props) {
  useLanguage();
  const [visible, setVisible] = useState(false);
  const [caps, setCaps] = useState(false);
  const capsId = useId();
  const described =
    [describedBy, fieldDescribedBy, caps ? capsId : null].filter(Boolean).join(' ') || undefined;
  const isInvalid = invalid || fieldInvalid === true || fieldInvalid === 'true';
  return (
    <span className="password-input">
      <input
        id={id}
        type={visible ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => setCaps(e.getModifierState('CapsLock'))}
        onKeyUp={(e) => setCaps(e.getModifierState('CapsLock'))}
        onBlur={() => setCaps(false)}
        autoFocus={autoFocus}
        // Read-only rather than disabled: a disabled field drops the focus (a screen reader then
        // starts again at the top of the page), and it is off only while the form works.
        readOnly={disabled}
        aria-disabled={disabled || undefined}
        autoComplete={autoComplete}
        spellCheck={false}
        aria-label={label}
        aria-invalid={isInvalid || undefined}
        aria-describedby={described}
      />
      {/* One name, and the state in aria-pressed: "Passwort verbergen, gedrückt" said both. */}
      <button
        type="button"
        className="icon-button"
        onClick={() => setVisible(!visible)}
        aria-label={t('Passwort zeigen')}
        aria-pressed={visible}
        title={visible ? t('Passwort verbergen') : t('Passwort zeigen')}
      >
        <Icon name={visible ? 'eyeOff' : 'eye'} size={16} />
      </button>
      {caps && (
        <small className="caps-hint" id={capsId} role="status">
          {t('Feststelltaste ist an')}
        </small>
      )}
    </span>
  );
}
