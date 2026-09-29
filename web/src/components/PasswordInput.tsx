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
};

/** A password field with an eye to peek, and a hint when Caps Lock is on. */
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
}: Props) {
  useLanguage();
  const [visible, setVisible] = useState(false);
  const [caps, setCaps] = useState(false);
  const capsId = useId();
  const described = [describedBy, caps ? capsId : null].filter(Boolean).join(' ') || undefined;
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
        disabled={disabled}
        autoComplete={autoComplete}
        spellCheck={false}
        aria-label={label}
        aria-invalid={invalid || undefined}
        aria-describedby={described}
      />
      <button
        type="button"
        className="icon-button"
        onClick={() => setVisible(!visible)}
        aria-label={visible ? t('Passwort verbergen') : t('Passwort zeigen')}
        aria-pressed={visible}
      >
        <Icon name={visible ? 'eyeOff' : 'eye'} size={16} />
      </button>
      {caps && (
        <small className="caps-hint" id={capsId}>
          {t('Feststelltaste ist an')}
        </small>
      )}
    </span>
  );
}
