import { IconButton, ICONS } from '@uwusuite/design';
import { useId, useState } from 'react';
import { t, useLanguage } from '../lib/i18n';

type Props = {
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  id?: string;
  name?: string;
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
  name,
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
        name={name}
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
      <IconButton
        icon={visible ? ICONS.hide : ICONS.show}
        label={visible ? t('Passwort verbergen') : t('Passwort zeigen')}
        size="sm"
        className="icon-button"
        onClick={() => setVisible(!visible)}
        aria-pressed={visible}
      />
      {caps && (
        <small className="caps-hint" id={capsId}>
          {t('Feststelltaste ist an')}
        </small>
      )}
    </span>
  );
}
