import { useState, type FormEvent, type ReactNode } from 'react';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';

/** One setting: a label, an optional explanation and its control. */
export function Row({
  label,
  description,
  children,
}: {
  label: string;
  description?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="setting-row">
      <div className="setting-text">
        <p className="setting-label">{label}</p>
        {description && <p className="setting-description">{description}</p>}
      </div>
      {children && <div className="setting-control">{children}</div>}
    </div>
  );
}

export function Segmented<T extends string | number>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button
          key={String(option.value)}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      className="toggle"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle-thumb" />
    </button>
  );
}

export type Result = { tone: 'info' | 'error'; text: string } | null;

export function ResultLine({ result }: { result: Result }) {
  if (!result) return null;
  return (
    <p className="setting-result" data-tone={result.tone} role="status">
      {result.text}
    </p>
  );
}

/**
 * Asks for the master password before something that needs it, and runs `action` with it.
 * Whatever `action` throws is shown here, and the dialog stays open to try again.
 */
export function PasswordPrompt({
  title,
  lead,
  confirm,
  tone = 'default',
  onCancel,
  action,
  children,
}: {
  title: string;
  lead: ReactNode;
  confirm: string;
  tone?: 'default' | 'warning';
  onCancel: () => void;
  action: (password: string) => Promise<void>;
  children?: ReactNode;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      await action(password);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      tone={tone}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" onClick={onCancel} disabled={busy} data-secondary>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className={tone === 'warning' ? 'danger' : 'primary'}
            onClick={() => void submit()}
            disabled={busy || !password}
          >
            {busy ? t('Einen Moment …') : confirm}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={submit}>
        <div className="dialog-lead">{lead}</div>
        {children}
        <label className="field">
          <span>{t('Master-Passwort')}</span>
          <PasswordInput value={password} onChange={setPassword} autoFocus disabled={busy} />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </form>
    </Modal>
  );
}

/** A file to the downloads folder. */
export function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
