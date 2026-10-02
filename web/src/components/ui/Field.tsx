import {
  Children,
  cloneElement,
  isValidElement,
  useId,
  type InputHTMLAttributes,
  type ReactElement,
  type ReactNode,
} from 'react';
import { useSettingRow } from './setting';

type ControlProps = {
  id?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean | 'true' | 'false';
};

type FieldProps = {
  label: string;
  /** A line under the control: what to type, what happens. Read out with the control. */
  hint?: ReactNode;
  /** `warn` shows the hint in the alarm colour (something will be lost). */
  hintTone?: 'default' | 'warn';
  /** What is wrong with the value; marks the control as invalid. */
  error?: ReactNode;
  /** Buttons inside the control, at its end: an eye, the dice, a reset. At most three. */
  tools?: ReactNode;
  /** The label only for screen readers, where a heading or the row already names the field. */
  hideLabel?: boolean;
  className?: string;
  /** One control: an input, a select, a textarea. It gets the id and the description. */
  children: ReactElement<ControlProps>;
};

/**
 * A labelled control: the label above, the control (with its tools inside), a hint or an error
 * below. Fields in a FormRow line up, whatever their hints and tools.
 */
export function Field({
  label,
  hint,
  hintTone = 'default',
  error,
  tools,
  hideLabel,
  className,
  children,
}: FieldProps) {
  const ownId = useId();
  const id = children.props.id ?? ownId;
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const described =
    [children.props['aria-describedby'], errorId, hintId].filter(Boolean).join(' ') || undefined;
  const control = cloneElement(children, {
    id,
    'aria-describedby': described,
    ...(error ? { 'aria-invalid': true } : {}),
  });
  const toolCount = Children.toArray(tools).filter(isValidElement).length;
  return (
    <div className={['field', className].filter(Boolean).join(' ')}>
      <label htmlFor={id} className={hideLabel ? 'sr-only' : 'field-label'}>
        {label}
      </label>
      {toolCount ? (
        <div className="field-control" data-tools={Math.min(toolCount, 3)}>
          {control}
          <span className="field-tools">{tools}</span>
        </div>
      ) : (
        control
      )}
      {error && (
        <small className="field-error" id={errorId}>
          {error}
        </small>
      )}
      {hint && (
        <small
          className="field-hint"
          id={hintId}
          data-tone={hintTone === 'warn' ? 'warn' : undefined}
        >
          {hint}
        </small>
      )}
    </div>
  );
}

type TextFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value'> & {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: ReactNode;
  error?: ReactNode;
  tools?: ReactNode;
  /** In the monospace font: keys, codes, addresses. */
  mono?: boolean;
};

/** A one-line text field with its label. */
export function TextField({
  label,
  value,
  onChange,
  hint,
  error,
  tools,
  mono,
  type = 'text',
  className,
  ...rest
}: TextFieldProps) {
  return (
    <Field label={label} hint={hint} error={error} tools={tools}>
      <input
        type={type}
        value={value}
        className={[mono ? 'mono' : undefined, className].filter(Boolean).join(' ') || undefined}
        onChange={(event) => onChange(event.target.value)}
        {...rest}
      />
    </Field>
  );
}

type SelectProps<T extends string> = {
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  /** The name for screen readers when no Field labels it. */
  label?: string;
  disabled?: boolean;
  id?: string;
  className?: string;
};

/** A native select from a list of choices; wrap it in a Field for a visible label. */
export function Select<T extends string>({
  value,
  options,
  onChange,
  label,
  disabled,
  id,
  className,
  ...rest
}: SelectProps<T> & ControlProps) {
  // In a SettingRow, without a Field: named and described by the row.
  const row = useSettingRow();
  const described =
    [rest['aria-describedby'], row?.descriptionId].filter(Boolean).join(' ') || undefined;
  return (
    <select
      id={id}
      className={['select', className].filter(Boolean).join(' ')}
      value={value}
      aria-label={label}
      aria-labelledby={!label && row && !id ? row.labelId : undefined}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value as T)}
      {...rest}
      aria-describedby={described}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

/** A check box with its words; the whole line is the target. */
export function Checkbox({
  label,
  checked,
  onChange,
  disabled,
  className,
}: {
  label: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <label className={['check', className].filter(Boolean).join(' ')}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

/**
 * Fields side by side, as many as fit (each at least `min` wide: narrow 120 px, default 180 px,
 * wide 240 px), one below the other on a phone. The fields line up at their top.
 */
export function FormRow({
  min = 'default',
  children,
}: {
  min?: 'narrow' | 'default' | 'wide';
  children: ReactNode;
}) {
  return (
    <div className="form-row" data-min={min === 'default' ? undefined : min}>
      {children}
    </div>
  );
}

/**
 * Fields that belong together, under a small heading ("Websites", "Eigene Felder"), with an
 * optional line about them and actions below them (the way to add another).
 */
export function FieldGroup({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  const id = useId();
  return (
    <section className="field-group" role="group" aria-labelledby={id}>
      <h3 className="field-group-title" id={id}>
        {title}
      </h3>
      {description && <p className="form-note">{description}</p>}
      {children}
      {actions && <div className="add-actions">{actions}</div>}
    </section>
  );
}

/**
 * A row of a list the form repeats (a website, a field of one's own): its main control, maybe a
 * second one, and the button to remove it last. On a narrow screen the second one moves below.
 */
export function RepeatRow({
  aux = 'wide',
  children,
}: {
  /** How much room the second control takes: as much as the first, or a select's width. */
  aux?: 'wide' | 'narrow';
  children: ReactNode;
}) {
  return (
    <div className="repeat-row" data-aux={aux === 'narrow' ? 'narrow' : undefined}>
      {children}
    </div>
  );
}
