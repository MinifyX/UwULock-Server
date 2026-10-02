import type { KeyboardEvent } from 'react';
import { useSettingRow } from './setting';

/**
 * The arrow keys in a group of radio buttons: they move to the next choice and pick it. Only the
 * picked one is in the Tab order (`tabIndex` from `radioTab`), as screen readers expect.
 */
export function radioArrows(event: KeyboardEvent<HTMLElement>) {
  const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
  if (!step || event.altKey || event.ctrlKey || event.metaKey) return;
  const radios = [
    ...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="radio"]:not(:disabled)'),
  ];
  const index = radios.indexOf(document.activeElement as HTMLButtonElement);
  const next = radios[(index + step + radios.length) % radios.length];
  if (!next) return;
  event.preventDefault();
  next.focus();
  next.click();
}

/** The Tab order in a radio group: the picked choice, or the first when none is. */
export function radioTab(checked: boolean, first: boolean, anyChecked: boolean): 0 | -1 {
  return checked || (first && !anyChecked) ? 0 : -1;
}

/** A few choices side by side, one picked: a radio group that looks like one control. */
export function Segmented<T extends string | number>({
  label,
  value,
  options,
  onChange,
  wide,
}: {
  /** The group's name for screen readers. */
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  /** As wide as its container, the choices sharing the room. */
  wide?: boolean;
}) {
  const row = useSettingRow();
  return (
    <div
      className={wide ? 'segmented wide' : 'segmented'}
      role="radiogroup"
      aria-label={label}
      aria-describedby={row?.descriptionId}
      onKeyDown={radioArrows}
    >
      {options.map((option, index) => (
        <button
          key={String(option.value)}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          tabIndex={radioTab(
            option.value === value,
            index === 0,
            options.some((o) => o.value === value),
          )}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/** An on/off switch. Its label is its accessible name; the row next to it says what it does. */
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
  const row = useSettingRow();
  return (
    <button
      type="button"
      role="switch"
      className="toggle"
      aria-checked={checked}
      aria-label={label}
      aria-describedby={row?.descriptionId}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle-thumb" />
    </button>
  );
}
