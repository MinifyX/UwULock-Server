import type { KeyboardEvent } from 'react';

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
