import { type KeyboardEvent } from 'react';

type Options = {
  /** Makes the entries' element ids: `<prefix>-<id>`. */
  prefix: string;
  /** The entries' ids, in the order shown. */
  ids: string[];
  selected: string | null;
  onSelect: (id: string) => void;
  /** Enter: open the picked entry (on a phone, its page). */
  onOpen?: (id: string) => void;
  /** Space: mark the picked entry, for doing something to several at once; with Shift, a range. */
  onMark?: (id: string, range: boolean) => void;
};

/**
 * A list to pick one entry from, the way screen readers know it (`role="listbox"`): Tab reaches
 * the list once, the arrow keys, Page Up/Down, Home and End move the pick, Enter opens it, Space
 * marks it. The list itself keeps the focus; `aria-activedescendant` says which entry is meant,
 * and the entries (`role="option"`, id from `optionId`) hold nothing focusable of their own.
 */
export function listbox({ prefix, ids, selected, onSelect, onOpen, onMark }: Options) {
  const optionId = (id: string) => `${prefix}-${id}`;
  const current = selected !== null && ids.includes(selected) ? selected : null;

  const move = (step: number) => {
    if (!ids.length) return;
    const index = current === null ? -1 : ids.indexOf(current);
    const next = ids[Math.max(0, Math.min(ids.length - 1, index + step))];
    if (next === undefined) return;
    onSelect(next);
    document.getElementById(optionId(next))?.scrollIntoView({ block: 'nearest' });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    switch (event.key) {
      case 'ArrowDown':
        move(1);
        break;
      case 'ArrowUp':
        move(-1);
        break;
      case 'PageDown':
        move(10);
        break;
      case 'PageUp':
        move(-10);
        break;
      case 'Home':
        move(-ids.length);
        break;
      case 'End':
        move(ids.length);
        break;
      case 'Enter':
        if (!onOpen || current === null) return;
        onOpen(current);
        break;
      case ' ':
        if (!onMark || current === null) return;
        onMark(current, event.shiftKey);
        break;
      default:
        return;
    }
    event.preventDefault();
  };

  return {
    move,
    optionId,
    listProps: {
      role: 'listbox' as const,
      tabIndex: 0,
      'aria-activedescendant': current === null ? undefined : optionId(current),
      onKeyDown,
    },
  };
}
