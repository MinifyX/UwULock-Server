import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Icon, type IconName } from './Icon';

export type MenuItem =
  | {
      label: string;
      icon?: IconName;
      danger?: boolean;
      disabled?: boolean;
      onSelect: () => void;
    }
  | 'separator';

type Props = {
  x: number;
  y: number;
  items: MenuItem[];
  onClose: () => void;
  label: string;
};

/**
 * A small menu at the pointer, for right-clicks. Arrow keys, Home and End move,
 * Enter picks, Escape, Tab or a click anywhere else closes — and focus goes back
 * to where it was. It moves itself inside the window when it would stick out.
 */
export function ContextMenu({ x, y, items, onClose, label }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ x, y });

  // Focus goes back to the button that opened the menu. A dialog the menu opens takes focus from
  // there, and gives it back there when it closes.
  useLayoutEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    return () => {
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  useLayoutEffect(() => {
    const menu = ref.current;
    if (!menu) return;
    const rect = menu.getBoundingClientRect();
    setPosition({
      x: Math.max(8, Math.min(x, window.innerWidth - rect.width - 8)),
      y: Math.max(8, Math.min(y, window.innerHeight - rect.height - 8)),
    });
    menu.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
  }, [x, y]);

  useEffect(() => {
    const close = (event: Event) => {
      if (ref.current && event.target instanceof Node && ref.current.contains(event.target)) return;
      onClose();
    };
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key === 'Tab') {
        event.preventDefault();
        onClose();
        return;
      }
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const buttons = [
        ...(ref.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []),
      ];
      const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
      const next =
        event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? buttons.length - 1
            : (index + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
      buttons[next]?.focus();
    };
    window.addEventListener('pointerdown', close, true);
    window.addEventListener('keydown', key, true);
    window.addEventListener('blur', onClose);
    window.addEventListener('resize', onClose);
    return () => {
      window.removeEventListener('pointerdown', close, true);
      window.removeEventListener('keydown', key, true);
      window.removeEventListener('blur', onClose);
      window.removeEventListener('resize', onClose);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="context-menu"
      role="menu"
      aria-label={label}
      style={{ left: position.x, top: position.y }}
      onContextMenu={(event) => event.preventDefault()}
    >
      {items.map((item, index) =>
        item === 'separator' ? (
          <hr key={`separator-${index}`} />
        ) : (
          <button
            key={item.label}
            role="menuitem"
            disabled={item.disabled}
            data-danger={item.danger || undefined}
            onClick={() => {
              onClose();
              item.onSelect();
            }}
          >
            {item.icon ? <Icon name={item.icon} size={15} /> : <span className="icon-gap" />}
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}
