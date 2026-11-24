import { Dialog } from '@uwusuite/design';
import { useEffect, useRef, useState, type ReactNode, type SyntheticEvent } from 'react';
import { createPortal } from 'react-dom';
import { useLanguage } from '../lib/i18n';

type ModalProps = {
  title: string;
  /** Security warnings get their own look, so they never blend in with routine dialogs. */
  tone?: 'default' | 'warning';
  /** Room for more: the item editor, the settings with their list of sections. Full screen on a phone. */
  size?: 'default' | 'wide';
  onCancel: () => void;
  children: ReactNode;
  /**
   * The buttons: `<span className="spacer" />`, then the safe choice (`data-secondary`), then the
   * main one (`primary`, or `danger` in a warning). A destructive extra goes before the spacer.
   */
  footer?: ReactNode;
};

const WIDTH = { default: 'md', wide: 'lg' } as const;

/** `onCancel` on a plain element: React's types only know it on <dialog>. */
const stopCancel = { onCancel: (event: SyntheticEvent) => event.stopPropagation() };

/**
 * A dialog: @uwusuite/design's `Dialog` (a native <dialog>, so the page behind it is inert, Tab
 * stays inside and the top one gets Escape), with what UwULock adds on top:
 *
 * - Escape, the × and the dialog's own buttons close it, a click beside it doesn't: closing by
 *   accident threw away whatever was typed into it.
 * - Focus lands where it is safe. An explicit [data-autofocus] wins — warnings point it at the
 *   safe choice. Otherwise the first field, or the first button not marked [data-secondary]:
 *   buttons that act on something risky carry it, so Enter can never trigger them by accident.
 *   When nothing should be focused, the dialog itself takes it, so Enter cannot activate whatever
 *   was focused in the background.
 * - Focus goes back where it was on close, or to the page's content when that is gone.
 *
 * Rendered straight into <body>: a dialog opened from inside another one (the export from
 * Settings) must not live in the outer dialog's scroll box.
 */
export function Modal({ title, tone = 'default', size = 'default', onCancel, children, footer }: ModalProps) {
  useLanguage();
  const bodyRef = useRef<HTMLDivElement>(null);
  // Escape calls the latest onCancel, not the one from when the dialog
  // opened: a form that asks before closing only knows once something changed.
  const cancelRef = useRef(onCancel);
  cancelRef.current = onCancel;
  // Where focus was when the dialog opened, taken while drawing it: by the time the effect runs
  // (twice, in development) focus may already be inside.
  const [previous] = useState(() => document.activeElement as HTMLElement | null);

  useEffect(() => {
    const body = bodyRef.current;
    const dialog = body?.closest('dialog');
    if (!body || !dialog) return;
    const first =
      dialog.querySelector<HTMLElement>('[data-autofocus]') ??
      body.querySelector<HTMLElement>('input, button:not([data-secondary]), textarea, select') ??
      dialog.querySelector<HTMLElement>('footer button:not([data-secondary])');
    if (first) {
      first.focus();
    } else {
      dialog.tabIndex = -1;
      dialog.focus();
    }
    return () => {
      if (previous?.isConnected && previous !== document.body) previous.focus();
      else
        (
          document.querySelector<HTMLElement>('dialog[open]') ??
          document.querySelector<HTMLElement>('[data-main-content]') ??
          document.getElementById('main')
        )?.focus();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // React passes a dialog's `cancel` up its own tree, through the portal, into the dialog this
  // one was opened from. The boundary stops it: only the dialog on top reacts.
  return createPortal(
    <div className="contents" {...stopCancel}>
      <Dialog
        open
        onClose={() => cancelRef.current()}
        title={title}
        tone={tone}
        width={WIDTH[size]}
        footer={footer}
        closeOnOutsideClick={false}
        className="modal"
      >
        <div ref={bodyRef} className="modal-body grid content-start gap-4 px-6 pt-1 pb-5 phone:px-4">
          {children}
        </div>
      </Dialog>
    </div>,
    document.body,
  );
}
