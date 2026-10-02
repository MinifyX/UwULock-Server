import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';

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
  /** A × in the title bar, for dialogs without a footer (the settings). */
  closable?: boolean;
};

const FOCUSABLE =
  'input, button, textarea, select, summary, [href], [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';

/**
 * Open dialogs, innermost last. A dialog can open another (the host form opens
 * the vault), and only the one on top may react to Escape and Tab.
 */
const stack: HTMLElement[] = [];

/**
 * A dialog. Escape cancels, a click beside it doesn't; focus moves into the
 * dialog on open, stays inside it while it is open, and goes back where it was
 * on close.
 *
 * Focus always lands somewhere inside. When nothing should be focused — the
 * host key dialog deliberately gives neither button default focus, so Enter
 * cannot trust a key by accident — the dialog itself takes it. Leaving focus
 * behind let Enter activate whatever was focused in the background: in the
 * end-to-end test that was the host row, and it started a second connection.
 */
export function Modal({
  title,
  tone = 'default',
  size = 'default',
  onCancel,
  children,
  footer,
  closable,
}: ModalProps) {
  useLanguage();
  const dialogRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  // Escape calls the latest onCancel, not the one from when the dialog
  // opened: a form that asks before closing only knows once something changed.
  const cancelRef = useRef(onCancel);
  cancelRef.current = onCancel;
  // Dialogs stack (the host form opens the vault): each needs its own title id.
  const titleId = useId();
  // Where focus was when the dialog opened, taken while drawing it: by the time the effect runs
  // (twice, in development) focus may already be inside.
  const [previous] = useState(() => document.activeElement as HTMLElement | null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    // An explicit [data-autofocus] wins — warnings point it at the safe choice.
    // Otherwise the first field, or the first button not marked secondary.
    // Buttons that act on something risky carry data-secondary, so Enter can
    // never trigger them by accident.
    // Only what can take the focus: a button that waits for its content (the generator's
    // "Übernehmen" before the first password) is disabled, and focusing it left the focus outside
    // the dialog, where a screen reader went on reading the page behind it.
    const first =
      dialog.querySelector<HTMLElement>('[data-autofocus]:not(:disabled)') ??
      dialog.querySelector<HTMLElement>(
        'input:not(:disabled), button:not([data-secondary]):not(:disabled), textarea:not(:disabled), select:not(:disabled)',
      ) ??
      dialog;
    // On the stack first: a dialog opened from another one takes the focus as the one on top, or
    // the one below (see onFocusIn) would pull it back.
    stack.push(dialog);
    first.focus();

    // Whatever moves the focus behind the dialog (a click on the page, a screen reader's own
    // cursor, an element of the page focusing itself), it comes back to the dialog on top.
    const onFocusIn = (event: FocusEvent) => {
      if (stack[stack.length - 1] !== dialog) return;
      if (event.target instanceof Node && dialog.contains(event.target)) return;
      dialog.focus();
    };
    document.addEventListener('focusin', onFocusIn);

    const onKey = (event: KeyboardEvent) => {
      if (stack[stack.length - 1] !== dialog) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        cancelRef.current();
        return;
      }
      if (event.key !== 'Tab') return;

      // Keep Tab inside the dialog.
      // Only what Tab really reaches: nothing disabled, nothing out of sight (a closed
      // <details>, a hidden panel), nothing taken out of the order.
      const focusable = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (el) =>
          !el.hasAttribute('disabled') &&
          el.tabIndex >= 0 &&
          el.getClientRects().length > 0 &&
          getComputedStyle(el).visibility !== 'hidden',
      );
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const firstEl = focusable[0]!;
      const lastEl = focusable[focusable.length - 1]!;
      const current = document.activeElement;
      if (event.shiftKey && (current === firstEl || current === dialog)) {
        event.preventDefault();
        lastEl.focus();
      } else if (!event.shiftKey && current === lastEl) {
        event.preventDefault();
        firstEl.focus();
      }
    };

    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      document.removeEventListener('focusin', onFocusIn);
      stack.splice(stack.indexOf(dialog), 1);
      // Back where it was. When that is gone (the row of a deleted item, the menu that opened
      // the dialog), to the dialog below, or to the page's content rather than to nowhere.
      if (previous?.isConnected && previous !== document.body) previous.focus();
      else
        (
          stack[stack.length - 1] ??
          document.querySelector<HTMLElement>('[data-main-content]') ??
          document.getElementById('main')
        )?.focus();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A hairline under the title and over the buttons, only while the body scrolls beneath them.
  useEffect(() => {
    const body = bodyRef.current;
    if (!body) return;
    const update = () => {
      const scrolled = body.scrollTop > 0;
      const more = body.scrollTop + body.clientHeight < body.scrollHeight - 1;
      body.toggleAttribute('data-scrolled', scrolled);
      body.toggleAttribute('data-more', more);
    };
    update();
    body.addEventListener('scroll', update, { passive: true });
    if (typeof ResizeObserver === 'undefined') {
      return () => body.removeEventListener('scroll', update);
    }
    // The body's own size and its content's: a field added below grows the content only.
    const sizes = new ResizeObserver(update);
    const watch = () => {
      sizes.disconnect();
      sizes.observe(body);
      for (const child of body.children) sizes.observe(child);
    };
    watch();
    const children = new MutationObserver(watch);
    children.observe(body, { childList: true });
    return () => {
      body.removeEventListener('scroll', update);
      sizes.disconnect();
      children.disconnect();
    };
  }, []);

  // Straight into <body>: a dialog opened from inside another one (the export
  // from Settings) otherwise lives in the outer dialog's scroll box, which
  // moves it about when a field inside gets focus.
  return createPortal(
    // A click beside the dialog does nothing: closing by accident threw away
    // whatever was typed into it. Escape and the dialog's own buttons close.
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        className="modal"
        data-tone={tone}
        data-size={size}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-head">
          <h2 id={titleId} className="modal-title">
            {title}
          </h2>
        </div>
        <div ref={bodyRef} className="modal-body">
          {children}
        </div>
        {footer && <div className="modal-footer">{footer}</div>}
        {/* Last in the Tab order, as before; drawn in the title bar. */}
        {closable && (
          <button
            type="button"
            className="icon-button modal-close"
            onClick={onCancel}
            aria-label={t('Schließen')}
            title={t('Schließen')}
          >
            <Icon name="close" size={16} />
          </button>
        )}
      </div>
    </div>,
    document.body,
  );
}
