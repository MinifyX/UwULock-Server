/**
 * Where the keyboard focus goes when the page changes under it: a screen reader reads what has
 * the focus, so focus left on nothing (the page's body) means silence, and the next Tab starts
 * from the top of the page.
 */

import { useEffect, useRef } from 'react';

/** The page's own title, as the server sent it (the server's name, or its branding). */
const baseTitle = typeof document === 'undefined' ? 'UwULock' : document.title || 'UwULock';

/** The page title for a screen: "Tresor – UwULock". */
export function pageTitle(screen: string | null): string {
  return screen ? `${screen} – ${baseTitle}` : baseTitle;
}

const nowhere = () => !document.activeElement || document.activeElement === document.body;

/**
 * When the screen changes (logged in, unlocked, another area of the admin portal), the page's
 * title says which one it is now, and the focus moves to its content, unless the new screen put
 * it somewhere itself (the unlock screen's password field). The first screen of a page keeps the
 * browser's own start.
 */
export function useScreen(screen: string | null, title: string) {
  const seen = useRef(false);
  useEffect(() => {
    document.title = pageTitle(title || null);
  }, [title]);
  useEffect(() => {
    if (screen === null) return;
    if (!seen.current) {
      seen.current = true;
      return;
    }
    // After the new screen drew and its own effects (autofocus) ran.
    const timer = window.setTimeout(() => {
      const main = document.getElementById('main');
      const active = document.activeElement;
      if (!nowhere() && active !== main) return;
      focusContent();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [screen]);
}

/** The focus to the page's content: the part marked as such, else its first heading. */
export function focusContent() {
  const main = document.getElementById('main');
  const target =
    main?.querySelector<HTMLElement>('[data-main-content]') ??
    main?.querySelector<HTMLElement>('h1') ??
    main;
  if (!target) return;
  if (!target.hasAttribute('tabindex')) target.tabIndex = -1;
  target.focus();
}

/**
 * Buttons and fields are switched off while they work ("Speichert …"): a focused element that is
 * switched off loses the focus to the page's body, a screen reader goes quiet, and Orca moved its
 * own cursor (and with it the focus) to the top of the page meanwhile. So the focus waits on the
 * form, dialog or page around it, and when the element is switched on again and nothing else took
 * the focus, it gets it back: a login that failed lands in its field again, a switch of the admin
 * portal stays under the finger.
 */
export function keepFocusThroughBusy(): () => void {
  let last: Element | null = null;
  let lost: HTMLElement | null = null;
  let holder: HTMLElement | null = null;
  let moving = false;
  const onFocusIn = (event: FocusEvent) => {
    if (moving) return;
    last = event.target instanceof Element ? event.target : null;
    lost = null;
    holder = null;
  };
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      const element = record.target as HTMLElement;
      if (element.hasAttribute('disabled')) {
        if (element !== last) continue;
        lost = element;
        // Still focused (the browser lets go of it only when it next draws): hand the focus to
        // what is around it before it falls to the body.
        if (document.activeElement === element || nowhere()) {
          holder =
            element.parentElement?.closest<HTMLElement>(
              'form, [role="dialog"], [data-main-content], main',
            ) ?? null;
          if (holder) {
            if (!holder.hasAttribute('tabindex')) holder.tabIndex = -1;
            moving = true;
            holder.focus({ preventScroll: true });
            moving = false;
          }
        }
      } else if (element === lost) {
        lost = null;
        const active = document.activeElement;
        if (element.isConnected && (nowhere() || active === holder || active === element))
          element.focus();
        holder = null;
      }
    }
  });
  observer.observe(document.body, {
    subtree: true,
    attributes: true,
    attributeFilter: ['disabled'],
  });
  document.addEventListener('focusin', onFocusIn);
  return () => {
    observer.disconnect();
    document.removeEventListener('focusin', onFocusIn);
  };
}
