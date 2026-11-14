import { useLayoutEffect, useRef } from 'react';

/**
 * NavIndicator from @uwusuite/design 1.15, ported: one pill behind the active row that slides
 * to the next one. Put it as a child of the row container. `active` picks the row (default:
 * aria-current / aria-selected); that row's own background moves to the pill (styles/motion.css).
 */
export function NavIndicator({
  active: selector = '[aria-current="page"], [aria-current="true"], [aria-selected="true"]',
}: {
  active?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);

  useLayoutEffect(() => {
    const bar = ref.current;
    const nav = bar?.parentElement;
    if (!bar || !nav) return;
    nav.setAttribute('data-uwu-indicator', '');
    const sizes =
      typeof ResizeObserver === 'function' ? new ResizeObserver(() => place()) : undefined;
    let marked: HTMLElement | null = null;

    const place = () => {
      const active = nav.querySelector<HTMLElement>(selector);
      if (active !== marked) {
        if (marked) sizes?.unobserve(marked);
        marked?.removeAttribute('data-uwu-indicated');
        if (active) sizes?.observe(active);
        active?.setAttribute('data-uwu-indicated', '');
        marked = active;
      }
      if (!active) return bar.removeAttribute('data-on');
      const n = nav.getBoundingClientRect();
      const a = active.getBoundingClientRect();
      bar.style.setProperty(
        'translate',
        `${a.left - n.left - nav.clientLeft + nav.scrollLeft}px ${a.top - n.top - nav.clientTop + nav.scrollTop}px`,
      );
      bar.style.setProperty('width', `${a.width}px`);
      bar.style.setProperty('height', `${a.height}px`);
      bar.style.setProperty('border-radius', getComputedStyle(active).borderRadius);
      bar.setAttribute('data-on', '');
    };

    place();
    // Slide only after the first placement, so it doesn't fly in from the corner.
    const frame = requestAnimationFrame(() => bar.setAttribute('data-ready', ''));
    const mutations = new MutationObserver(place);
    mutations.observe(nav, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['aria-current', 'aria-selected', 'data-active'],
    });
    sizes?.observe(nav);
    void document.fonts?.ready.then(place); // the webfont changes the row widths
    return () => {
      cancelAnimationFrame(frame);
      mutations.disconnect();
      sizes?.disconnect();
      marked?.removeAttribute('data-uwu-indicated');
      nav.removeAttribute('data-uwu-indicator');
    };
  }, [selector]);

  return <span ref={ref} aria-hidden className="uwu-nav-indicator" />;
}
