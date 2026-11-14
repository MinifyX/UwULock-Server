/**
 * The circle reveal from @uwusuite/design 1.15 (src/lib/motion.ts), ported because the
 * web vault has its own styles. Page change, stagger and the nav pill are CSS in styles/motion.css.
 */

/** Same rule as the CSS: the system allows motion and Settings hasn't switched it off. */
export function motionAllowed(): boolean {
  if (document.documentElement.dataset.motion === 'reduced') return false;
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: no-preference)').matches
  );
}

/** A token like `--uwu-duration-count` in ms. */
export function tokenMs(name: string, fallback: number): number {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const ms = raw.endsWith('ms')
    ? parseFloat(raw)
    : raw.endsWith('s')
      ? parseFloat(raw) * 1000
      : NaN;
  return Number.isFinite(ms) ? ms : fallback;
}

/**
 * Uncovers `target` with a growing circle from the centre of `origin` (default: the first
 * `[data-uwu-reveal-origin]`). The window behind shows `--uwu-reveal-backdrop` meanwhile.
 * Does nothing without motion; never blocks input.
 */
export function revealFrom(target: HTMLElement, origin?: Element | null) {
  if (!motionAllowed() || typeof target.animate !== 'function') return;
  const from = origin ?? document.querySelector('[data-uwu-reveal-origin]');
  const box = target.getBoundingClientRect();
  let x = box.width / 2;
  let y = box.height / 2;
  if (from) {
    const o = from.getBoundingClientRect();
    x = o.left + o.width / 2 - box.left;
    y = o.top + o.height / 2 - box.top;
  }
  // Radius to the farthest corner, so the circle ends exactly when everything is uncovered.
  const r = Math.ceil(Math.hypot(Math.max(x, box.width - x), Math.max(y, box.height - y)));
  const root = document.documentElement;
  root.classList.add('uwu-revealing');
  const animation = target.animate(
    [{ clipPath: `circle(0px at ${x}px ${y}px)` }, { clipPath: `circle(${r}px at ${x}px ${y}px)` }],
    { duration: tokenMs('--uwu-duration-reveal', 480), easing: 'cubic-bezier(0.2, 0.9, 0.3, 1)' },
  );
  const done = () => root.classList.remove('uwu-revealing');
  animation.finished.then(done, done);
}

/** A ref for what appears after login or unlock: it opens in a circle from the logo. Stable, so it runs on mount only. */
export const revealOnMount = (el: HTMLElement | null) => {
  if (el) revealFrom(el);
};
