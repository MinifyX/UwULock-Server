import { useEffect, useRef, useState } from 'react';
import { motionAllowed, tokenMs } from '../../lib/motion';

/**
 * CountUp from @uwusuite/design 1.15, ported: a number that counts up to its value when it
 * appears, and from the old to the new one when it changes. Screen readers get only the final
 * value; without motion it just shows it. For overview numbers, not tables or lists.
 */
export function CountUp({
  value,
  format = (n) => n.toLocaleString(),
}: {
  value: number;
  format?: (n: number) => string;
}) {
  const target = Number.isFinite(value) ? value : 0;
  const [shown, setShown] = useState(() => (motionAllowed() ? 0 : target));
  const from = useRef(shown);

  useEffect(() => {
    const start = from.current;
    if (!motionAllowed() || start === target) {
      from.current = target;
      setShown(target);
      return;
    }
    const duration = tokenMs('--uwu-duration-count', 600);
    const t0 = performance.now();
    let frame = requestAnimationFrame(function step(now) {
      const t = Math.min(1, (now - t0) / duration);
      const v = t >= 1 ? target : start + (target - start) * (1 - (1 - t) ** 3); // ease-out cubic
      from.current = v;
      setShown(v);
      if (t < 1) frame = requestAnimationFrame(step);
    });
    return () => cancelAnimationFrame(frame);
  }, [target]);

  return (
    <>
      {/* Whole numbers count in whole steps. */}
      <span aria-hidden="true">{format(Number.isInteger(target) ? Math.round(shown) : shown)}</span>
      <span className="sr-only">{format(target)}</span>
    </>
  );
}
