import { useEffect, useRef, useState, type ReactNode } from 'react';

/**
 * A table of records (users, invitations, events): a card with a header row. On a narrow screen
 * it scrolls sideways inside its frame instead of being cut off; while it does, the frame takes
 * the keyboard focus, so it scrolls with the arrow keys too. Rows are plain <tr>s.
 */
export function Table({
  label,
  head,
  children,
}: {
  /** The table's name for screen readers, when no heading right above names it. */
  label?: string;
  /** The header cells, as <th>s. */
  head: ReactNode;
  children: ReactNode;
}) {
  const frame = useRef<HTMLDivElement>(null);
  const [scrolls, setScrolls] = useState(false);
  useEffect(() => {
    const element = frame.current;
    if (!element || typeof ResizeObserver === 'undefined') return;
    const check = () => setScrolls(element.scrollWidth > element.clientWidth + 1);
    const observer = new ResizeObserver(check);
    observer.observe(element);
    if (element.firstElementChild) observer.observe(element.firstElementChild);
    check();
    return () => observer.disconnect();
  }, []);
  return (
    <div
      className="table-scroll"
      ref={frame}
      tabIndex={scrolls ? 0 : undefined}
      role={scrolls && label ? 'region' : undefined}
      aria-label={scrolls && label ? label : undefined}
    >
      <table className="table" aria-label={label}>
        <thead>
          <tr>{head}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
