import type { ReactNode } from 'react';

/** Buttons side by side; they wrap on a narrow screen. `end` puts them at the far side. */
export function ButtonRow({ children, end }: { children: ReactNode; end?: boolean }) {
  return (
    <div className="button-row" data-end={end ? '' : undefined}>
      {children}
    </div>
  );
}
