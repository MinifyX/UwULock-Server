import type { ReactNode } from 'react';

/**
 * A table of records (users, invitations, events): a card with a header row. On a narrow screen
 * it scrolls sideways inside its frame instead of being cut off. Rows are plain <tr>s.
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
  return (
    <div className="table-scroll">
      <table className="table" aria-label={label}>
        <thead>
          <tr>{head}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
