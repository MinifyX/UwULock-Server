import { useId, type ReactNode } from 'react';
import { Icon } from '../Icon';

/**
 * What can lock people out or lose data, set apart at the end of a page: a frame in the alarm
 * colour, a heading that says so, a line about why. Every action in it still asks first.
 */
export function DangerZone({
  heading,
  lead,
  children,
}: {
  heading: string;
  lead?: ReactNode;
  children?: ReactNode;
}) {
  const id = useId();
  return (
    <section className="danger-zone" aria-labelledby={id}>
      <h3 className="danger-zone-heading" id={id}>
        <Icon name="warning" size={15} />
        {heading}
      </h3>
      {lead && <p className="section-lead">{lead}</p>}
      {children}
    </section>
  );
}
