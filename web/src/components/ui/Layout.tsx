import { Children, isValidElement, useId, type ReactNode } from 'react';
import { Button } from './Button';
import { SettingContext } from './setting';

/**
 * A card: a framed block on the page (a channel, a check, a domain). An optional head with a
 * heading and things beside it (a Badge, buttons), then the content with even gaps.
 */
export function Card({
  heading,
  aside,
  children,
  className,
  as: Tag = 'section',
}: {
  heading?: ReactNode;
  /** Beside the heading, at its end. */
  aside?: ReactNode;
  children?: ReactNode;
  className?: string;
  as?: 'section' | 'div' | 'li' | 'article';
}) {
  return (
    <Tag className={['card', className].filter(Boolean).join(' ')}>
      {(heading || aside) && (
        <div className="card-head">
          {heading && <h3 className="card-heading">{heading}</h3>}
          {aside && (
            <>
              <span className="spacer" />
              {aside}
            </>
          )}
        </div>
      )}
      {children}
    </Tag>
  );
}

/**
 * A part of a page or of a settings section: a small heading, a line in plain words about it,
 * then its rows or fields. Sections one after the other keep one gap.
 */
export function Section({
  heading,
  lead,
  children,
  className,
}: {
  heading?: string;
  lead?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  const id = useId();
  return (
    <section
      className={['section', className].filter(Boolean).join(' ')}
      aria-labelledby={heading ? id : undefined}
    >
      {heading && (
        <h3 className="section-heading" id={id}>
          {heading}
        </h3>
      )}
      {lead && <p className="section-lead">{lead}</p>}
      {children}
    </section>
  );
}

/**
 * One setting: its name and a line about it on the left, its control on the right.
 *
 * A switch, a select or a choice takes the line about it as its description. Buttons alone (like
 * "Einrichten …") are a group named after the setting, so a screen reader says which setting a
 * button belongs to.
 */
export function SettingRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: ReactNode;
  children?: ReactNode;
}) {
  const id = useId();
  const labelId = `${id}-label`;
  const descriptionId = description ? `${id}-description` : undefined;
  // Buttons ("Einrichten …") say nothing of the setting they belong to: they go in a group named
  // after it. A field, a switch or a select has a name of its own and stays as it is.
  const buttons = Children.toArray(children).filter(isValidElement);
  const grouped =
    buttons.length > 0 &&
    buttons.every((child) => child.type === 'button' || child.type === Button);
  return (
    <div className="setting-row">
      <div className="setting-text">
        <p className="setting-label" id={labelId}>
          {label}
        </p>
        {description && (
          <p className="setting-description" id={descriptionId}>
            {description}
          </p>
        )}
      </div>
      {children && (
        <SettingContext.Provider value={{ labelId, descriptionId }}>
          <div
            className="setting-control"
            role={grouped ? 'group' : undefined}
            aria-labelledby={grouped ? labelId : undefined}
            aria-describedby={grouped ? descriptionId : undefined}
          >
            {children}
          </div>
        </SettingContext.Provider>
      )}
    </div>
  );
}

/** Buttons side by side; they wrap on a narrow screen. `end` puts them at the far side. */
export function ButtonRow({ children, end }: { children: ReactNode; end?: boolean }) {
  return (
    <div className="button-row" data-end={end ? '' : undefined}>
      {children}
    </div>
  );
}
