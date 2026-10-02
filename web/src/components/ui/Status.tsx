import type { ReactNode } from 'react';
import { t, useLanguage } from '../../lib/i18n';
import { Icon, type IconName } from '../Icon';

export type Tone = 'accent' | 'ok' | 'alarm' | 'neutral';

/** A short label on a pill: a count, a state ("Aktiv", "Fällig"). */
export function Badge({
  tone = 'accent',
  children,
  label,
}: {
  tone?: Tone;
  children: ReactNode;
  /** What a bare number means, for screen readers ("3 neue Hinweise"). */
  label?: string;
}) {
  return (
    <span className="badge" data-tone={tone === 'accent' ? undefined : tone} aria-label={label}>
      {children}
    </span>
  );
}

export type CalloutTone = 'info' | 'accent' | 'ok' | 'warning' | 'error';

const ICON: Record<CalloutTone, IconName> = {
  info: 'shield',
  accent: 'sparkles',
  ok: 'check',
  warning: 'warning',
  error: 'warning',
};

/**
 * A notice inside a page or a dialog: something to know (`info`), to do (`accent`), that went
 * well (`ok`), that needs care (`warning`) or went wrong (`error`). Errors are announced; the
 * others are read when reached.
 */
export function Callout({
  tone = 'info',
  title,
  icon,
  actions,
  children,
}: {
  tone?: CalloutTone;
  title?: ReactNode;
  /** Another icon, or `null` for none. */
  icon?: IconName | null;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  const shown = icon === undefined ? ICON[tone] : icon;
  return (
    <div
      className="callout"
      data-tone={tone === 'info' ? undefined : tone}
      role={tone === 'error' ? 'alert' : undefined}
    >
      {shown && <Icon name={shown} size={16} />}
      <div className="callout-body">
        {title && <p className="callout-title">{title}</p>}
        {typeof children === 'string' ? <p>{children}</p> : children}
        {actions && <div className="callout-actions">{actions}</div>}
      </div>
    </div>
  );
}

/**
 * A secret that is not shown: dots on the screen, "verborgen" for screen readers, which otherwise
 * read every dot out ("Punkt Punkt Punkt …").
 */
export function Masked({ text = '••••••••••••' }: { text?: string }) {
  useLanguage();
  return (
    <span className="masked">
      <span aria-hidden="true">{text}</span>
      <span className="sr-only">{t('verborgen')}</span>
    </span>
  );
}
