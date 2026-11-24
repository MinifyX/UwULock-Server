import { Hint, Icon, ICONS, type HintTone } from '@uwusuite/design';
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export type CalloutTone = 'info' | 'accent' | 'ok' | 'warning' | 'error';

const HINT: Record<CalloutTone, HintTone> = {
  info: 'info',
  accent: 'info',
  ok: 'success',
  warning: 'warning',
  error: 'danger',
};

const ICON: Record<CalloutTone, LucideIcon> = {
  info: ICONS.securityCheck,
  accent: ICONS.tip,
  ok: ICONS.done,
  warning: ICONS.warning,
  error: ICONS.error,
};

/**
 * A notice inside a page or a dialog, on @uwusuite/design's Hint: something to know (`info`), to
 * do (`accent`, with a pink icon), that went well (`ok`), that needs care (`warning`) or went
 * wrong (`error`, announced). The Hint has no icon, title or actions; UwULock's notices do.
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
  icon?: LucideIcon | null;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  const shown = icon === undefined ? ICON[tone] : icon;
  return (
    <Hint tone={HINT[tone]} className="callout flex items-start gap-2.5">
      {shown && (
        <Icon icon={shown} className={tone === 'accent' ? 'mt-0.5 text-pink-ink' : 'mt-0.5'} />
      )}
      <div className="grid min-w-0 flex-1 gap-1.5">
        {title && <p className="font-semibold">{title}</p>}
        {typeof children === 'string' ? <p>{children}</p> : children}
        {actions && <div className="mt-1 flex flex-wrap gap-2">{actions}</div>}
      </div>
    </Hint>
  );
}
