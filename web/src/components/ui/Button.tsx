import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Icon, type IconName } from '../Icon';

export type ButtonVariant = 'default' | 'primary' | 'danger' | 'quiet' | 'quiet-danger';

type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
  /** How much the button stands out: `primary` once per view, `quiet` for actions in a list. */
  variant?: ButtonVariant;
  /** `small` in list heads, toolbars and cards; fields and buttons otherwise share one height. */
  size?: 'default' | 'small';
  /** An icon before the words. */
  icon?: IconName;
  /** Another class for layout (a margin, a place in a grid), never for looks. */
  className?: string;
  children?: ReactNode;
};

const VARIANT: Record<ButtonVariant, string | undefined> = {
  default: undefined,
  primary: 'primary',
  danger: 'danger',
  quiet: 'quiet',
  'quiet-danger': 'quiet danger-text',
};

/**
 * A button of the web vault and the admin portal. It is `type="button"` unless told otherwise,
 * so it never sends a form by accident; a dialog's safe choice carries `data-secondary`, so
 * Enter cannot trigger a risky one (see Modal).
 */
export function Button({
  variant = 'default',
  size = 'default',
  icon,
  className,
  type = 'button',
  children,
  ...rest
}: ButtonProps) {
  const classes = [VARIANT[variant], size === 'small' ? 'small' : undefined, className]
    .filter(Boolean)
    .join(' ');
  return (
    <button type={type} className={classes || undefined} {...rest}>
      {icon && <Icon name={icon} size={size === 'small' ? 14 : 15} />}
      {children}
    </button>
  );
}

type IconButtonProps = Omit<
  ButtonHTMLAttributes<HTMLButtonElement>,
  'className' | 'children' | 'aria-label'
> & {
  /** What it does, in words: the button's name for screen readers and its tooltip. */
  label: string;
  icon: IconName;
  /** `small` (24 px) only where space is short, like a heading's tool; never below 24 px. */
  size?: 'default' | 'small';
  className?: string;
};

/** A button that is only an icon. Its label is both its accessible name and its tooltip. */
export function IconButton({
  label,
  icon,
  size = 'default',
  className,
  type = 'button',
  title,
  ...rest
}: IconButtonProps) {
  const classes = ['icon-button', size === 'small' ? 'small' : undefined, className]
    .filter(Boolean)
    .join(' ');
  return (
    <button type={type} className={classes} aria-label={label} title={title ?? label} {...rest}>
      <Icon name={icon} size={size === 'small' ? 14 : 15} />
    </button>
  );
}
