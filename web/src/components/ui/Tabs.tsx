import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';

export type Tab<T extends string> = {
  id: T;
  label: string;
  /** Something next to the label, like a count in a Badge. */
  extra?: ReactNode;
  disabled?: boolean;
};

/**
 * Tabs: the parts of a page (`line`, under a heading) or the views of a list (`segmented`). The
 * arrow keys, Home and End move between them and pick one; only the picked tab is in the Tab
 * order. `panelId(tab)` gives the id for `<TabPanel>`, so each tab names its panel.
 */
export function Tabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
  variant = 'line',
  idPrefix,
}: {
  /** The tab list's name for screen readers. */
  label: string;
  tabs: readonly Tab<T>[];
  value: T;
  onChange: (id: T) => void;
  variant?: 'line' | 'segmented';
  /** Ties the tabs to their panels; the same prefix goes to TabPanel. Without it, no panels. */
  idPrefix?: string;
}) {
  const list = useRef<HTMLDivElement>(null);
  const enabled = tabs.filter((tab) => !tab.disabled);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = enabled.findIndex((tab) => tab.id === value);
    const next =
      event.key === 'ArrowRight'
        ? enabled[(index + 1) % enabled.length]
        : event.key === 'ArrowLeft'
          ? enabled[(index - 1 + enabled.length) % enabled.length]
          : event.key === 'Home'
            ? enabled[0]
            : event.key === 'End'
              ? enabled[enabled.length - 1]
              : undefined;
    if (!next || event.altKey || event.ctrlKey || event.metaKey) return;
    event.preventDefault();
    onChange(next.id);
    list.current?.querySelector<HTMLElement>(`[data-tab="${CSS.escape(next.id)}"]`)?.focus();
  };

  return (
    <div
      ref={list}
      className={variant === 'segmented' ? 'segmented' : 'tabs'}
      role="tablist"
      aria-label={label}
      onKeyDown={onKeyDown}
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          data-tab={tab.id}
          id={idPrefix ? `${idPrefix}-tab-${tab.id}` : undefined}
          aria-controls={idPrefix ? `${idPrefix}-panel-${tab.id}` : undefined}
          aria-selected={tab.id === value}
          tabIndex={tab.id === value ? 0 : -1}
          disabled={tab.disabled}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.extra}
        </button>
      ))}
    </div>
  );
}

/** The content of the picked tab, named by its tab. */
export function TabPanel({
  idPrefix,
  tab,
  children,
  className,
}: {
  idPrefix: string;
  tab: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idPrefix}-panel-${tab}`}
      aria-labelledby={`${idPrefix}-tab-${tab}`}
      tabIndex={0}
      className={className}
    >
      {children}
    </div>
  );
}

/** A prefix for Tabs and TabPanel, unique on the page. */
export function useTabsId(): string {
  return useId().replace(/:/g, '');
}
