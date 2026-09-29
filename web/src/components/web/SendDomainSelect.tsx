import { useEffect, useState } from 'react';
import { account } from '../../lib/account';
import { useServerInfo } from '../../lib/branding';
import { listen } from '../../lib/events';
import { t, useLanguage } from '../../lib/i18n';
import { hostOfUrl, type SendDomain } from '../../lib/links';

const NONE: SendDomain[] = [];

/** The admin's send domains (§14), when there are any; empty otherwise. */
export function useSendDomains(): SendDomain[] {
  const info = useServerInfo();
  if (!info?.features?.includes('send-domains')) return NONE;
  return info.sendDomains ?? NONE;
}

let accountDefault: Promise<string | null> | null = null;

// Another account in this tab has its own.
void listen<{ state: string }>('vault-status', ({ payload }) => {
  if (payload.state === 'logged-out') accountDefault = null;
});

/** The account's default send domain, asked once per session; null: the main host. */
export function defaultSendDomain(): Promise<string | null> {
  accountDefault ??= account().then(
    (info) => info.sendDomainId ?? null,
    () => null,
  );
  return accountDefault;
}

/** After the settings changed it. */
export function rememberDefaultSendDomain(sendDomainId: string | null) {
  accountDefault = Promise.resolve(sendDomainId);
}

/**
 * The domain a new Send or file request starts with: the account's default, once known. `ready`
 * is false until then, so nothing is saved with the wrong one.
 */
export function useDefaultSendDomain(enabled: boolean): { value: string | null; ready: boolean } {
  const [value, setValue] = useState<{ value: string | null; ready: boolean }>({
    value: null,
    ready: !enabled,
  });
  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    void defaultSendDomain().then((found) => !stopped && setValue({ value: found, ready: true }));
    return () => {
      stopped = true;
    };
  }, [enabled]);
  return value;
}

/** Which address a link uses: this server's own or one of its send domains. */
export function SendDomainField({
  label,
  value,
  onChange,
  domains,
  hint,
  disabled,
  bare,
}: {
  label: string;
  value: string | null;
  onChange: (sendDomainId: string | null) => void;
  domains: SendDomain[];
  hint?: string;
  disabled?: boolean;
  /** Only the list, for a settings row that has its label already. */
  bare?: boolean;
}) {
  useLanguage();
  // A domain the admin deleted since: the link is on the main host again.
  const known = value && domains.some((domain) => domain.id === value) ? value : '';
  const select = (
    <select
      className="select"
      value={known}
      disabled={disabled}
      aria-label={bare ? label : undefined}
      onChange={(e) => onChange(e.target.value || null)}
    >
      <option value="">{t('{host} (Hauptadresse)', { host: location.host })}</option>
      {domains.map((domain) => (
        <option key={domain.id} value={domain.id}>
          {hostOfUrl(domain.url)}
        </option>
      ))}
    </select>
  );
  if (bare) return select;
  return (
    <label className="field">
      <span>{label}</span>
      {select}
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}
