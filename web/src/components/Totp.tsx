import type { TotpCode } from '../lib/api';
import { spacedCode } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';

/**
 * A one-time code counting down, and in the last seconds of its period the next one below it,
 * small, with a copy button of its own ("Nächster: 123 456"). The item details and the Send page
 * of an entry Send both show codes this way.
 */
export function TotpCodes({
  code,
  onCopyNext,
}: {
  code: TotpCode;
  /** Copies the next code; without it there is no button. */
  onCopyNext?: () => void;
}) {
  useLanguage();
  const fraction = code.remaining / code.period;
  const circumference = 2 * Math.PI * 9;
  return (
    <span className="totp-stack">
      <span className="totp" data-soon={code.remaining <= 5 || undefined}>
        <span className="totp-code">{spacedCode(code.code)}</span>
        <svg className="totp-ring" viewBox="0 0 24 24" width="22" height="22" aria-hidden>
          <circle cx="12" cy="12" r="9" className="totp-track" />
          <circle
            cx="12"
            cy="12"
            r="9"
            className="totp-left"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - fraction)}
            transform="rotate(-90 12 12)"
          />
        </svg>
        <span className="totp-seconds">
          {code.remaining}
          <span className="sr-only"> {t('Sekunden')}</span>
        </span>
      </span>
      {code.showNext && (
        <span className="totp-next" data-totp-next>
          <span>
            {t('Nächster:')} <span className="mono">{spacedCode(code.next)}</span>
          </span>
          {onCopyNext && (
            <button
              type="button"
              className="icon-button small"
              onClick={onCopyNext}
              aria-label={t('Nächsten Code kopieren')}
              title={t('Nächsten Code kopieren')}
            >
              <Icon name="copy" size={13} />
            </button>
          )}
        </span>
      )}
    </span>
  );
}
