import { t, useLanguage } from '../../lib/i18n';
import { NyuScene } from '../nyu/scenes';

/**
 * Where a link led to something this server has switched off (docs/features.md): said plainly,
 * with the way back. `vault` is false on a page for people without an account.
 */
export function Unavailable({ vault = true }: { vault?: boolean }) {
  useLanguage();
  return (
    <div className="lock">
      <div className="lock-card" role="status">
        <NyuScene name="sleepy" className="lock-scene" />
        <h1 className="card-title">{t('Nicht auf diesem Server')}</h1>
        <p className="dialog-lead">
          {vault
            ? t(
                'Das gibt es auf diesem Server gerade nicht. Ein Admin kann es im Admin-Portal unter Funktionen einschalten; was du dort schon hattest, ist dann wieder da.',
              )
            : t(
                'Das gibt es auf diesem Server gerade nicht. Frag die Person, die dir den Link geschickt hat.',
              )}
        </p>
        {vault && (
          <div className="form-actions">
            <span className="spacer" />
            <button className="primary" onClick={() => (location.hash = '')}>
              {t('Zum Tresor')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
