import { useEffect, useState } from 'react';
import { account } from '../../lib/account';
import { errorText } from '../../lib/errors';
import { vaultItems } from '../../lib/api';
import { passwordReport, type Finding, type Report } from '../../lib/features';
import {
  missingTwoFactor,
  twofaDirectory,
  type MissingTwoFactor,
  type TwofaDirectory,
} from '../../lib/twofa';
import { t, useLanguage } from '../../lib/i18n';
import { Icon } from '../Icon';

type Props = {
  onOpen: (id: string) => void;
};

/**
 * The password check: weak passwords, passwords used more than once, passwords that were in a
 * breach, logins that send them without https, and logins for sites that offer two-step login
 * with an authenticator app when none is stored. Worked out in the browser; for breaches the
 * server only ever sees five characters of each password's hash, for two-step login nothing: the
 * list of sites comes from the server's copy of 2FA Directory.
 */
export function HealthReport({ onOpen }: Props) {
  useLanguage();
  // Whether the server may ask Have I Been Pwned.
  const [hibp, setHibp] = useState(true);
  useEffect(() => {
    account().then(
      (info) => setHibp(info.hibp),
      () => undefined,
    );
  }, []);
  const [report, setReport] = useState<Report | null>(null);
  const [twofa, setTwofa] = useState<{
    missing: MissingTwoFactor[];
    source: TwofaDirectory['source'];
  } | null>(null);
  const [twofaError, setTwofaError] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (breaches: boolean) => {
    setError(null);
    setBusy(t('Prüft …'));
    // The list of sites with two-step login comes alongside; without it the rest still counts.
    const directory = Promise.all([twofaDirectory(), vaultItems()]).then(
      ([list, items]) => {
        setTwofa({ missing: missingTwoFactor(items, list.entries), source: list.source });
        setTwofaError(false);
      },
      () => setTwofaError(true),
    );
    try {
      setReport(
        await passwordReport(breaches, (done, total) =>
          setBusy(t('Fragt Have I Been Pwned … {done} von {total}', { done, total })),
        ),
      );
      await directory;
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const group = (title: string, lead: string, list: Finding[], detail: (f: Finding) => string) =>
    list.length > 0 && (
      <section className="detail-card" key={title}>
        <h3 className="detail-card-title">
          {title} <span className="nav-count">{list.length}</span>
        </h3>
        <p className="field-hint">{lead}</p>
        {list.map((finding) => (
          <div className="detail-row" key={finding.id}>
            <div className="detail-text">
              <span className="detail-value">{finding.name || t('(ohne Namen)')}</span>
              <span className="detail-label">
                {[finding.subtitle, detail(finding)].filter(Boolean).join(' · ')}
              </span>
            </div>
            <div className="detail-actions">
              <button className="quiet" onClick={() => onOpen(finding.id)}>
                {t('Öffnen')}
              </button>
            </div>
          </div>
        ))}
      </section>
    );

  const findings = report?.findings ?? [];
  const breached = findings.filter((f) => (f.breached ?? 0) > 0);
  const reused = findings.filter((f) => f.reused > 0);
  const weak = findings.filter((f) => f.weak);
  const unsecured = findings.filter((f) => f.unsecured);
  const missing = twofa?.missing ?? [];
  const clean =
    report &&
    !breached.length &&
    !reused.length &&
    !weak.length &&
    !unsecured.length &&
    !missing.length;

  return (
    <section className="report-pane" aria-label={t('Passwortprüfung')}>
      <article className="detail">
        <header className="detail-head">
          <span className="item-tile" data-size="large" data-hue="4">
            <Icon name="pulse" size={26} />
          </span>
          <div className="detail-title">
            <h2>{t('Passwortprüfung')}</h2>
            <p className="chips">
              {report && (
                <span className="chip">{t('{n} Passwörter geprüft', { n: report.checked })}</span>
              )}
            </p>
          </div>
          <div className="detail-tools">
            <button className="primary" disabled={Boolean(busy)} onClick={() => void run(hibp)}>
              <Icon name="refresh" size={15} />
              {report ? t('Nochmal prüfen') : t('Jetzt prüfen')}
            </button>
          </div>
        </header>
        {!report && !busy && (
          <p className="dialog-lead">
            {hibp
              ? t(
                  'Findet schwache und doppelte Passwörter, Logins ohne https – und Passwörter aus bekannten Datenlecks. Dafür fragt dein Server Have I Been Pwned nach den ersten fünf Zeichen des Hashs jedes Passworts; das Passwort selbst verlässt diesen Browser nie. Dein Server sieht diese fünf Zeichen dabei, schreibt sie aber nirgends auf.',
                )
              : t(
                  'Findet schwache und doppelte Passwörter und Logins ohne https. Den Abgleich mit Datenlecks hat die Verwaltung dieses Servers ausgeschaltet.',
                )}
          </p>
        )}
        {busy && (
          <p className="dialog-lead" role="status">
            {busy}
          </p>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {report?.breachesIncomplete && (
          <p className="form-error" role="alert">
            {t(
              'Have I Been Pwned hat nicht für alle Passwörter geantwortet. Der Rest des Berichts stimmt; prüf später noch einmal.',
            )}
          </p>
        )}
        {clean && <p className="dialog-lead">{t('Alles gut: nichts gefunden ✧')}</p>}
        {group(
          t('In Datenlecks'),
          t('Diese Passwörter tauchen in bekannten Datenlecks auf. Ändere sie zuerst.'),
          breached,
          (f) => t('{n} Mal gesehen', { n: (f.breached ?? 0).toLocaleString() }),
        )}
        {group(
          t('Mehrfach benutzt'),
          t('Wird eines davon bekannt, sind die anderen Konten mit offen.'),
          reused,
          (f) => t('noch {n} Mal im Tresor', { n: f.reused }),
        )}
        {group(t('Schwach'), t('Zu kurz oder zu leicht zu erraten.'), weak, (f) =>
          t('{bits} Bit', { bits: f.bits }),
        )}
        {group(
          t('Ohne https'),
          t('Die Adresse beginnt mit http://: Das Passwort geht unverschlüsselt über das Netz.'),
          unsecured,
          () => '',
        )}
        {report && missing.length > 0 && (
          <section className="detail-card">
            <h3 className="detail-card-title">
              {t('2FA möglich, nicht eingerichtet')}{' '}
              <span className="nav-count">{missing.length}</span>
            </h3>
            <p className="field-hint">
              {t(
                'Diese Websites bieten Einmal-Codes aus einer Authenticator-App an, im Eintrag ist aber keiner hinterlegt. Richte die Zwei-Schritt-Anmeldung dort ein und trag den Schlüssel im Eintrag ein.',
              )}
            </p>
            {missing.map(({ item, entry }) => (
              <div className="detail-row" key={item.id}>
                <div className="detail-text">
                  <span className="detail-value">{item.name || t('(ohne Namen)')}</span>
                  <span className="detail-label">
                    {[item.host, entry.name !== item.name ? entry.name : null]
                      .filter(Boolean)
                      .join(' · ')}
                  </span>
                </div>
                <div className="detail-actions">
                  {entry.documentation && (
                    <a
                      className="button-link"
                      href={entry.documentation}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <Icon name="external" size={14} />
                      {t('Anleitung')}
                      <span className="sr-only">
                        {t('für {site} (neues Fenster)', { site: entry.name })}
                      </span>
                    </a>
                  )}
                  <button className="quiet" onClick={() => onOpen(item.id)}>
                    {t('Öffnen')}
                  </button>
                </div>
              </div>
            ))}
            {twofa && (
              <p className="field-hint">
                {t('Liste der Websites: {source}, {license}', {
                  source: twofa.source.name,
                  license: twofa.source.license,
                })}
              </p>
            )}
          </section>
        )}
        {report && twofaError && (
          <p className="field-hint" role="status">
            {t(
              'Die Liste der Websites mit Zwei-Schritt-Anmeldung war gerade nicht zu haben; dieser Teil fehlt im Bericht.',
            )}
          </p>
        )}
      </article>
    </section>
  );
}
