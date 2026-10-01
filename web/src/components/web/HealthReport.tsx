import { useCallback, useEffect, useMemo, useState } from 'react';
import { account } from '../../lib/account';
import {
  breachAfterChange,
  breachIndex,
  changeIgnores,
  checkEmails,
  emailOptIn,
  isAddress,
  loadIgnores,
  setEmailOptIn,
  siteBreaches,
  switchesOf,
  unignore,
  type BreachSwitches,
  type EmailResult,
  type OptIn,
  type ProblemKind,
  type SiteBreach,
  type SiteBreachList,
  type StoredIgnores,
} from '../../lib/breaches';
import { errorText } from '../../lib/errors';
import { currentProfile, vaultItems } from '../../lib/api';
import {
  passwordReport,
  saveReport,
  savedReport,
  type Finding,
  type Report,
} from '../../lib/features';
import {
  missingTwoFactor,
  twofaDirectory,
  type MissingTwoFactor,
  type TwofaDirectory,
} from '../../lib/twofa';
import { useSwitch } from '../../lib/switches';
import { t, useLanguage } from '../../lib/i18n';
import { Icon } from '../Icon';
import { breachText, hidden, problemTitle } from './HealthReview';

type Props = {
  onOpen: (id: string) => void;
  /** To the review one login at a time. */
  onReview?: () => void;
};

/**
 * The password check: weak passwords, passwords used more than once, passwords that were in a
 * breach, logins that send them without https, and logins for sites that offer two-step login
 * with an authenticator app when none is stored. Worked out in the browser; for breaches the
 * server only ever sees five characters of each password's hash, for two-step login nothing: the
 * list of sites comes from the server's copy of 2FA Directory.
 */
export function HealthReport({ onOpen, onReview }: Props) {
  useLanguage();
  // Which breach sources the server offers, and whether this account agreed to the check of
  // its addresses.
  const [switches, setSwitches] = useState<BreachSwitches>({
    hibp: true,
    xonPasswords: false,
    siteBreaches: false,
    emailCheck: false,
    changePassword: false,
  });
  const [optIn, setOptIn] = useState<OptIn | null>(null);
  useEffect(() => {
    account().then(
      (info) => {
        const on = switchesOf(info);
        setSwitches(on);
        if (on.emailCheck) emailOptIn().then(setOptIn, () => undefined);
      },
      () => undefined,
    );
  }, []);
  const hibp = switches.hibp || switches.xonPasswords;
  const [sites, setSites] = useState<SiteBreachList | null>(null);
  useEffect(() => {
    if (switches.siteBreaches) siteBreaches().then(setSites, () => undefined);
  }, [switches.siteBreaches]);
  const siteIndex = useMemo(() => (sites ? breachIndex(sites.breaches) : null), [sites]);
  const [ignores, setIgnores] = useState<StoredIgnores | null>(null);
  useEffect(() => {
    loadIgnores().then(setIgnores, () => undefined);
  }, []);
  const [emails, setEmails] = useState<{
    results: EmailResult[];
    retryAfter: number | null;
  } | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  // When the report shown was made: the last check, kept encrypted on the server.
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [twofa, setTwofa] = useState<{
    missing: MissingTwoFactor[];
    source: TwofaDirectory['source'];
  } | null>(null);
  const [twofaError, setTwofaError] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The list of sites with two-step login, beside the report; without it the rest still counts.
  // Switched off on the server, that part is left out without a word.
  const directoryOn = useSwitch('twofa-directory');
  const checkDirectory = useCallback((): Promise<void> => {
    if (!directoryOn) {
      setTwofa(null);
      setTwofaError(false);
      return Promise.resolve();
    }
    return Promise.all([twofaDirectory(), vaultItems()]).then(
      ([list, items]) => {
        setTwofa({ missing: missingTwoFactor(items, list.entries), source: list.source });
        setTwofaError(false);
      },
      () => setTwofaError(true),
    );
  }, [directoryOn]);

  // The last check's report, if one was saved: shown until the next check.
  useEffect(() => {
    let current = true;
    savedReport().then(
      (saved) => {
        if (!current || !saved) return;
        setReport((shown) => shown ?? saved.report);
        setSavedAt((shown) => shown ?? saved.date);
        void checkDirectory();
      },
      () => undefined,
    );
    return () => {
      current = false;
    };
  }, [checkDirectory]);

  const run = async () => {
    setError(null);
    setBusy(t('Prüft …'));
    const directory = checkDirectory();
    try {
      const fresh = await passwordReport(
        { hibp: switches.hibp, xon: switches.xonPasswords },
        (done, total) => setBusy(t('Fragt nach Datenlecks … {done} von {total}', { done, total })),
      );
      setReport(fresh);
      setSavedAt(new Date().toISOString());
      // Kept for next time; a report that could not be saved is still shown.
      saveReport(fresh).then(setSavedAt, () => undefined);
      await directory;
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const checkAddresses = async () => {
    setError(null);
    setBusy(t('Prüft Adressen …'));
    try {
      const items = await vaultItems();
      const own = currentProfile()?.email as string | undefined;
      const addresses = [
        ...(own ? [own] : []),
        ...items
          .filter((item) => item.kind === 'login' && !item.deleted && isAddress(item.subtitle))
          .map((item) => item.subtitle as string),
      ];
      setEmails(
        await checkEmails(addresses, (done, total) =>
          setBusy(t('Prüft Adressen … {done} von {total}', { done, total })),
        ),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const agree = async (on: boolean) => {
    try {
      setOptIn(await setEmailOptIn(on));
      if (!on) setEmails(null);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const undoIgnore = async (id: string, kind: ProblemKind) => {
    if (!ignores) return;
    try {
      setIgnores(await changeIgnores(ignores, (list) => unignore(list, id, kind)));
    } catch (e) {
      setError(errorText(e));
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
  const open = (kind: ProblemKind) => (f: { id: string }) => !hidden(ignores, f.id, kind);
  const breached = findings.filter((f) => (f.breached ?? 0) > 0).filter(open('breached'));
  const reused = findings.filter((f) => f.reused > 0).filter(open('reused'));
  const weak = findings.filter((f) => f.weak).filter(open('weak'));
  const unsecured = findings.filter((f) => f.unsecured).filter(open('unsecured'));
  const missing = (twofa?.missing ?? []).filter(({ item }) => open('twofa')(item));
  const siteBreached: { finding: Finding; breach: SiteBreach }[] = siteIndex
    ? findings
        .map((finding) => ({ finding, breach: breachAfterChange(siteIndex, finding) }))
        .filter((x): x is { finding: Finding; breach: SiteBreach } => x.breach !== null)
        .filter(({ finding }) => open('siteBreach')(finding))
    : [];
  const names = new Map(findings.map((f) => [f.id, f.name]));
  const ignored = (ignores?.list.ignored ?? []).filter((entry) => names.has(entry.itemId));
  const xonNames = useMemo(() => {
    const byName = new Map<string, SiteBreach>();
    for (const breach of sites?.breaches ?? []) {
      if (breach.sources.xon) byName.set(breach.sources.xon, breach);
    }
    return byName;
  }, [sites]);
  const problems =
    breached.length +
    reused.length +
    weak.length +
    unsecured.length +
    missing.length +
    siteBreached.length;
  const clean = report && !problems;

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
              {report && savedAt && (
                <span className="chip">
                  {t('Stand: {when}', { when: new Date(savedAt).toLocaleString() })}
                </span>
              )}
            </p>
          </div>
          <div className="detail-tools">
            {report && problems > 0 && onReview && (
              <button disabled={Boolean(busy)} onClick={onReview}>
                <Icon name="layers" size={15} />
                {t('Durchgehen')}
              </button>
            )}
            <button className="primary" disabled={Boolean(busy)} onClick={() => void run()}>
              <Icon name="refresh" size={15} />
              {report ? t('Nochmal prüfen') : t('Jetzt prüfen')}
            </button>
          </div>
        </header>
        {!report && !busy && (
          <p className="dialog-lead">
            {hibp
              ? t(
                  'Findet schwache und doppelte Passwörter, Logins ohne https – und Passwörter aus bekannten Datenlecks. Dafür fragt dein Server Have I Been Pwned (die ersten fünf Zeichen eines SHA-1) und XposedOrNot (die ersten zehn Zeichen eines Keccak-512) nach dem Hash jedes Passworts; das Passwort selbst verlässt diesen Browser nie. Dein Server sieht diese Zeichen dabei, schreibt sie aber nirgends auf.',
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
              'Eine Quelle für Datenlecks hat nicht für alle Passwörter geantwortet. Der Rest des Berichts stimmt; prüf später noch einmal.',
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
        {siteBreached.length > 0 && (
          <section className="detail-card">
            <h3 className="detail-card-title">
              {problemTitle('siteBreach')} <span className="nav-count">{siteBreached.length}</span>
            </h3>
            <p className="field-hint">
              {t(
                'Bei diesen Websites wurden Passwörter gestohlen, nachdem du deines zuletzt geändert hast. Ändere es dort.',
              )}
            </p>
            {siteBreached.map(({ finding, breach }) => (
              <div className="detail-row" key={finding.id}>
                <div className="detail-text">
                  <span className="detail-value">{finding.name || t('(ohne Namen)')}</span>
                  <span className="detail-label">
                    {[finding.subtitle, breachText(breach)].filter(Boolean).join(' · ')}
                  </span>
                </div>
                <div className="detail-actions">
                  <button className="quiet" onClick={() => onOpen(finding.id)}>
                    {t('Öffnen')}
                  </button>
                </div>
              </div>
            ))}
            {sites && (
              <p className="field-hint">
                {t('Listen der Datenlecks: {sources}', {
                  sources: sites.sources
                    .map((source) =>
                      source.license ? `${source.name} (${source.license})` : source.name,
                    )
                    .join(', '),
                })}
              </p>
            )}
          </section>
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
        {switches.emailCheck && (
          <section className="detail-card" data-testid="email-check">
            <h3 className="detail-card-title">{t('Deine Adressen in Datenlecks')}</h3>
            {optIn?.optedIn ? (
              <>
                <p className="field-hint">
                  {t(
                    'Dein Server fragt XposedOrNot nach deiner Kontoadresse und den Adressen, die in Logins als Benutzername stehen. Dafür geht jede Adresse im Klartext an XposedOrNot; dein Server merkt sich die Antworten eine Woche lang, nur unter einem Hash der Adresse.',
                  )}
                </p>
                <div className="detail-actions">
                  <button disabled={Boolean(busy)} onClick={() => void checkAddresses()}>
                    {t('Adressen prüfen')}
                  </button>
                  <button className="quiet" onClick={() => void agree(false)}>
                    {t('Zustimmung zurücknehmen')}
                  </button>
                </div>
                {emails?.results.map((result) => (
                  <div className="detail-row" key={result.email}>
                    <div className="detail-text">
                      <span className="detail-value">{result.email}</span>
                      <span className="detail-label">
                        {result.status === 'found'
                          ? result.breaches
                              .map((name) => {
                                const known = xonNames.get(name);
                                return known?.date
                                  ? `${known.title} (${new Date(`${known.date}T00:00:00Z`).getFullYear()})`
                                  : name;
                              })
                              .join(', ')
                          : result.status === 'clean'
                            ? t('In keinem bekannten Datenleck')
                            : result.status === 'later'
                              ? t('Später – das Kontingent des Servers ist gerade aufgebraucht')
                              : t('XposedOrNot hat nicht geantwortet')}
                      </span>
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <>
                <p className="field-hint">
                  {t(
                    'Auf Wunsch fragt dein Server XposedOrNot, ob deine Adressen in Datenlecks auftauchen. Dafür schickt er jede Adresse im Klartext an XposedOrNot (xposedornot.com) – deine Passwörter und deine anderen Daten nicht.',
                  )}
                </p>
                <div className="detail-actions">
                  <button onClick={() => void agree(true)}>{t('Zustimmen und einschalten')}</button>
                </div>
              </>
            )}
          </section>
        )}
        {ignored.length > 0 && (
          <section className="detail-card" data-testid="ignored">
            <h3 className="detail-card-title">
              {t('Ignoriert')} <span className="nav-count">{ignored.length}</span>
            </h3>
            <p className="field-hint">
              {t('Diese Hinweise zeigt die Prüfung nicht mehr, auf keinem Gerät.')}
            </p>
            {ignored.map((entry) => (
              <div className="detail-row" key={`${entry.itemId}:${entry.kind}`}>
                <div className="detail-text">
                  <span className="detail-value">
                    {names.get(entry.itemId) || t('(ohne Namen)')}
                  </span>
                  <span className="detail-label">{problemTitle(entry.kind)}</span>
                </div>
                <div className="detail-actions">
                  <button
                    className="quiet"
                    onClick={() => void undoIgnore(entry.itemId, entry.kind)}
                  >
                    {t('Rückgängig')}
                  </button>
                </div>
              </div>
            ))}
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
