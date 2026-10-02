import { useCallback, useEffect, useRef, useState } from 'react';
import { account } from '../../lib/account';
import { savePassword, vaultItems, type ItemSummary } from '../../lib/api';
import {
  breachIndex,
  cardsOf,
  changeIgnores,
  changePasswordPage,
  ignore,
  isIgnored,
  loadIgnores,
  siteBreaches,
  switchesOf,
  unignore,
  type BreachSwitches,
  type Card,
  type Problem,
  type ProblemKind,
  type SiteBreach,
  type StoredIgnores,
} from '../../lib/breaches';
import { errorText } from '../../lib/errors';
import { passwordReport, saveReport, savedReport, type Report } from '../../lib/features';
import { t, useLanguage } from '../../lib/i18n';
import { useSwitch } from '../../lib/switches';
import { toast } from '../../lib/toast';
import { missingTwoFactor, twofaDirectory } from '../../lib/twofa';
import { GeneratorDialog } from '../GeneratorDialog';
import { Icon } from '../Icon';
import { ItemTile } from '../ItemTile';

type Props = {
  /** Back to the report. */
  onBack: () => void;
  onOpen: (id: string) => void;
};

/** Logins skipped with "Later" stay skipped while this tab is open. */
const LATER_KEY = 'uwulock.review.later';

function laterIds(): Set<string> {
  try {
    return new Set(JSON.parse(window.sessionStorage.getItem(LATER_KEY) ?? '[]') as string[]);
  } catch {
    return new Set();
  }
}

function keepLater(ids: Set<string>) {
  try {
    window.sessionStorage.setItem(LATER_KEY, JSON.stringify([...ids]));
  } catch {
    // Only a convenience.
  }
}

/** How far a card has to be dragged to count as a swipe. */
const SWIPE = 80;

export function problemTitle(kind: ProblemKind): string {
  switch (kind) {
    case 'breached':
      return t('Passwort in Datenlecks');
    case 'siteBreach':
      return t('Datenleck nach deiner letzten Passwortänderung');
    case 'reused':
      return t('Mehrfach benutzt');
    case 'weak':
      return t('Schwach');
    case 'unsecured':
      return t('Ohne https');
    case 'twofa':
      return t('2FA möglich, nicht eingerichtet');
  }
}

function sourceNames(sources: string[]): string {
  const names: Record<string, string> = { hibp: 'Have I Been Pwned', xon: 'XposedOrNot' };
  return sources
    .map((source) => (Object.hasOwn(names, source) ? names[source] : source))
    .join(', ');
}

export function problemDetail(problem: Problem): string {
  switch (problem.kind) {
    case 'breached':
      return [
        t('{n} Mal gesehen', { n: problem.count.toLocaleString() }),
        problem.sources.length ? sourceNames(problem.sources) : null,
      ]
        .filter(Boolean)
        .join(' · ');
    case 'siteBreach':
      return breachText(problem.breach);
    case 'reused':
      return t('noch {n} Mal im Tresor', { n: problem.others });
    case 'weak':
      return t('{bits} Bit', { bits: problem.bits });
    case 'unsecured':
      return t('Die Adresse beginnt mit http://');
    case 'twofa':
      return t('Die Website bietet Einmal-Codes aus einer Authenticator-App an.');
  }
}

export function breachText(breach: SiteBreach): string {
  return t('{site}, {date} – {sources}', {
    site: breach.title,
    date: breach.date ? new Date(`${breach.date}T00:00:00Z`).toLocaleDateString() : '?',
    sources: sourceNames(Object.keys(breach.sources)),
  });
}

/**
 * The password check, one login at a time: a stack of cards, one per login with a problem,
 * swiped (or moved with the arrow keys) back and forth. Each card offers what fixes it: the
 * site's change-password page, a new password saved to the item, "later" for this session, and
 * "ignore" per problem — kept encrypted on the server, so every UwULock app knows it.
 */
export function HealthReview({ onBack, onOpen }: Props) {
  useLanguage();
  const [switches, setSwitches] = useState<BreachSwitches | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [sites, setSites] = useState<Map<string, SiteBreach[]> | null>(null);
  const [twofa, setTwofa] = useState<Map<string, { documentation: string | null }>>(new Map());
  const [ignores, setIgnores] = useState<StoredIgnores | null>(null);
  const [cards, setCards] = useState<Card[] | null>(null);
  const [index, setIndex] = useState(0);
  const [later, setLater] = useState<Set<string>>(laterIds);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);
  /** Logins that got a new password here: their password problems are solved. */
  const [renewed, setRenewed] = useState<Set<string>>(new Set());
  const twofaOn = useSwitch('twofa-directory');

  // Everything the cards need: the switches, the last report (or a fresh one), the vault's
  // items, the lists of breached sites and 2FA sites, and the ignore list.
  useEffect(() => {
    let current = true;
    void (async () => {
      try {
        setBusy(t('Lädt …'));
        const info = await account();
        const on = switchesOf(info);
        if (!current) return;
        setSwitches(on);
        const [saved, vault, ignored] = await Promise.all([
          savedReport().catch(() => null),
          vaultItems(),
          loadIgnores(),
        ]);
        let shown = saved?.report ?? null;
        if (!shown) {
          setBusy(t('Prüft …'));
          shown = await passwordReport({ hibp: on.hibp, xon: on.xonPasswords });
          saveReport(shown).catch(() => undefined);
        }
        const [siteList, directory] = await Promise.all([
          on.siteBreaches ? siteBreaches().catch(() => null) : Promise.resolve(null),
          twofaOn ? twofaDirectory().catch(() => null) : Promise.resolve(null),
        ]);
        if (!current) return;
        setItems(vault);
        setReport(shown);
        setIgnores(ignored);
        setSites(siteList ? breachIndex(siteList.breaches) : null);
        setTwofa(
          new Map(
            (directory ? missingTwoFactor(vault, directory.entries) : []).map(({ item, entry }) => [
              item.id,
              { documentation: entry.documentation },
            ]),
          ),
        );
      } catch (e) {
        if (current) setError(errorText(e));
      } finally {
        if (current) setBusy(null);
      }
    })();
    return () => {
      current = false;
    };
  }, [twofaOn]);

  // The stack is laid once: ignoring or fixing changes a card, it does not reshuffle the rest.
  useEffect(() => {
    if (!report || !ignores || cards) return;
    const live = new Set(items.filter((item) => !item.deleted).map((item) => item.id));
    const findings = report.findings.filter((finding) => live.has(finding.id));
    const all = cardsOf({ ...report, findings }, { sites, twofa, ignored: ignores.list });
    setCards(all.filter((card) => !later.has(card.finding.id)));
  }, [report, ignores, items, sites, twofa, later, cards]);

  const total = cards?.length ?? 0;
  const card = cards && index < total ? cards[index] : null;
  const summary = card ? items.find((item) => item.id === card.finding.id) : undefined;

  const go = useCallback(
    (step: number) => setIndex((at) => Math.min(Math.max(at + step, 0), Math.max(total - 1, 0))),
    [total],
  );

  // The arrow keys, while no field and no dialog has them.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey || generating) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest('input, textarea, select, [role="dialog"]')) return;
      if (event.key === 'ArrowRight') {
        event.preventDefault();
        go(1);
      } else if (event.key === 'ArrowLeft') {
        event.preventDefault();
        go(-1);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go, generating]);

  // The change-password page of the card shown, asked for ahead so the link is ready.
  const [page, setPage] = useState<{ id: string; url: string | null } | null>(null);
  useEffect(() => {
    setPage(null);
    if (!card || !switches?.changePassword || !card.finding.host) return;
    let current = true;
    const id = card.finding.id;
    void changePasswordPage(card.finding.host).then((url) => {
      if (current) setPage({ id, url });
    });
    return () => {
      current = false;
    };
  }, [card, switches]);

  const fallback =
    card?.finding.uri ?? (card?.finding.host ? `https://${card.finding.host}/` : null);
  const target =
    (page && card && page.id === card.finding.id ? page.url : null) ??
    (fallback && /^https?:\/\//i.test(fallback) ? fallback : null);

  // ── Swiping ──
  const drag = useRef<{ x: number; y: number; id: number; moved: boolean } | null>(null);
  const [dx, setDx] = useState(0);
  const onPointerDown = (event: React.PointerEvent) => {
    if (event.button !== 0) return;
    drag.current = { x: event.clientX, y: event.clientY, id: event.pointerId, moved: false };
  };
  const onPointerMove = (event: React.PointerEvent) => {
    const start = drag.current;
    if (!start || start.id !== event.pointerId) return;
    const x = event.clientX - start.x;
    const y = event.clientY - start.y;
    if (!start.moved && Math.abs(x) > 10 && Math.abs(x) > Math.abs(y)) {
      start.moved = true;
      (event.currentTarget as HTMLElement).setPointerCapture?.(event.pointerId);
    }
    if (start.moved) setDx(x);
  };
  const onPointerUp = (event: React.PointerEvent) => {
    const start = drag.current;
    drag.current = null;
    if (!start || !start.moved) return;
    const x = event.clientX - start.x;
    setDx(0);
    if (x <= -SWIPE) go(1);
    else if (x >= SWIPE) go(-1);
  };
  // A drag is not a click on the button it began on.
  const onClickCapture = (event: React.MouseEvent) => {
    if (dx !== 0) event.stopPropagation();
  };

  const changeIgnore = async (id: string, kind: ProblemKind, on: boolean) => {
    if (!ignores) return;
    try {
      const next = await changeIgnores(ignores, (list) =>
        on ? ignore(list, id, kind) : unignore(list, id, kind),
      );
      setIgnores(next);
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const skip = () => {
    if (!card) return;
    const next = new Set(later);
    next.add(card.finding.id);
    setLater(next);
    keepLater(next);
    setCards((all) => all?.filter((c) => c.finding.id !== card.finding.id) ?? null);
    setIndex((at) => Math.min(at, Math.max(total - 2, 0)));
  };

  const saveNew = async (password: string) => {
    const id = generating;
    setGenerating(null);
    if (!id || !report) return;
    try {
      await savePassword(id, password);
      setRenewed((done) => new Set(done).add(id));
      // The kept report knows of it too, until the next check.
      const fixed: Report = {
        ...report,
        findings: report.findings.map((finding) =>
          finding.id === id
            ? {
                ...finding,
                breached: report.breachesChecked ? 0 : null,
                breachSources: [],
                weak: false,
                reused: 0,
                passwordChanged: new Date().toISOString(),
              }
            : finding,
        ),
      };
      setReport(fixed);
      saveReport(fixed).catch(() => undefined);
      toast(t('Neues Passwort gespeichert; das alte steht im Verlauf des Eintrags.'));
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const passwordProblem = (kind: ProblemKind) =>
    kind === 'breached' || kind === 'siteBreach' || kind === 'reused' || kind === 'weak';

  return (
    <section
      className="report-pane"
      aria-label={t('Passwörter durchgehen')}
      tabIndex={-1}
      data-main-content
    >
      <article className="detail review">
        <header className="detail-head">
          <span className="item-tile" data-size="large" data-hue="4">
            <Icon name="pulse" size={26} />
          </span>
          <div className="detail-title">
            <h2>{t('Passwörter durchgehen')}</h2>
            <p className="chips">
              {total > 0 && (
                <span className="chip" data-testid="review-progress">
                  {t('{n} von {total}', { n: Math.min(index + 1, total), total })}
                </span>
              )}
              {/* Said on every move: which card it is now, not only its number. */}
              <span className="sr-only" aria-live="polite">
                {card
                  ? t('{n} von {total}: {name}', {
                      n: Math.min(index + 1, total),
                      total,
                      name: card.finding.name || t('(ohne Namen)'),
                    })
                  : ''}
              </span>
            </p>
          </div>
          <div className="detail-tools">
            <button className="quiet" onClick={onBack}>
              {t('Zum Bericht')}
            </button>
          </div>
        </header>
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
        {cards && total === 0 && !busy && (
          <p className="dialog-lead">
            {t('Nichts mehr durchzugehen ✧ Ignoriertes findest du im Bericht.')}
          </p>
        )}
        {card && (
          <>
            <p className="field-hint review-hint">{t('Wischen oder Pfeiltasten ← → blättern.')}</p>
            <div
              className="review-stack"
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerCancel={() => {
                drag.current = null;
                setDx(0);
              }}
              onClickCapture={onClickCapture}
            >
              {index + 1 < total && <div className="review-card review-card-behind" aria-hidden />}
              <section
                className="review-card"
                key={card.finding.id}
                aria-roledescription={t('Karte')}
                aria-label={card.finding.name || t('(ohne Namen)')}
                data-testid="review-card"
                style={
                  dx
                    ? {
                        transform: `translateX(${dx}px) rotate(${dx / 40}deg)`,
                        transition: 'none',
                      }
                    : undefined
                }
              >
                <header className="review-card-head">
                  {summary ? (
                    <ItemTile item={summary} size="large" />
                  ) : (
                    <span className="item-tile" data-size="large" data-hue="1">
                      <Icon name="globe" size={22} />
                    </span>
                  )}
                  <div className="detail-title">
                    <h3>{card.finding.name || t('(ohne Namen)')}</h3>
                    <p className="detail-label">
                      {[card.finding.subtitle, card.finding.host].filter(Boolean).join(' · ')}
                    </p>
                  </div>
                </header>
                <ul className="review-problems">
                  {card.problems.map((problem) => {
                    const ignored = ignores
                      ? isIgnored(ignores.list, card.finding.id, problem.kind)
                      : false;
                    const solved = renewed.has(card.finding.id) && passwordProblem(problem.kind);
                    return (
                      <li
                        key={problem.kind}
                        className="review-problem"
                        data-state={solved ? 'solved' : ignored ? 'ignored' : 'open'}
                      >
                        <Icon name={solved ? 'check' : ignored ? 'eye' : 'warning'} size={16} />
                        <div className="detail-text">
                          <span className="detail-value">{problemTitle(problem.kind)}</span>
                          <span className="detail-label">
                            {solved
                              ? t('Neues Passwort gespeichert')
                              : ignored
                                ? t('Ignoriert')
                                : problemDetail(problem)}
                          </span>
                        </div>
                        {!solved && (
                          <button
                            className="quiet small"
                            onClick={() =>
                              void changeIgnore(card.finding.id, problem.kind, !ignored)
                            }
                          >
                            {ignored ? t('Rückgängig') : t('Ignorieren')}
                            <span className="sr-only">: {problemTitle(problem.kind)}</span>
                          </button>
                        )}
                      </li>
                    );
                  })}
                </ul>
                {renewed.has(card.finding.id) && (
                  <p className="field-hint" role="status">
                    {t('Neues Passwort gespeichert – jetzt noch auf der Website ändern.')}
                  </p>
                )}
                <div className="review-actions">
                  {target ? (
                    <a
                      className="button-link primary"
                      href={target}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <Icon name="external" size={15} />
                      {t('Seite öffnen & Passwort ändern')}
                      <span className="sr-only"> {t('(neues Fenster)')}</span>
                    </a>
                  ) : null}
                  <button onClick={() => setGenerating(card.finding.id)}>
                    <Icon name="key" size={15} />
                    {t('Neues Passwort erzeugen & speichern')}
                  </button>
                  <button className="quiet" onClick={skip}>
                    <Icon name="clock" size={15} />
                    {t('Später')}
                  </button>
                  <button className="quiet" onClick={() => onOpen(card.finding.id)}>
                    {t('Eintrag öffnen')}
                  </button>
                </div>
              </section>
            </div>
            {/* aria-disabled, not disabled: the last "Weiter" keeps the focus instead of dropping
                it on the page. */}
            <nav className="review-nav" aria-label={t('Karten')}>
              <button
                className="quiet"
                aria-disabled={index === 0 || undefined}
                onClick={() => index > 0 && go(-1)}
              >
                <span aria-hidden>‹</span> {t('Zurück')}
              </button>
              <button
                className="quiet"
                aria-disabled={index + 1 >= total || undefined}
                onClick={() => index + 1 < total && go(1)}
              >
                {t('Weiter')} <span aria-hidden>›</span>
              </button>
            </nav>
          </>
        )}
      </article>
      {generating && (
        <GeneratorDialog onClose={() => setGenerating(null)} onUse={(pw) => void saveNew(pw)} />
      )}
    </section>
  );
}

/** Whether the ignore list in `stored` hides `kind` of `id`, for the report's lists. */
export const hidden = (stored: StoredIgnores | null, id: string, kind: ProblemKind) =>
  stored ? isIgnored(stored.list, id, kind) : false;
