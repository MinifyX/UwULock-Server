/**
 * The breach sources of the password check beyond the passwords themselves (docs/uwu-api.md
 * §15): the public lists of breached sites, the check of addresses at XposedOrNot (only with the
 * account's consent), whether a site has a change-password page, and the list of problems an
 * account chose not to see again. The browser only ever talks to its own server.
 */

import type { Finding, Report } from './features';
import { webUrl } from './links';
import { openExtras } from './requests';
import { call } from './web/core';
import { ApiError, request } from './web/http';

// ── Which sources the server offers ───────────────────────

export type BreachSwitches = {
  hibp: boolean;
  xonPasswords: boolean;
  siteBreaches: boolean;
  emailCheck: boolean;
  changePassword: boolean;
};

/** An older server knows only Have I Been Pwned. */
export function switchesOf(info: {
  hibp: boolean;
  breaches?: Partial<BreachSwitches>;
}): BreachSwitches {
  return {
    hibp: info.breaches?.hibp ?? info.hibp,
    xonPasswords: info.breaches?.xonPasswords ?? false,
    siteBreaches: info.breaches?.siteBreaches ?? false,
    emailCheck: info.breaches?.emailCheck ?? false,
    changePassword: info.breaches?.changePassword ?? false,
  };
}

// ── Breached sites ────────────────────────────────────────

export type SiteBreach = {
  domain: string;
  title: string;
  /** When it happened, `YYYY-MM-DD`. */
  date: string | null;
  added: string | null;
  records: number;
  passwords: boolean;
  dataClasses: string[];
  /** Source id → the breach's name there (`hibp`, `xon`). */
  sources: Record<string, string>;
};

export type SiteBreachList = {
  updated: string;
  sources: { id: string; name: string; url: string; license: string | null; updated: string }[];
  breaches: SiteBreach[];
};

let sitesCached: SiteBreachList | null = null;

/** The merged list; asked for once per page. */
export async function siteBreaches(): Promise<SiteBreachList> {
  sitesCached ??= await request<SiteBreachList>('/uwu/v1/breaches/sites');
  return sitesCached;
}

/** Every domain to its breaches. */
export function breachIndex(breaches: SiteBreach[]): Map<string, SiteBreach[]> {
  const index = new Map<string, SiteBreach[]>();
  for (const breach of breaches) {
    const key = breach.domain.toLowerCase();
    index.set(key, [...(index.get(key) ?? []), breach]);
  }
  return index;
}

/**
 * The breaches of a host: of the host itself and of every domain above it (`login.example.com`
 * finds `example.com`), never of a bare top-level domain. Addresses and local names find none.
 */
export function breachesFor(index: Map<string, SiteBreach[]>, host: string | null | undefined) {
  if (!host) return [];
  let name = host.toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(name) || name.includes(':') || !name.includes('.')) return [];
  if (name.startsWith('www.')) name = name.slice(4);
  const found: SiteBreach[] = [];
  for (;;) {
    found.push(...(index.get(name) ?? []));
    const dot = name.indexOf('.');
    const parent = name.slice(dot + 1);
    if (dot < 0 || !parent.includes('.')) return found;
    name = parent;
  }
}

/**
 * The latest breach of the login's site in which passwords were taken and which happened after
 * its password was last changed — "the site had a breach after your last password change".
 * A breach of the same day counts: the date says only the day.
 */
export function breachAfterChange(
  index: Map<string, SiteBreach[]>,
  finding: Pick<Finding, 'host' | 'passwordChanged'>,
): SiteBreach | null {
  const changed = finding.passwordChanged?.slice(0, 10);
  if (!changed) return null;
  const after = breachesFor(index, finding.host)
    .filter((breach) => breach.passwords && (breach.date ?? breach.added ?? '') >= changed)
    .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
  return after[0] ?? null;
}

// ── Addresses ─────────────────────────────────────────────

export type EmailResult = {
  email: string;
  /** `found`, `clean`, `later` (the server's budget is used up for now) or `failed`. */
  status: 'found' | 'clean' | 'later' | 'failed';
  /** XposedOrNot's names of the breaches; `sources.xon` of the site list. */
  breaches: string[];
};

export type OptIn = { optedIn: boolean; since: string | null };

export const emailOptIn = () => request<OptIn>('/uwu/v1/breaches/emails/opt-in');

export const setEmailOptIn = (optedIn: boolean) =>
  request<OptIn>('/uwu/v1/breaches/emails/opt-in', { method: 'PUT', body: { optedIn } });

/** Whether `text` looks like an address worth asking about. */
export const isAddress = (text: string | null | undefined): text is string =>
  Boolean(text && /^[^\s@/?#%\\"<>]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(text.trim()));

/**
 * Check `addresses` (at most 50 at a time are sent). The server answers what it can now and
 * says when to come back; this asks again while that is soon, then hands back what it has.
 */
export async function checkEmails(
  addresses: string[],
  progress?: (done: number, total: number) => void,
): Promise<{ results: EmailResult[]; retryAfter: number | null }> {
  const unique = [...new Set(addresses.map((a) => a.trim().toLowerCase()).filter(isAddress))];
  const results = new Map<string, EmailResult>();
  let retryAfter: number | null = null;
  for (let start = 0; start < unique.length; start += 50) {
    let batch = unique.slice(start, start + 50);
    for (let round = 0; batch.length && round < 30; round++) {
      const answer = await request<{ results: EmailResult[]; retryAfter: number | null }>(
        '/uwu/v1/breaches/emails',
        { body: { emails: batch } },
      );
      for (const result of answer.results) results.set(result.email, result);
      progress?.([...results.values()].filter((r) => r.status !== 'later').length, unique.length);
      retryAfter = answer.retryAfter;
      batch = answer.results.filter((r) => r.status === 'later').map((r) => r.email);
      // Only a short wait is waited here; a long one is said.
      if (!batch.length || !retryAfter || retryAfter > 5) break;
      await new Promise((done) => window.setTimeout(done, retryAfter! * 1000));
    }
    if (retryAfter && retryAfter > 5) break;
  }
  const later = unique.filter((address) => !results.has(address));
  for (const email of later) results.set(email, { email, status: 'later', breaches: [] });
  return { results: unique.map((address) => results.get(address)!), retryAfter };
}

// ── Change-password pages ─────────────────────────────────

const pages = new Map<string, Promise<string | null>>();

/** The site's `/.well-known/change-password` if the server found one; else null. */
export function changePasswordPage(host: string): Promise<string | null> {
  const key = host.toLowerCase();
  let known = pages.get(key);
  if (!known) {
    known = request<{ url: string | null }>(`/uwu/v1/change-password/${encodeURIComponent(key)}`)
      // Only an http(s) page: a hostile or broken answer never becomes another kind of link.
      .then((answer) => webUrl(answer.url))
      .catch(() => null);
    pages.set(key, known);
  }
  return known;
}

/** What "open the page & change the password" opens: the change-password page, else the login. */
export async function pageToOpen(
  finding: Pick<Finding, 'host' | 'uri'>,
  ask: boolean,
): Promise<string | null> {
  const page = ask && finding.host ? await changePasswordPage(finding.host) : null;
  if (page) return page;
  const uri = finding.uri ?? (finding.host ? `https://${finding.host}/` : null);
  return uri && /^https?:\/\//i.test(uri) ? uri : null;
}

// ── Problems, and those not shown again ───────────────────

/**
 * The kinds of problem the check knows; stable ids, the same in every UwULock app (they are
 * what the ignore list keeps).
 */
export type ProblemKind = 'breached' | 'reused' | 'weak' | 'unsecured' | 'siteBreach' | 'twofa';

export const PROBLEM_KINDS: ProblemKind[] = [
  'breached',
  'siteBreach',
  'reused',
  'weak',
  'unsecured',
  'twofa',
];

export type Ignored = { itemId: string; kind: ProblemKind; since: string };

/** The ignore list as it is encrypted (docs/uwu-api.md §15.6). */
export type IgnoreList = { version: 1; ignored: Ignored[] };

export type StoredIgnores = { list: IgnoreList; revision: string | null };

const EMPTY: IgnoreList = { version: 1, ignored: [] };

function parse(text: string): IgnoreList {
  const value = JSON.parse(text) as Partial<IgnoreList>;
  const kinds = new Set<string>(PROBLEM_KINDS);
  const ignored = Array.isArray(value.ignored)
    ? value.ignored.filter(
        (entry): entry is Ignored =>
          typeof entry?.itemId === 'string' &&
          typeof entry.since === 'string' &&
          kinds.has(entry.kind as string),
      )
    : [];
  return { version: 1, ignored };
}

type Wire = { data: string | null; revisionDate: string | null };

/** The ignore list, opened with the extras key; empty when there is none. */
export async function loadIgnores(): Promise<StoredIgnores> {
  await openExtras();
  const stored = await request<Wire>('/uwu/v1/reports/health/ignored');
  if (!stored.data) return { list: EMPTY, revision: stored.revisionDate };
  const data = stored.data;
  try {
    const text = await call((core) => core.openReport(data));
    return { list: parse(text), revision: stored.revisionDate };
  } catch {
    // A list that does not open (another key) is started over.
    return { list: EMPTY, revision: stored.revisionDate };
  }
}

/**
 * Change the ignore list: `change` is applied to the stored list, which is saved only if no
 * other device saved one in between — otherwise the newer one is loaded and `change` applied
 * to it again.
 */
export async function changeIgnores(
  known: StoredIgnores,
  change: (list: IgnoreList) => IgnoreList,
): Promise<StoredIgnores> {
  let current = known;
  for (let attempt = 0; attempt < 3; attempt++) {
    const next = change(current.list);
    await openExtras();
    const data = await call((core) => core.sealReport(JSON.stringify(next)));
    try {
      const stored = await request<Wire>('/uwu/v1/reports/health/ignored', {
        method: 'PUT',
        body: { data, revisionDate: current.revision },
      });
      return { list: next, revision: stored.revisionDate };
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 409) throw error;
      current = await loadIgnores();
    }
  }
  throw new Error('The list kept changing on another device.');
}

export const ignore = (list: IgnoreList, itemId: string, kind: ProblemKind): IgnoreList =>
  list.ignored.some((entry) => entry.itemId === itemId && entry.kind === kind)
    ? list
    : {
        version: 1,
        ignored: [...list.ignored, { itemId, kind, since: new Date().toISOString() }],
      };

export const unignore = (list: IgnoreList, itemId: string, kind: ProblemKind): IgnoreList => ({
  version: 1,
  ignored: list.ignored.filter((entry) => !(entry.itemId === itemId && entry.kind === kind)),
});

/** Without entries for items that are gone. */
export const tidy = (list: IgnoreList, itemIds: Set<string>): IgnoreList => ({
  version: 1,
  ignored: list.ignored.filter((entry) => itemIds.has(entry.itemId)),
});

export const isIgnored = (list: IgnoreList, itemId: string, kind: ProblemKind) =>
  list.ignored.some((entry) => entry.itemId === itemId && entry.kind === kind);

// ── One card per login ────────────────────────────────────

export type Problem =
  | { kind: 'breached'; count: number; sources: string[] }
  | { kind: 'siteBreach'; breach: SiteBreach }
  | { kind: 'reused'; others: number }
  | { kind: 'weak'; bits: number }
  | { kind: 'unsecured' }
  | { kind: 'twofa'; documentation: string | null };

export type Card = { finding: Finding; problems: Problem[] };

/**
 * The cards of the swipe review: every login with at least one problem that is not ignored,
 * the worst first: by what they have, a breach weighing more than a site breach, that more than
 * reuse, then weak, then http, then 2FA.
 */
export function cardsOf(
  report: Report,
  options: {
    sites?: Map<string, SiteBreach[]> | null;
    twofa?: Map<string, { documentation: string | null }>;
    ignored: IgnoreList;
  },
): Card[] {
  const cards: Card[] = [];
  for (const finding of report.findings) {
    const problems: Problem[] = [];
    if ((finding.breached ?? 0) > 0) {
      problems.push({
        kind: 'breached',
        count: finding.breached ?? 0,
        sources: finding.breachSources ?? [],
      });
    }
    const breach = options.sites ? breachAfterChange(options.sites, finding) : null;
    if (breach) problems.push({ kind: 'siteBreach', breach });
    if (finding.reused > 0) problems.push({ kind: 'reused', others: finding.reused });
    if (finding.weak) problems.push({ kind: 'weak', bits: finding.bits });
    if (finding.unsecured) problems.push({ kind: 'unsecured' });
    const twofa = options.twofa?.get(finding.id);
    if (twofa) problems.push({ kind: 'twofa', documentation: twofa.documentation });
    const open = problems.filter((p) => !isIgnored(options.ignored, finding.id, p.kind));
    if (open.length) cards.push({ finding, problems: open });
  }
  // Each kind outweighs all lighter ones together: a breach first, a missing 2FA last.
  const weight = (card: Card) =>
    card.problems.reduce(
      (sum, p) => sum + 2 ** (PROBLEM_KINDS.length - PROBLEM_KINDS.indexOf(p.kind)),
      0,
    );
  return cards.sort(
    (a, b) => weight(b) - weight(a) || a.finding.name.localeCompare(b.finding.name),
  );
}
