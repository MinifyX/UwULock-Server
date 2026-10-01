import { useCallback, useEffect, useState } from 'react';
import {
  Badge,
  Button,
  ButtonRow,
  Field,
  FormRow,
  Modal,
  Section,
  Segmented,
  Select,
  SettingRow,
  Table,
  TextField,
  Toggle,
} from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import {
  blockIp,
  failedByIp,
  failedLogins,
  geoipStatus,
  updateGeoip,
  type FailedReason,
  type GeoIpStatus,
  type IpGroup,
  type LoginAttempt,
  type LoginFilter,
  placeText,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes, when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import { ApiError } from '../lib/web/http';
import { SettingsTab } from './draft';

export const REASONS: Record<FailedReason, string> = {
  password: N_('Falsches Passwort'),
  'unknown-account': N_('Konto existiert nicht'),
  disabled: N_('Konto gesperrt'),
  'api-key': N_('Falscher API-Schlüssel'),
  'two-factor': N_('Falscher zweiter Schritt'),
};

const RANGES: { hours: number; label: string }[] = [
  { hours: 1, label: N_('1 Stunde') },
  { hours: 24, label: N_('24 Stunden') },
  { hours: 168, label: N_('7 Tage') },
  { hours: 720, label: N_('30 Tage') },
  { hours: 2160, label: N_('90 Tage') },
];

/** The client in one line: "mobile 2026.9.0". */
function clientText(attempt: LoginAttempt): string | null {
  return [attempt.clientName, attempt.clientVersion].filter(Boolean).join(' ') || null;
}

/**
 * *Sicherheit → Fehlgeschlagene Anmeldungen*: every refused login with where it came from, what
 * client and device, and for which account — or grouped by address, with the history of an
 * address and the way to block it. GeoIP's switch and its credits at the foot.
 */
export function FailedLogins() {
  useLanguage();
  const [view, setView] = useState<'attempts' | 'ips'>('attempts');
  const [filter, setFilter] = useState<LoginFilter>({ hours: 24, user: '', ip: '', reason: '' });
  // What is typed is asked for once the typing pauses.
  const [asked, setAsked] = useState(filter);
  useEffect(() => {
    const timer = setTimeout(() => setAsked(filter), 300);
    return () => clearTimeout(timer);
  }, [filter]);
  const [block, setBlock] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  const [generation, setGeneration] = useState(0);

  const set = (change: Partial<LoginFilter>) => setFilter((old) => ({ ...old, ...change }));
  const showAddress = (ip: string) => {
    set({ ip });
    setView('attempts');
  };

  return (
    <div className="stack">
      <p className="section-lead">
        {t(
          'Jede abgelehnte Anmeldung der letzten 90 Tage: woher sie kam, mit welchem Gerät und welcher App, und für welches Konto. Eine Adresse, die viel probiert, lässt sich sperren.',
        )}
      </p>
      <Segmented
        label={t('Zeitraum')}
        value={filter.hours ?? 0}
        onChange={(hours) => set({ hours })}
        options={RANGES.map((range) => ({ value: range.hours, label: t(range.label) }))}
      />
      <FormRow>
        <TextField
          label={t('Konto')}
          type="search"
          placeholder={t('Adresse oder Teil davon')}
          value={filter.user}
          onChange={(user) => set({ user })}
        />
        <TextField
          label={t('IP-Adresse')}
          type="search"
          mono
          placeholder={t('203.0.113.7 oder 203.0.113.*')}
          value={filter.ip}
          onChange={(ip) => set({ ip })}
        />
        <Field label={t('Grund')}>
          <Select
            value={filter.reason}
            onChange={(reason) => set({ reason })}
            options={[
              { value: '' as const, label: t('Alle Gründe') },
              ...(Object.keys(REASONS) as FailedReason[]).map((reason) => ({
                value: reason,
                label: t(REASONS[reason]),
              })),
            ]}
          />
        </Field>
      </FormRow>
      <Segmented
        label={t('Ansicht')}
        value={view}
        onChange={setView}
        options={[
          { value: 'attempts', label: t('Einzeln') },
          { value: 'ips', label: t('Nach IP-Adresse') },
        ]}
      />
      {view === 'attempts' ? (
        <Attempts
          filter={asked}
          key={generation}
          onAddress={showAddress}
          onBlock={setBlock}
          onHistory={setHistory}
        />
      ) : (
        <Groups filter={asked} key={generation} onBlock={setBlock} onHistory={setHistory} />
      )}
      {block && (
        <BlockDialog
          network={block}
          onClose={(blocked) => {
            setBlock(null);
            if (blocked) setGeneration((n) => n + 1);
          }}
        />
      )}
      {history && (
        <HistoryDialog
          ip={history}
          onClose={() => setHistory(null)}
          onBlock={() => {
            setBlock(history);
            setHistory(null);
          }}
        />
      )}
      <GeoIpSection />
    </div>
  );
}

function Attempts({
  filter,
  onAddress,
  onBlock,
  onHistory,
}: {
  filter: LoginFilter;
  onAddress: (ip: string) => void;
  onBlock: (ip: string) => void;
  onHistory: (ip: string) => void;
}) {
  useLanguage();
  const [list, setList] = useState<LoginAttempt[] | null>(null);
  const [more, setMore] = useState(false);
  const [open, setOpen] = useState<number | null>(null);

  const load = useCallback(
    (before: number | null) => {
      failedLogins(filter, before).then(
        (page) => {
          setList((all) => (before ? [...(all ?? []), ...page.attempts] : page.attempts));
          setMore(page.more);
        },
        (e) => toast(errorText(e), 'error'),
      );
    },
    [filter],
  );
  useEffect(() => load(null), [load]);

  return (
    <>
      <Table
        label={t('Fehlgeschlagene Anmeldungen')}
        head={
          <>
            <th>{t('Wann')}</th>
            <th>{t('Grund')}</th>
            <th>{t('Konto')}</th>
            <th>{t('Von wo')}</th>
            <th>
              <span className="sr-only">{t('Aktionen')}</span>
            </th>
          </>
        }
      >
        {list?.map((attempt) => (
          <AttemptRow
            key={attempt.id}
            attempt={attempt}
            open={open === attempt.id}
            onToggle={() => setOpen(open === attempt.id ? null : attempt.id)}
            onAddress={onAddress}
            onBlock={onBlock}
            onHistory={onHistory}
          />
        ))}
      </Table>
      {list?.length === 0 && (
        <p className="empty-note">{t('Keine abgelehnten Anmeldungen in diesem Zeitraum.')}</p>
      )}
      {more && (
        <ButtonRow>
          <Button onClick={() => load(list?.[list.length - 1]?.id ?? null)}>
            {t('Ältere laden')}
          </Button>
        </ButtonRow>
      )}
    </>
  );
}

function reasonText(attempt: LoginAttempt): string {
  if (attempt.kind === 'login') return t('Anmeldung');
  return attempt.reason ? t(REASONS[attempt.reason]) : (attempt.detail ?? attempt.kind);
}

/** The account a login was for: a link to it, or that there is none. */
function Target({ attempt }: { attempt: LoginAttempt }) {
  useLanguage();
  if (attempt.account)
    return (
      <a href={`#/users?q=${encodeURIComponent(attempt.account.email)}`}>{attempt.account.email}</a>
    );
  return (
    <>
      {attempt.email ?? '–'}
      {attempt.kind !== 'login' && <small>{t('existiert nicht')}</small>}
    </>
  );
}

function AttemptRow({
  attempt,
  open,
  onToggle,
  onAddress,
  onBlock,
  onHistory,
}: {
  attempt: LoginAttempt;
  open: boolean;
  onToggle: () => void;
  onAddress: (ip: string) => void;
  onBlock: (ip: string) => void;
  onHistory: (ip: string) => void;
}) {
  useLanguage();
  const where = placeText(attempt.place);
  return (
    <>
      <tr data-alarm={attempt.kind !== 'login' || undefined}>
        <td>
          <button className="row-toggle" onClick={onToggle} aria-expanded={open}>
            {when(attempt.time)}
          </button>
        </td>
        <td>{reasonText(attempt)}</td>
        <td>
          <Target attempt={attempt} />
        </td>
        <td>
          <span className="mono">{attempt.ip ?? '–'}</span>
          {where && <small>{where}</small>}
        </td>
        <td className="row-actions">
          <Button size="small" onClick={onToggle} aria-expanded={open}>
            {open ? t('Weniger') : t('Details')}
          </Button>
        </td>
      </tr>
      {open && (
        <tr className="row-detail">
          <td colSpan={5}>
            <dl className="facts row-fact-list">
              <Fact label={t('Zeit')} value={when(attempt.time)} />
              <Fact label={t('Grund')} value={reasonText(attempt)} />
              <Fact
                label={t('Eingegeben')}
                value={attempt.email}
                extra={
                  attempt.account
                    ? t('Konto vorhanden')
                    : attempt.kind === 'login'
                      ? null
                      : t('existiert nicht')
                }
              />
              <Fact label={t('IP-Adresse')} value={attempt.ip} mono />
              <Fact label={t('Herkunft')} value={where} />
              <Fact
                label={t('Gerät')}
                value={[attempt.deviceName, attempt.deviceType].filter(Boolean).join(' · ') || null}
              />
              <Fact label={t('App')} value={clientText(attempt)} />
              <Fact label={t('User-Agent')} value={attempt.userAgent} mono />
            </dl>
            {attempt.ip && (
              <div className="row-buttons">
                <Button size="small" onClick={() => onHistory(attempt.ip!)}>
                  {t('Verlauf dieser Adresse')}
                </Button>
                <Button size="small" onClick={() => onAddress(attempt.ip!)}>
                  {t('Nur diese Adresse zeigen')}
                </Button>
                <Button size="small" variant="danger" onClick={() => onBlock(attempt.ip!)}>
                  {t('IP sperren …')}
                </Button>
                {attempt.account && (
                  <Button
                    size="small"
                    variant="quiet"
                    onClick={() => go(`/users?q=${encodeURIComponent(attempt.account!.email)}`)}
                  >
                    {t('Zum Konto')}
                  </Button>
                )}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function Fact({
  label,
  value,
  extra,
  mono,
}: {
  label: string;
  value: string | null | undefined;
  extra?: string | null;
  mono?: boolean;
}) {
  return (
    <div className="fact">
      <dt className="fact-label">{label}</dt>
      <dd className={mono ? 'fact-value mono' : 'fact-value'}>
        {value || '–'}
        {extra && <small className="event-detail">{extra}</small>}
      </dd>
    </div>
  );
}

function Groups({
  filter,
  onBlock,
  onHistory,
}: {
  filter: LoginFilter;
  onBlock: (ip: string) => void;
  onHistory: (ip: string) => void;
}) {
  useLanguage();
  const [groups, setGroups] = useState<IpGroup[] | null>(null);
  useEffect(() => {
    failedByIp(filter).then(
      (answer) => setGroups(answer.groups),
      (e) => toast(errorText(e), 'error'),
    );
  }, [filter]);
  return (
    <>
      <Table
        label={t('Nach IP-Adresse')}
        head={
          <>
            <th>{t('IP-Adresse')}</th>
            <th>{t('Versuche')}</th>
            <th>{t('Konten')}</th>
            <th>{t('Zuletzt')}</th>
            <th>
              <span className="sr-only">{t('Aktionen')}</span>
            </th>
          </>
        }
      >
        {groups?.map((group) => (
          <tr key={group.ip} data-alarm={group.attempts >= 10 || undefined}>
            <td>
              <span className="mono">{group.ip}</span>
              {group.blocked && (
                <span className="badges">
                  <Badge tone="alarm">{t('gesperrt')}</Badge>
                </span>
              )}
              {placeText(group.place) && <small>{placeText(group.place)}</small>}
            </td>
            <td>
              {group.attempts}
              {group.logins > 0 && (
                <small>{t('{n} erfolgreiche Anmeldungen', { n: group.logins })}</small>
              )}
            </td>
            <td>
              {group.targets}
              <small>
                {group.emails.join(', ')}
                {group.unknown > 0 && ` · ${t('{n} ohne Konto', { n: group.unknown })}`}
              </small>
            </td>
            <td>
              {when(group.last)}
              <small>{t('seit {when}', { when: when(group.first) ?? '' })}</small>
            </td>
            <td className="row-actions">
              <Button size="small" onClick={() => onHistory(group.ip)}>
                {t('Verlauf')}
                <span className="sr-only">{group.ip}</span>
              </Button>
              {!group.blocked && (
                <Button size="small" variant="danger" onClick={() => onBlock(group.ip)}>
                  {t('IP sperren …')}
                  <span className="sr-only">{group.ip}</span>
                </Button>
              )}
            </td>
          </tr>
        ))}
      </Table>
      {groups?.length === 0 && (
        <p className="empty-note">{t('Keine abgelehnten Anmeldungen in diesem Zeitraum.')}</p>
      )}
    </>
  );
}

/** Everything an address did in the 90 days: refused logins and those that worked. */
function HistoryDialog({
  ip,
  onClose,
  onBlock,
}: {
  ip: string;
  onClose: () => void;
  onBlock: () => void;
}) {
  useLanguage();
  const [list, setList] = useState<LoginAttempt[] | null>(null);
  useEffect(() => {
    failedLogins({ hours: null, user: '', ip, reason: '', all: true }, null).then(
      (page) => setList(page.attempts),
      (e) => toast(errorText(e), 'error'),
    );
  }, [ip]);
  const where = placeText(list?.find((attempt) => attempt.place)?.place);
  const failed = list?.filter((attempt) => attempt.kind !== 'login').length ?? 0;
  return (
    <Modal
      title={t('Verlauf von {ip}', { ip })}
      onCancel={onClose}
      footer={
        <>
          <Button variant="danger" onClick={onBlock}>
            {t('IP sperren …')}
          </Button>
          <span className="spacer" />
          <Button variant="primary" data-autofocus onClick={onClose}>
            {t('Schließen')}
          </Button>
        </>
      }
    >
      {list && (
        <p className="dialog-lead">
          {where ? `${where} · ` : ''}
          {t('{failed} abgelehnt, {ok} erfolgreich in 90 Tagen.', {
            failed,
            ok: list.length - failed,
          })}
        </p>
      )}
      <Table
        label={t('Verlauf von {ip}', { ip })}
        head={
          <>
            <th>{t('Wann')}</th>
            <th>{t('Was')}</th>
            <th>{t('Konto')}</th>
            <th>{t('Gerät')}</th>
          </>
        }
      >
        {list?.map((attempt) => (
          <tr key={attempt.id} data-alarm={attempt.kind !== 'login' || undefined}>
            <td>{when(attempt.time)}</td>
            <td>{reasonText(attempt)}</td>
            <td>
              <Target attempt={attempt} />
            </td>
            <td>
              {[attempt.deviceName, attempt.deviceType].filter(Boolean).join(' · ') || '–'}
              {clientText(attempt) && <small>{clientText(attempt)}</small>}
            </td>
          </tr>
        ))}
      </Table>
      {list?.length === 0 && <p className="empty-note">{t('Noch nichts.')}</p>}
    </Modal>
  );
}

export const DURATIONS: { hours: string; label: string }[] = [
  { hours: '1', label: N_('1 Stunde') },
  { hours: '24', label: N_('24 Stunden') },
  { hours: '168', label: N_('7 Tage') },
  { hours: '720', label: N_('30 Tage') },
  { hours: '', label: N_('Bis ich sie aufhebe') },
];

/** Block an address (or a network) for a while; the server refuses one's own. */
export function BlockDialog({
  network: initial,
  onClose,
}: {
  network: string;
  onClose: (blocked: boolean) => void;
}) {
  useLanguage();
  const [network, setNetwork] = useState(initial);
  const [hours, setHours] = useState('24');
  const [reason, setReason] = useState('');
  const [result, setResult] = useState<Result>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setResult(null);
    try {
      await blockIp(network.trim(), reason.trim(), hours ? Number(hours) : null);
      toast(t('{network} ist gesperrt.', { network: network.trim() }), 'info');
      onClose(true);
    } catch (e) {
      const code = e instanceof ApiError ? (e.body as { code?: string } | null)?.code : null;
      setResult({
        tone: 'error',
        text:
          code === 'would_lock_out'
            ? t('Das ist deine eigene Adresse – du würdest dich selbst aussperren.')
            : errorText(e),
      });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('IP-Adresse sperren')}
      tone="warning"
      onCancel={() => onClose(false)}
      footer={
        <>
          <span className="spacer" />
          <Button onClick={() => onClose(false)} data-secondary>
            {t('Abbrechen')}
          </Button>
          <Button variant="danger" disabled={busy || !network.trim()} onClick={() => void save()}>
            {t('Adresse sperren')}
          </Button>
        </>
      }
    >
      <p className="dialog-lead">
        {t(
          'Von dieser Adresse geht dann keine Anmeldung mehr: nicht im Web-Tresor, nicht im Admin-Portal, nicht in den Apps. Wer schon angemeldet ist, bleibt es.',
        )}
      </p>
      <TextField
        label={t('IP-Adresse oder Netz')}
        mono
        value={network}
        onChange={setNetwork}
        hint={t('Eine Adresse, oder ein Netz wie 203.0.113.0/24 oder 2001:db8::/64.')}
      />
      <Field label={t('Wie lange')}>
        <Select
          value={hours}
          onChange={setHours}
          options={DURATIONS.map((duration) => ({
            value: duration.hours,
            label: t(duration.label),
          }))}
        />
      </Field>
      <TextField
        label={t('Notiz (optional)')}
        value={reason}
        maxLength={200}
        onChange={setReason}
        placeholder={t('etwa: probiert Passwörter durch')}
      />
      <ResultLine result={result} />
    </Modal>
  );
}

/** GeoIP: the switch, the databases' state, a download now, and the credit DB-IP asks for. */
function GeoIpSection() {
  useLanguage();
  const [status, setStatus] = useState<GeoIpStatus | null>(null);
  const [result, setResult] = useState<Result>(null);
  const load = useCallback(() => geoipStatus().then(setStatus, () => setStatus(null)), []);
  useEffect(() => {
    void load();
  }, [load]);
  // While a download runs, look again now and then.
  useEffect(() => {
    if (!status?.updating) return;
    const timer = setTimeout(() => void load(), 3000);
    return () => clearTimeout(timer);
  }, [status, load]);

  const update = async () => {
    setResult(null);
    try {
      await updateGeoip();
      setResult({ tone: 'info', text: t('Der Download läuft; das dauert ein, zwei Minuten.') });
      await load();
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    }
  };

  return (
    <SettingsTab>
      {({ draft, setDraft }) => (
        <Section
          heading={t('Herkunft der Adressen (GeoIP)')}
          lead={t(
            'Land, Stadt und Netz einer Adresse kommen aus einer Datenbank auf diesem Server. Der Server lädt sie einmal im Monat von DB-IP herunter; einzelne Adressen werden nirgends nachgefragt.',
          )}
        >
          <SettingRow
            label={t('GeoIP verwenden')}
            description={t(
              'Ausgeschaltet lädt der Server nichts herunter, zeigt keine Herkunft und löscht die Datenbank beim nächsten nächtlichen Lauf.',
            )}
          >
            <Toggle
              label={t('GeoIP verwenden')}
              checked={draft.geoip}
              onChange={(geoip) => setDraft({ ...draft, geoip })}
            />
          </SettingRow>
          {status && (
            <p className="field-hint">
              {status.month
                ? t('Stand {month}: Städte {city}, Netze {asn}.', {
                    month: status.month,
                    city: bytes(status.cityBytes),
                    asn: bytes(status.asnBytes),
                  })
                : t('Noch nicht heruntergeladen.')}
              {status.updating && ` ${t('Der Download läuft …')}`}
              {status.error &&
                ` ${t('Der letzte Versuch ging nicht: {error}', { error: status.error })}`}
            </p>
          )}
          {status?.enabled && (
            <ButtonRow>
              <Button size="small" disabled={status.updating} onClick={() => void update()}>
                {t('Jetzt herunterladen')}
              </Button>
            </ButtonRow>
          )}
          <ResultLine result={result} />
          {status && (
            <p className="field-hint">
              <a href={status.source.url} target="_blank" rel="noreferrer noopener">
                {status.source.attribution}
              </a>{' '}
              ·{' '}
              <a href={status.source.licenseUrl} target="_blank" rel="noreferrer noopener">
                {status.source.license}
              </a>
            </p>
          )}
        </Section>
      )}
    </SettingsTab>
  );
}
