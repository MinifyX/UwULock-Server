import { useEffect, useState } from 'react';
import { Callout, Section, Segmented } from '../components/ui';
import { stats, type Day } from '../lib/admin';
import { errorText } from '../lib/errors';
import { bytes } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';

const WIDTH = 300;
const HEIGHT = 80;

function dayText(day: string): string {
  const [y, m, d] = day.split('-').map(Number);
  return new Date(Date.UTC(y!, m! - 1, d!)).toLocaleDateString(undefined, {
    day: 'numeric',
    month: 'short',
  });
}

/** Where a value sits between 0 (bottom) and the largest (top), with a little room above. */
function scale(values: number[]) {
  const top = Math.max(1, ...values) * 1.1;
  return (value: number) => HEIGHT - (value / top) * HEIGHT;
}

function Line({ values, label }: { values: number[]; label: string }) {
  const y = scale(values);
  const x = (index: number) => (values.length < 2 ? WIDTH : (index / (values.length - 1)) * WIDTH);
  const points = values.map((value, index) => `${x(index).toFixed(1)},${y(value).toFixed(1)}`);
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      <polygon
        className="chart-area"
        points={`0,${HEIGHT} ${points.join(' ')} ${WIDTH},${HEIGHT}`}
      />
      <polyline
        className="chart-line"
        points={points.join(' ')}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function Bars({ values, alarms, label }: { values: number[]; alarms: number[]; label: string }) {
  const y = scale(values.map((value, index) => value + (alarms[index] ?? 0)));
  const slot = WIDTH / Math.max(1, values.length);
  const width = Math.max(1, slot * 0.7);
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      {values.map((value, index) => {
        const failed = alarms[index] ?? 0;
        const left = index * slot + (slot - width) / 2;
        return (
          <g key={index}>
            <rect
              className="chart-bar"
              x={left}
              y={y(value)}
              width={width}
              height={HEIGHT - y(value)}
            />
            {failed > 0 && (
              <rect
                className="chart-bar-alarm"
                x={left}
                y={y(value + failed)}
                width={width}
                height={y(value) - y(value + failed)}
              />
            )}
          </g>
        );
      })}
    </svg>
  );
}

function Card({
  title,
  value,
  note,
  days,
  children,
}: {
  title: string;
  value: string;
  note?: string;
  days: Day[];
  children: React.ReactNode;
}) {
  return (
    <figure className="card chart-card">
      <figcaption>
        <span className="stat-label">{title}</span>
        <span className="chart-value">{value}</span>
        {note && <span className="stat-note">{note}</span>}
      </figcaption>
      {children}
      <div className="chart-axis" aria-hidden>
        <span>{dayText(days[0]!.day)}</span>
        <span>{dayText(days[days.length - 1]!.day)}</span>
      </div>
    </figure>
  );
}

/** The numbers over time: one row a day, written by the server every hour. */
export function History() {
  useLanguage();
  const [span, setSpan] = useState<'30' | '90' | '365'>('90');
  const [days, setDays] = useState<Day[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    stats(Number(span)).then(setDays, (e) => setError(errorText(e)));
  }, [span]);

  if (error) return <Callout tone="error">{error}</Callout>;
  if (!days) return null;
  const last = days[days.length - 1];
  const sum = (pick: (day: Day) => number) => days.reduce((total, day) => total + pick(day), 0);

  return (
    <Section heading={t('Verlauf')} className="history">
      <div className="history-head">
        <Segmented
          label={t('Zeitraum')}
          value={span}
          onChange={setSpan}
          options={[
            { value: '30', label: t('30 Tage') },
            { value: '90', label: t('90 Tage') },
            { value: '365', label: t('1 Jahr') },
          ]}
        />
      </div>
      {!last || days.length < 2 ? (
        <p className="empty-note">
          {t(
            'Der Server schreibt seine Zahlen jede Stunde auf. Ab morgen gibt es hier einen Verlauf.',
          )}
        </p>
      ) : (
        <div className="chart-grid">
          <Card title={t('Nutzer')} value={last.users.toLocaleString()} days={days}>
            <Line values={days.map((day) => day.users)} label={t('Nutzer pro Tag')} />
          </Card>
          <Card
            title={t('Einträge')}
            value={last.ciphers.toLocaleString()}
            note={t('{n} Sends', { n: last.sends })}
            days={days}
          >
            <Line values={days.map((day) => day.ciphers)} label={t('Einträge pro Tag')} />
          </Card>
          <Card title={t('Dateien')} value={bytes(last.fileBytes)} days={days}>
            <Line values={days.map((day) => day.fileBytes)} label={t('Dateien pro Tag')} />
          </Card>
          <Card
            title={t('Anmeldungen')}
            value={sum((day) => day.logins).toLocaleString()}
            note={t('{n} fehlgeschlagen', { n: sum((day) => day.failedLogins) })}
            days={days}
          >
            <Bars
              values={days.map((day) => day.logins)}
              alarms={days.map((day) => day.failedLogins)}
              label={t('Anmeldungen pro Tag, fehlgeschlagene obenauf')}
            />
          </Card>
        </div>
      )}
    </Section>
  );
}
