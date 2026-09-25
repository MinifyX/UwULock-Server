import { useEffect, useRef, useState } from 'react';
import { Segmented, Toggle } from '../components/web/controls';
import { logs, type LogLine } from '../lib/admin';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';

/** The server's newest log lines, as they come; nothing secret is ever logged. */
export function Logs() {
  useLanguage();
  const [level, setLevel] = useState('info');
  const [lines, setLines] = useState<LogLine[]>([]);
  const [follow, setFollow] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const last = useRef(0);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    last.current = 0;
    setLines([]);
    let stopped = false;
    const poll = async () => {
      try {
        const fresh = await logs(last.current, level);
        if (stopped) return;
        if (fresh.length) {
          last.current = fresh[fresh.length - 1]!.seq;
          setLines((all) => [...all, ...fresh].slice(-2000));
        }
        setError(null);
      } catch (e) {
        setError(errorText(e));
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [level]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  return (
    <>
      <div className="log-controls">
        <Segmented
          label={t('Stufe')}
          value={level}
          onChange={setLevel}
          options={[
            { value: 'error', label: t('Fehler') },
            { value: 'warn', label: t('Warnungen') },
            { value: 'info', label: t('Info') },
            { value: 'debug', label: t('Alles') },
          ]}
        />
        <span className="spacer" />
        <label className="check">
          <Toggle label={t('Mitlaufen')} checked={follow} onChange={setFollow} />
          <span>{t('Mitlaufen')}</span>
        </label>
      </div>
      {error && <p className="form-error">{error}</p>}
      <div className="log-box" ref={box}>
        {lines.map((line) => (
          <p key={line.seq} className="log-line" data-level={line.level}>
            <span className="log-time">{line.time.slice(11, 19)}</span>
            <span className="log-level">{line.level}</span>
            <span className="log-message">{line.message}</span>
          </p>
        ))}
        {lines.length === 0 && <p className="empty-note">{t('Noch nichts.')}</p>}
      </div>
    </>
  );
}
