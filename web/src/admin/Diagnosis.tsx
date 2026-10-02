import { useEffect, useState } from 'react';
import { Icon, type IconName } from '../components/Icon';
import { Badge, Button, ButtonRow, Callout, Modal, Section, type Tone } from '../components/ui';
import {
  checkUpload,
  checkWebSocket,
  clientDiagnosis,
  diagnosis as load,
  runDiagnosis,
  settings,
  type Check,
  type CheckStatus,
  type Diagnosis as Data,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

const TITLES: Record<string, string> = {
  certificate: N_('Zertifikat'),
  clock: N_('Uhrzeit'),
  mail: N_('Mailserver'),
  backup: N_('Backups'),
  disk: N_('Speicherplatz'),
  'proxy.clientIp': N_('Proxy: Client-IP'),
  'proxy.publicUrl': N_('Proxy: öffentliche Adresse'),
  'proxy.websocket': N_('Proxy: WebSockets'),
  'proxy.uploadLimit': N_('Proxy: große Uploads'),
};

/** A check's name; a send domain's certificate comes as `certificate.<domain>`. */
function titleOf(id: string): string {
  const own = TITLES[id];
  if (own) return t(own);
  const [head = '', ...rest] = id.split('.');
  const family = TITLES[head];
  return family ? `${t(family)} (${rest.join('.')})` : id;
}

const STATUS: Record<CheckStatus, { label: string; icon: IconName; tone: Tone }> = {
  ok: { label: N_('in Ordnung'), icon: 'check', tone: 'ok' },
  warning: { label: N_('Warnung'), icon: 'warning', tone: 'alarm' },
  error: { label: N_('Fehler'), icon: 'close', tone: 'alarm' },
  skipped: { label: N_('übersprungen'), icon: 'more', tone: 'neutral' },
};

/**
 * Whether the server is set up well: certificate, clock, mail, backups, disk, and
 * the proxy in front — the last two of those only a browser can see, so this page tries them.
 */
export function Diagnosis() {
  useLanguage();
  const [data, setData] = useState<Data | null>(null);
  const [maxFileMb, setMaxFileMb] = useState<number | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    load().then(setData, (e) => setError(errorText(e)));
    settings().then(
      (s) => setMaxFileMb(s.maxFileMb),
      () => undefined,
    );
  }, []);

  const run = async (full: boolean) => {
    setError(null);
    try {
      if (!full) {
        setBusy(t('Der Server prüft … (bis zu 25 Sekunden)'));
        setData(await runDiagnosis());
        setBusy(t('Der Browser prüft WebSockets und einen Upload von 16 MB …'));
        const websocket = await checkWebSocket();
        const upload = await checkUpload();
        setData(await clientDiagnosis({ websocket, upload }));
      } else if (maxFileMb) {
        setBusy(t('Lädt {mb} MB hoch …', { mb: maxFileMb }));
        const upload = await checkUpload(maxFileMb);
        setData(await clientDiagnosis({ upload }));
      }
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const checks = data?.checks ?? [];
  const count = (status: CheckStatus) => checks.filter((c) => c.status === status).length;
  return (
    <>
      <Section
        heading={t('Ist alles richtig eingerichtet?')}
        lead={t(
          'Prüft Zertifikat, Uhrzeit, Mail, Backups, Speicherplatz und den Proxy davor. WebSockets und große Uploads prüft dieser Browser gegen den eigenen Server. Nach jedem Update läuft die Diagnose von selbst; das Ergebnis steht dann hier.',
        )}
      >
        <ButtonRow>
          <Button variant="primary" disabled={Boolean(busy)} onClick={() => void run(false)}>
            {t('Diagnose starten')}
          </Button>
          <Button disabled={Boolean(busy) || !maxFileMb} onClick={() => setAsking(true)}>
            {t('Volle Größe prüfen')}
          </Button>
        </ButtonRow>
        {busy && (
          <p className="setting-result" role="status" aria-live="polite">
            {busy}
          </p>
        )}
        {error && <Callout tone="error">{error}</Callout>}
        {data && (
          <p className="section-lead">
            {data.date
              ? t('Stand {when}, Version {version}: {errors} Fehler, {warnings} Warnungen.', {
                  when: when(data.date) ?? '',
                  version: data.version,
                  errors: count('error'),
                  warnings: count('warning'),
                })
              : t('Noch keine Diagnose. Starte sie oben.')}
          </p>
        )}
      </Section>
      <ul className="check-list">
        {checks.map((check) => (
          <CheckCard key={check.id} check={check} />
        ))}
      </ul>
      {asking && maxFileMb && (
        <Modal
          title={t('Mit der größten Datei prüfen?')}
          tone="warning"
          onCancel={() => setAsking(false)}
          footer={
            <>
              <span className="spacer" />
              <Button onClick={() => setAsking(false)} data-secondary>
                {t('Abbrechen')}
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setAsking(false);
                  void run(true);
                }}
              >
                {t('{mb} MB hochladen', { mb: maxFileMb })}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Dieser Browser schickt {mb} MB Nullen an den Server, so viel wie die größte erlaubte Datei. Der Server zählt sie und wirft sie weg. Über eine langsame oder bezahlte Leitung dauert das und kostet.',
              { mb: maxFileMb },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

function CheckCard({ check }: { check: Check }) {
  useLanguage();
  const status = STATUS[check.status] ?? STATUS.skipped;
  return (
    <li className="card check-card" data-status={check.status}>
      <div className="card-head">
        <h3 className="card-heading">{titleOf(check.id)}</h3>
        <span className="spacer" />
        <Badge tone={status.tone}>
          <Icon name={status.icon} size={13} />
          {t(status.label)}
        </Badge>
      </div>
      <p className="check-summary">{check.summary}</p>
      {check.detail && <p className="check-detail">{check.detail}</p>}
      {check.fix && (
        <div className="check-fix">
          <p>{check.fix.text}</p>
          {check.fix.caddy && <Snippet name="Caddy" text={check.fix.caddy} />}
          {check.fix.nginx && <Snippet name="nginx" text={check.fix.nginx} />}
        </div>
      )}
    </li>
  );
}

/** A piece of proxy configuration to copy. */
function Snippet({ name, text }: { name: string; text: string }) {
  useLanguage();
  return (
    <div className="snippet">
      <div className="snippet-head">
        <span>{name}</span>
        <Button
          size="small"
          variant="quiet"
          icon="copy"
          onClick={() =>
            void navigator.clipboard.writeText(text).then(() => toast(t('Kopiert ✧'), 'info'))
          }
          aria-label={t('{name} kopieren', { name })}
        >
          {t('Kopieren')}
        </Button>
      </div>
      {/* Focusable: a long line scrolls sideways, with the arrow keys too. */}
      <pre tabIndex={0}>
        <code>{text}</code>
      </pre>
    </div>
  );
}
