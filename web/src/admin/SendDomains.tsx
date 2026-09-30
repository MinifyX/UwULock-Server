import { useCallback, useEffect, useState } from 'react';
import { Icon } from '../components/Icon';
import {
  Badge,
  Button,
  ButtonRow,
  Callout,
  Card,
  Modal,
  Section,
  Segmented,
  SettingRow,
  TextField,
} from '../components/ui';
import { ResultLine, type Result } from '../components/web/controls';
import {
  addSendDomain,
  checkSendDomain,
  deleteSendDomain,
  sendDomains,
  setSendDomainTls,
  type AdminSendDomain,
  type SendDomainCheck,
  type SendDomainTls,
} from '../lib/admin';
import { loadServerInfo } from '../lib/branding';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { hostOf } from '../lib/links';
import { toast } from '../lib/toast';
import { Branding } from './Branding';

function tlsOptions() {
  return [
    { value: 'acme' as const, label: "Let's Encrypt" },
    { value: 'proxy' as const, label: t('Proxy davor') },
  ];
}

/** What the certificate of a send domain is doing, in a line. */
function certificateText(domain: AdminSendDomain): string {
  const { status, expires, error } = domain.certificate;
  if (status === 'proxy') return t('TLS macht der Proxy davor.');
  if (status === 'ok')
    return expires
      ? t('Zertifikat gültig bis {when}.', { when: when(expires) ?? '' })
      : t('Zertifikat in Ordnung.');
  if (status === 'pending') return t('Zertifikat wird geholt …');
  return error
    ? t('Kein Zertifikat: {error}', { error })
    : t('Kein Zertifikat. Zeigt der Name hierher, und ist Port 443 erreichbar?');
}

/**
 * Send domains (§14.1): extra host names — like send.example.com beside the vault's — that serve
 * only Sends and file requests, each with its own certificate and, if wanted, its own look.
 */
export function SendDomains() {
  useLanguage();
  const [list, setList] = useState<AdminSendDomain[] | null>(null);
  const [result, setResult] = useState<Result>(null);
  const [host, setHost] = useState('');
  const [tls, setTls] = useState<SendDomainTls>('acme');
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState<AdminSendDomain | null>(null);
  const [styling, setStyling] = useState<string | null>(null);

  const reload = useCallback(() => {
    sendDomains().then(setList, (e) => setResult({ tone: 'error', text: errorText(e) }));
  }, []);
  useEffect(reload, [reload]);

  // `/uwu/v1/info` lists them for the vault's editors.
  const changed = () => {
    reload();
    void loadServerInfo(true);
  };

  const add = async () => {
    const name = hostOf(host);
    if (!name) return;
    setBusy(true);
    setResult(null);
    try {
      await addSendDomain(name, tls);
      setHost('');
      setResult({
        tone: 'info',
        text:
          tls === 'acme'
            ? t('Hinzugefügt ✧ Das Zertifikat kommt in ein, zwei Minuten.')
            : t('Hinzugefügt ✧'),
      });
      changed();
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const styled = list?.find((domain) => domain.id === styling) ?? null;

  return (
    <>
      <Section
        heading={t('Send-Domains auf diesem Server')}
        lead={t(
          'Weitere Adressen, unter denen nur Sends und Datei-Anfragen erreichbar sind – etwa send.example.com neben der Adresse des Tresors. Tresor, Anmeldung und Admin-Portal gibt es dort nicht. Jeder Send ist unter allen Adressen erreichbar; die Wahl bestimmt nur, welcher Link angezeigt wird.',
        )}
      >
        {list === null ? (
          <ResultLine result={result} />
        ) : list.length === 0 ? (
          <p className="empty-note">{t('Noch keine Send-Domains.')}</p>
        ) : (
          <div className="card-list">
            {list.map((domain) => (
              <DomainCard
                key={domain.id}
                domain={domain}
                onChanged={changed}
                onStyle={() => setStyling(domain.id)}
                onDelete={() => setDeleting(domain)}
              />
            ))}
          </div>
        )}
      </Section>

      <Section heading={t('Send-Domain hinzufügen')}>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            void add();
          }}
        >
          <TextField
            label={t('Name')}
            value={host}
            spellCheck={false}
            autoCapitalize="off"
            placeholder="send.example.com"
            onChange={setHost}
            hint={
              host.trim() && hostOf(host) !== host.trim()
                ? t('Wird als {host} gespeichert.', { host: hostOf(host) })
                : undefined
            }
          />
          <SettingRow
            label={t('Zertifikat (TLS)')}
            description={
              tls === 'acme'
                ? t(
                    "Der Server holt sich selbst ein Zertifikat von Let's Encrypt, wie für seine Hauptadresse. Dafür muss der Name per DNS auf diesen Server zeigen und Port 443 von außen erreichbar sein.",
                  )
                : t(
                    'Ein Proxy davor (Caddy, nginx, Traefik …) macht TLS für den Namen und reicht die Anfragen mit dem Host-Header an diesen Server weiter.',
                  )
            }
          >
            <Segmented label={t('TLS')} value={tls} onChange={setTls} options={tlsOptions()} />
          </SettingRow>
          <ButtonRow end>
            <Button variant="primary" type="submit" icon="plus" disabled={busy || !hostOf(host)}>
              {t('Hinzufügen')}
            </Button>
          </ButtonRow>
        </form>
        {list !== null && <ResultLine result={result} />}
      </Section>

      {styled && (
        <Modal
          title={t('Aussehen von {host}', { host: styled.host })}
          size="wide"
          onCancel={() => setStyling(null)}
          footer={
            <>
              <span className="spacer" />
              <Button variant="primary" data-autofocus onClick={() => setStyling(null)}>
                {t('Fertig')}
              </Button>
            </>
          }
        >
          <div className="settings-content">
            <Branding
              domain={{ id: styled.id, host: styled.host, custom: styled.branding !== null }}
              onChanged={reload}
            />
          </div>
        </Modal>
      )}

      {deleting && (
        <Modal
          title={t('Send-Domain löschen?')}
          tone="warning"
          onCancel={() => !busy && setDeleting(null)}
          footer={
            <>
              <span className="spacer" />
              <Button data-secondary disabled={busy} onClick={() => setDeleting(null)}>
                {t('Abbrechen')}
              </Button>
              <Button
                variant="danger"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await deleteSendDomain(deleting.id);
                    toast(t('Gelöscht.'));
                    setDeleting(null);
                    changed();
                  } catch (e) {
                    toast(errorText(e), 'error');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t('Löschen')}
              </Button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Sends und Datei-Anfragen, die {host} gewählt haben, bekommen wieder Links unter der Hauptadresse. Links unter {host}, die schon verschickt sind, funktionieren danach nicht mehr.',
              { host: deleting.host },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

function DomainCard({
  domain,
  onChanged,
  onStyle,
  onDelete,
}: {
  domain: AdminSendDomain;
  onChanged: () => void;
  onStyle: () => void;
  onDelete: () => void;
}) {
  useLanguage();
  const [check, setCheck] = useState<SendDomainCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const failed = domain.certificate.status === 'failed';

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      className="channel-card"
      heading={<span className="mono">{domain.host}</span>}
      aside={
        <Badge tone="neutral">
          {domain.branding ? t('eigenes Aussehen') : t('wie der Server')}
        </Badge>
      }
    >
      <SettingRow
        label={t('Zertifikat (TLS)')}
        description={failed ? undefined : certificateText(domain)}
      >
        <Segmented
          label={t('TLS für {host}', { host: domain.host })}
          value={domain.tls}
          onChange={(tls) =>
            void run(async () => {
              await setSendDomainTls(domain.id, tls);
              setCheck(null);
              onChanged();
            })
          }
          options={tlsOptions()}
        />
      </SettingRow>
      {failed && <Callout tone="warning">{certificateText(domain)}</Callout>}
      {check && (
        <ul className="domain-checks" aria-label={t('Ergebnis der Prüfung')}>
          <CheckLine
            ok={check.dns.ok}
            text={
              check.dns.ok
                ? t('DNS: zeigt auf {addresses}', { addresses: check.dns.addresses.join(', ') })
                : check.dns.addresses.length
                  ? t('DNS: zeigt auf {addresses} – nicht auf diesen Server', {
                      addresses: check.dns.addresses.join(', '),
                    })
                  : t('DNS: Der Name löst sich nicht auf.')
            }
          />
          <CheckLine
            ok={check.https.ok}
            text={
              check.https.ok
                ? t('HTTPS: erreichbar')
                : t('HTTPS: {error}', { error: check.https.error ?? t('nicht erreichbar') })
            }
          />
          <CheckLine
            ok={check.routing.ok}
            text={
              check.routing.ok
                ? t('Weiterleitung: kommt bei diesem Server an')
                : t('Weiterleitung: Die Anfragen kommen nicht bei diesem Server an.')
            }
          />
        </ul>
      )}
      <ButtonRow>
        <Button
          size="small"
          disabled={busy}
          onClick={() => void run(async () => setCheck(await checkSendDomain(domain.id)))}
        >
          {busy ? t('Einen Moment …') : t('Prüfen')}
          <span className="sr-only">{domain.host}</span>
        </Button>
        <Button size="small" variant="quiet" icon="eye" onClick={onStyle}>
          {t('Aussehen …')}
          <span className="sr-only">{domain.host}</span>
        </Button>
        <span className="spacer" />
        <Button size="small" variant="quiet-danger" onClick={onDelete}>
          {t('Löschen …')}
          <span className="sr-only">{domain.host}</span>
        </Button>
      </ButtonRow>
    </Card>
  );
}

function CheckLine({ ok, text }: { ok: boolean; text: string }) {
  useLanguage();
  return (
    <li data-ok={ok}>
      <Icon name={ok ? 'check' : 'close'} size={14} />
      <span>
        <span className="sr-only">{ok ? t('in Ordnung') : t('Fehler')}: </span>
        {text}
      </span>
    </li>
  );
}
