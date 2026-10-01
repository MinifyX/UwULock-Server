import { useEffect, useState, type ReactNode } from 'react';
import { copyGenerated } from '../../lib/api';
import { errorText } from '../../lib/errors';
import { locale, t, useLanguage } from '../../lib/i18n';
import {
  RDP_DEFAULTS,
  bool,
  connectCommand,
  deepLink,
  desktopSystem,
  forwardText,
  identityOf,
  num,
  obj,
  rdpFile,
  rdpFileName,
  ref,
  str,
  titleOf,
  type Index,
  type SpaceName,
  type SuiteRecord,
} from '../../lib/suite/model';
import { revealSecret } from '../../lib/suite/sync';
import { toast } from '../../lib/toast';
import { Icon, type IconName } from '../Icon';
import { save } from '../web/controls';
import { KIND_ICON, kindLabel, workspaceLabel, authLabel } from './labels';

type Props = {
  space: SpaceName;
  record: SuiteRecord;
  all: Index;
  records: SuiteRecord[];
  onEdit: () => void;
  onDelete: () => void;
  onOpen: (id: string) => void;
  /** A new port forward for this host. */
  onAddForward?: () => void;
  onMove?: (by: -1 | 1) => void;
};

export function Row({
  label,
  children,
  actions,
  mono,
}: {
  label: string;
  children: ReactNode;
  actions?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="detail-row">
      <div className="detail-text">
        <span className="detail-label">{label}</span>
        <span className={mono ? 'detail-value mono suite-value' : 'detail-value suite-value'}>
          {children}
        </span>
      </div>
      {actions && <div className="detail-actions">{actions}</div>}
    </div>
  );
}

function Tool({ label, icon, onClick }: { label: string; icon: IconName; onClick: () => void }) {
  return (
    <button className="icon-button" onClick={onClick} aria-label={label} title={label}>
      <Icon name={icon} size={15} />
    </button>
  );
}

async function copyText(text: string, what: string) {
  try {
    await copyGenerated(text);
    toast(t('{what} kopiert ✧', { what }));
  } catch (e) {
    toast(errorText(e), 'error');
  }
}

/** A secret record's content: dots until the eye is clicked, then read from the module. */
function SecretRow({
  space,
  id,
  label,
  multiline,
  download,
}: {
  space: SpaceName;
  id: string;
  label: string;
  multiline?: boolean;
  /** Offer it as a file under this name. */
  download?: string;
}) {
  useLanguage();
  const [value, setValue] = useState<string | null>(null);
  // Out of sight when the window is left alone for a while.
  useEffect(() => {
    if (value === null) return;
    const timer = window.setTimeout(() => setValue(null), 60_000);
    return () => window.clearTimeout(timer);
  }, [value]);
  useEffect(() => setValue(null), [id]);
  const read = () => revealSecret(space, id);
  return (
    <Row
      label={label}
      mono
      actions={
        <>
          <Tool
            label={
              value === null ? t('{label} zeigen', { label }) : t('{label} verbergen', { label })
            }
            icon={value === null ? 'eye' : 'eyeOff'}
            onClick={() =>
              value !== null
                ? setValue(null)
                : void read().then(setValue, (e) => toast(errorText(e), 'error'))
            }
          />
          <Tool
            label={t('{label} kopieren', { label })}
            icon="copy"
            onClick={() =>
              void read().then(
                (text) => copyText(text, label),
                (e) => toast(errorText(e), 'error'),
              )
            }
          />
          {download && (
            <Tool
              label={t('{label} herunterladen', { label })}
              icon="download"
              onClick={() =>
                void read().then(
                  (text) => save(new Blob([text], { type: 'application/octet-stream' }), download),
                  (e) => toast(errorText(e), 'error'),
                )
              }
            />
          )}
        </>
      }
    >
      {value === null ? (
        '••••••••••••'
      ) : multiline ? (
        <pre className="suite-secret">{value}</pre>
      ) : (
        value
      )}
    </Row>
  );
}

/** A link to another record, by its name. */
function Link({
  target,
  onOpen,
}: {
  target: SuiteRecord | undefined;
  onOpen: (id: string) => void;
}) {
  useLanguage();
  if (!target) return <span className="muted">{t('Keine')}</span>;
  return (
    <button className="button-link" onClick={() => onOpen(target.id)}>
      {titleOf(target) || t('(ohne Namen)')}
    </button>
  );
}

const onOff = (on: boolean) => (on ? t('An') : t('Aus'));

function RdpRows({
  host,
  all,
  onOpen,
}: {
  host: SuiteRecord;
  all: Index;
  onOpen: (id: string) => void;
}) {
  useLanguage();
  const rdp = { ...RDP_DEFAULTS, ...(obj(host.payload?.rdp) ?? {}) };
  const display = str(rdp.display);
  const gateway = obj(rdp.gateway);
  const drives = obj(rdp.drives);
  const audio = str(rdp.audio);
  return (
    <>
      <section className="detail-card">
        <h3 className="detail-card-title">{t('Anzeige')}</h3>
        <Row label={t('Größe')}>
          {display === 'fixed'
            ? `${num(rdp.width)} × ${num(rdp.height)}`
            : display === 'fullscreen'
              ? t('Vollbild')
              : t('An das Fenster anpassen')}
        </Row>
        <Row label={t('Farbtiefe')}>{t('{bits} Bit', { bits: num(rdp.colorDepth, 32) })}</Row>
        <Row label={t('Einpassen statt scrollen')}>{onOff(bool(rdp.smartSizing, true))}</Row>
        <Row label={t('Hintergrundbild')}>{onOff(bool(rdp.wallpaper, true))}</Row>
        <Row label={t('Grafik-Pipeline (RDPEGFX)')}>{onOff(bool(rdp.graphicsPipeline, true))}</Row>
      </section>
      <section className="detail-card">
        <h3 className="detail-card-title">{t('Verbindung')}</h3>
        <Row label={t('Ton')}>
          {audio === 'remote'
            ? t('Auf dem Server lassen')
            : audio === 'off'
              ? t('Aus')
              : t('Hier abspielen')}
        </Row>
        <Row label={t('Zwischenablage')}>{onOff(bool(rdp.clipboard, true))}</Row>
        <Row label={t('Konsolensitzung (/admin)')}>{onOff(bool(rdp.admin))}</Row>
        <Row label={t('Network Level Authentication')}>{onOff(bool(rdp.nla, true))}</Row>
        <Row label={t('Laufwerke')}>
          {drives === null
            ? t('Wie die Gruppe')
            : bool(drives.enabled)
              ? (Array.isArray(drives.drives) ? drives.drives : [])
                  .map((d) => {
                    const drive = obj(d);
                    return drive ? `${str(drive.name)} (${str(drive.path)})` : '';
                  })
                  .filter(Boolean)
                  .join(', ') || t('An')
              : t('Aus')}
        </Row>
        {gateway && str(gateway.address) && (
          <>
            <Row label={t('Gateway')} mono>
              {str(gateway.address)}:{num(gateway.port, 443)}
            </Row>
            <Row label={t('Anmeldung am Gateway')}>
              {bool(gateway.useHostLogin) ? (
                t('Wie am Host')
              ) : (
                <Link
                  target={all.get(ref(host.payload?.gateway_identity_id) ?? '')}
                  onOpen={onOpen}
                />
              )}
            </Row>
            <Row label={t('Gateway im lokalen Netz umgehen')}>
              {onOff(bool(gateway.bypassLocal))}
            </Row>
          </>
        )}
      </section>
    </>
  );
}

export function SuiteDetail({
  space,
  record,
  all,
  records,
  onEdit,
  onDelete,
  onOpen,
  onAddForward,
  onMove,
}: Props) {
  useLanguage();
  const p = record.payload ?? {};
  const title = titleOf(record) || t('(ohne Namen)');
  const desktop = desktopSystem(navigator.userAgent, navigator.maxTouchPoints ?? 0);
  const app = space === 'ssh' ? 'UwUSSH' : 'UwURDP';

  const hostTools =
    record.kind === 'host' ? (
      <>
        <button
          className="primary"
          onClick={() => void copyText(connectCommand(space, record, all), t('Befehl'))}
        >
          <Icon name="copy" size={15} />
          {space === 'ssh' ? t('Befehl kopieren') : t('Adresse kopieren')}
        </button>
        {desktop && (
          <button
            className="quiet"
            onClick={() => {
              // The app asks the browser; only the record's id goes along.
              window.location.href = deepLink(space, record.id);
            }}
          >
            <Icon name="external" size={15} />
            {t('In {app} öffnen', { app })}
          </button>
        )}
        {space === 'rdp' && (
          <button
            className="quiet"
            onClick={() =>
              save(
                new Blob([rdpFile(record, all)], { type: 'application/x-rdp' }),
                rdpFileName(record),
              )
            }
          >
            <Icon name="download" size={15} />
            {t('.rdp-Datei')}
          </button>
        )}
      </>
    ) : null;

  const forwards =
    record.kind === 'host'
      ? records.filter((r) => r.kind === 'port_forward' && ref(r.payload?.host_id) === record.id)
      : [];
  const hostsOfGroup =
    record.kind === 'group'
      ? records.filter((r) => r.kind === 'host' && ref(r.payload?.group_id) === record.id)
      : [];
  const knownHost = record.kind === 'known_host';

  return (
    <article className="detail suite-detail" aria-label={title}>
      <header className="detail-head">
        <span className="item-tile" data-size="large" data-hue={space === 'ssh' ? '4' : '5'}>
          <Icon name={KIND_ICON[record.kind] ?? 'note'} size={26} />
        </span>
        <div className="detail-title">
          <h2>{title}</h2>
          <p className="chips">
            <span className="chip">{kindLabel(record.kind)}</span>
            {(record.kind === 'host' || record.kind === 'group') && (
              <span className="chip">{workspaceLabel(str(p.workspace))}</span>
            )}
          </p>
        </div>
        <div className="detail-tools">
          {hostTools}
          {!knownHost && (
            <button className="quiet" data-edit onClick={onEdit}>
              <Icon name="pencil" size={15} />
              {t('Bearbeiten')}
            </button>
          )}
          {onMove && (
            <>
              <button
                className="icon-button"
                onClick={() => onMove(-1)}
                aria-label={t('Nach oben')}
                title={t('Nach oben')}
              >
                <Icon name="up" size={15} />
              </button>
              <button
                className="icon-button suite-down"
                onClick={() => onMove(1)}
                aria-label={t('Nach unten')}
                title={t('Nach unten')}
              >
                <Icon name="up" size={15} />
              </button>
            </>
          )}
          <button
            className="quiet danger-text"
            onClick={onDelete}
            title={t('Löschen')}
            aria-label={t('Löschen')}
          >
            <Icon name="trash" size={15} />
          </button>
        </div>
      </header>

      {record.kind === 'host' && (
        <>
          <section className="detail-card">
            <Row
              label={t('Adresse')}
              mono
              actions={
                <Tool
                  label={t('Adresse kopieren')}
                  icon="copy"
                  onClick={() => void copyText(str(p.address), t('Adresse'))}
                />
              }
            >
              {str(p.address)}
            </Row>
            <Row label={t('Port')} mono>
              {num(p.port)}
            </Row>
            <Row label={t('Identität')}>
              <Link target={all.get(ref(p.identity_id) ?? '')} onOpen={onOpen} />
              {!ref(p.identity_id) && identityOf(record, all) && (
                <> · {t('von der Gruppe: {name}', { name: titleOf(identityOf(record, all)!) })}</>
              )}
            </Row>
            <Row label={t('Gruppe')}>
              <Link target={all.get(ref(p.group_id) ?? '')} onOpen={onOpen} />
            </Row>
            {str(p.comment) && <Row label={t('Kommentar')}>{str(p.comment)}</Row>}
            {space === 'ssh' && (
              <Row label={t('Befehl')} mono>
                {connectCommand(space, record, all)}
              </Row>
            )}
          </section>
          {space === 'rdp' && <RdpRows host={record} all={all} onOpen={onOpen} />}
          {space === 'ssh' && (
            <section className="detail-card">
              <h3 className="detail-card-title">{t('Port-Weiterleitungen')}</h3>
              {forwards.map((f) => (
                <Row
                  key={f.id}
                  label={str(f.payload?.name) || t('(ohne Namen)')}
                  mono
                  actions={<Tool label={t('Öffnen')} icon="chevron" onClick={() => onOpen(f.id)} />}
                >
                  {forwardText(f.payload ?? {})}
                  {bool(f.payload?.autostart) && ` · ${t('startet mit')}`}
                </Row>
              ))}
              {onAddForward && (
                <button className="quiet" onClick={onAddForward}>
                  <Icon name="plus" size={15} />
                  {t('Weiterleitung hinzufügen')}
                </button>
              )}
            </section>
          )}
        </>
      )}

      {record.kind === 'group' && (
        <section className="detail-card">
          {space === 'rdp' && (
            <Row label={t('Identität für alle Hosts')}>
              <Link target={all.get(ref(p.identity_id) ?? '')} onOpen={onOpen} />
            </Row>
          )}
          {space === 'rdp' && (
            <Row label={t('Laufwerke für alle Hosts')}>
              {bool(obj(p.drives)?.enabled) ? t('An') : t('Aus')}
            </Row>
          )}
          <Row label={t('Hosts')}>
            {hostsOfGroup.map((h) => titleOf(h)).join(', ') || t('Keine')}
          </Row>
        </section>
      )}

      {record.kind === 'identity' && (
        <section className="detail-card">
          <Row
            label={t('Benutzername')}
            mono
            actions={
              <Tool
                label={t('Benutzername kopieren')}
                icon="copy"
                onClick={() => void copyText(str(p.username), t('Benutzername'))}
              />
            }
          >
            {str(p.username)}
          </Row>
          {space === 'rdp' && str(p.domain) && (
            <Row label={t('Domäne')} mono>
              {str(p.domain)}
            </Row>
          )}
          <Row label={t('Anmeldung mit')}>{authLabel(str(p.auth_type))}</Row>
          {ref(p.key_id) && (
            <Row label={t('Schlüssel')}>
              <Link target={all.get(ref(p.key_id)!)} onOpen={onOpen} />
            </Row>
          )}
          {ref(p.password_secret_id) && all.has(ref(p.password_secret_id)!) && (
            <SecretRow space={space} id={ref(p.password_secret_id)!} label={t('Passwort')} />
          )}
        </section>
      )}

      {record.kind === 'key' && (
        <section className="detail-card">
          <Row label={t('Typ')} mono>
            {str(p.key_type)}
          </Row>
          {str(p.public_key) && (
            <Row
              label={t('Öffentlicher Schlüssel')}
              mono
              actions={
                <Tool
                  label={t('Öffentlichen Schlüssel kopieren')}
                  icon="copy"
                  onClick={() => void copyText(str(p.public_key), t('Öffentlicher Schlüssel'))}
                />
              }
            >
              <span className="suite-wrap">{str(p.public_key)}</span>
            </Row>
          )}
          {ref(p.private_secret_id) && all.has(ref(p.private_secret_id)!) && (
            <SecretRow
              space={space}
              id={ref(p.private_secret_id)!}
              label={t('Privater Schlüssel')}
              multiline
              download={str(p.key_type) === 'ssh-rsa' ? 'id_rsa' : 'id_ed25519'}
            />
          )}
          {ref(p.passphrase_secret_id) && all.has(ref(p.passphrase_secret_id)!) && (
            <SecretRow space={space} id={ref(p.passphrase_secret_id)!} label={t('Passphrase')} />
          )}
        </section>
      )}

      {record.kind === 'snippet' && (
        <section className="detail-card">
          <Row
            label={t('Befehl')}
            mono
            actions={
              <Tool
                label={t('Snippet kopieren')}
                icon="copy"
                onClick={() => void copyText(str(p.body), t('Snippet'))}
              />
            }
          >
            <pre className="suite-secret">{str(p.body)}</pre>
          </Row>
          {str(p.group_path) && <Row label={t('Ordner')}>{str(p.group_path)}</Row>}
        </section>
      )}

      {record.kind === 'port_forward' && (
        <section className="detail-card">
          <Row label={t('Host')}>
            <Link target={all.get(ref(p.host_id) ?? '')} onOpen={onOpen} />
          </Row>
          <Row label={t('Art')}>
            {str(p.kind) === 'remote'
              ? t('Entfernt (-R)')
              : str(p.kind) === 'local'
                ? t('Lokal (-L)')
                : str(p.kind)}
          </Row>
          <Row label={t('Lauscht auf')} mono>
            {str(p.bind_address)}:{num(p.bind_port)}
          </Row>
          <Row label={t('Führt zu')} mono>
            {str(p.target_host)}:{num(p.target_port)}
          </Row>
          <Row label={t('Startet mit dem Terminal')}>{onOff(bool(p.autostart))}</Row>
        </section>
      )}

      {knownHost && (
        <section className="detail-card">
          <Row label={t('Algorithmus')} mono>
            {str(p.algorithm)}
          </Row>
          <Row label={t('Fingerabdruck')} mono>
            <span className="suite-wrap">{str(p.fingerprint_sha256)}</span>
          </Row>
          <Row label={t('Öffentlicher Schlüssel')} mono>
            <span className="suite-wrap">{str(p.public_key)}</span>
          </Row>
          {num(p.first_seen_ms) > 0 && (
            <Row label={t('Zuerst gesehen')}>
              {new Date(num(p.first_seen_ms)).toLocaleString(locale())}
            </Row>
          )}
        </section>
      )}
    </article>
  );
}
