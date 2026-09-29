import { useCallback, useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import { ResultLine, Segmented, Toggle, type Result } from '../components/web/controls';
import {
  addChannel,
  alertTitle,
  deleteChannel,
  notifications,
  saveChannel,
  testChannel,
  type Channel,
  type ChannelDraft,
  type ChannelKind,
} from '../lib/admin';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';

const KINDS: { value: ChannelKind; label: string }[] = [
  { value: 'mail', label: N_('Mail') },
  { value: 'ntfy', label: 'ntfy' },
  { value: 'gotify', label: 'Gotify' },
  { value: 'matrix', label: 'Matrix' },
];

const kindLabel = (kind: ChannelKind) => t(KINDS.find((k) => k.value === kind)?.label ?? kind);

const defaultName = (kind: ChannelKind) =>
  kind === 'mail' ? t('Mail an die Admins') : kindLabel(kind);

/** A new channel of `kind`, with every event. */
function blank(kind: ChannelKind, events: string[]): ChannelDraft {
  return {
    kind,
    name: defaultName(kind),
    enabled: true,
    events: [...events],
    config: configOf(kind, {}),
  };
}

/** The fields of `kind`, the secrets empty: left empty they keep the stored one. */
function configOf(kind: ChannelKind, config: Channel['config']): ChannelDraft['config'] {
  switch (kind) {
    case 'ntfy':
      return {
        url: config.url ?? '',
        topic: config.topic ?? '',
        priority: config.priority ?? 3,
        token: '',
      };
    case 'gotify':
      return { url: config.url ?? '', priority: config.priority ?? 5, token: '' };
    case 'matrix':
      return { homeserver: config.homeserver ?? '', roomId: config.roomId ?? '', accessToken: '' };
    default:
      return {};
  }
}

const draftOf = (channel: Channel): ChannelDraft => ({
  kind: channel.kind,
  name: channel.name,
  enabled: channel.enabled,
  events: [...channel.events],
  config: configOf(channel.kind, channel.config),
});

/**
 * Where the server says that something is wrong — a backup failed, the certificate runs out,
 * mail does not go out: by mail to the admins, or to ntfy, Gotify or a Matrix room.
 */
export function Notifications() {
  useLanguage();
  const [channels, setChannels] = useState<Channel[] | null>(null);
  const [events, setEvents] = useState<string[]>([]);
  const [adding, setAdding] = useState<ChannelDraft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    notifications().then(
      (list) => {
        setChannels(list.channels);
        setEvents(list.events);
      },
      (e) => setError(errorText(e)),
    );
  }, []);
  useEffect(load, [load]);

  if (error) return <p className="form-error">{error}</p>;
  if (!channels) return null;
  return (
    <>
      <p className="settings-lead">
        {t(
          'Der Server meldet sich, wenn etwas nicht stimmt, und noch einmal, wenn es vorbei ist – jede Meldung höchstens einmal pro Stunde und Kanal. Die Nachrichten nennen keine Konten, nur Zahlen. Geht ein Kanal nicht, versucht der Server es später wieder und zeigt es in der Übersicht.',
        )}
      </p>
      <div className="channel-list">
        {channels.map((channel) => (
          <ChannelCard
            key={channel.id}
            channel={channel}
            events={events}
            onSaved={(saved) => setChannels(channels.map((c) => (c.id === saved.id ? saved : c)))}
            onDeleted={() => setChannels(channels.filter((c) => c.id !== channel.id))}
          />
        ))}
        {channels.length === 0 && (
          <p className="empty-note">
            {t('Kein Kanal: Der Server meldet sich nur im Log und in der Übersicht.')}
          </p>
        )}
        {adding ? (
          <ChannelCard
            events={events}
            initial={adding}
            onSaved={(saved) => {
              setChannels([...channels, saved]);
              setAdding(null);
              toast(t('Kanal hinzugefügt ✧'), 'info');
            }}
            onCancel={() => setAdding(null)}
          />
        ) : (
          <div className="form-actions">
            <button className="primary" onClick={() => setAdding(blank('ntfy', events))}>
              {t('Kanal hinzufügen')}
            </button>
          </div>
        )}
      </div>
    </>
  );
}

type CardProps = {
  events: string[];
  onSaved: (channel: Channel) => void;
} & (
  | { channel: Channel; onDeleted: () => void; initial?: never; onCancel?: never }
  | { channel?: never; onDeleted?: never; initial: ChannelDraft; onCancel: () => void }
);

/** One channel: its settings, which events it gets, how it went last. A new one without `channel`. */
function ChannelCard({ channel, events, initial, onSaved, onDeleted, onCancel }: CardProps) {
  useLanguage();
  const [saved, setSaved] = useState<ChannelDraft>(() => initial ?? draftOf(channel!));
  const [draft, setDraft] = useState<ChannelDraft>(saved);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);
  const [deleting, setDeleting] = useState(false);
  const dirty = !channel || JSON.stringify(draft) !== JSON.stringify(saved);
  const config = draft.config;
  const setConfig = (change: Partial<ChannelDraft['config']>) =>
    setDraft({ ...draft, config: { ...config, ...change } });
  const toggleEvent = (event: string, on: boolean) =>
    setDraft({
      ...draft,
      events: on ? [...draft.events, event] : draft.events.filter((e) => e !== event),
    });

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setResult(null);
    try {
      await work();
    } catch (e) {
      setResult({ tone: 'error', text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const save = () =>
    run(async () => {
      const done = channel ? await saveChannel(channel.id, draft) : await addChannel(draft);
      if (channel) {
        const next = draftOf(done);
        setSaved(next);
        setDraft(next);
        setResult({ tone: 'info', text: t('Gespeichert ✧') });
      }
      onSaved(done);
    });

  const secretHint = (set: boolean | undefined) =>
    channel && set ? (
      <small className="field-hint">
        {t('Gespeichert. Leer lassen behält ihn, solange die Adresse gleich bleibt.')}
      </small>
    ) : null;

  const status = channel?.status;
  return (
    <section
      className="channel-card"
      aria-label={draft.name || kindLabel(draft.kind)}
      data-disabled={channel && !channel.enabled ? true : undefined}
    >
      <div className="channel-head">
        <span className="badge">{kindLabel(draft.kind)}</span>
        <b className="channel-name">{channel ? channel.name : t('Neuer Kanal')}</b>
        <span className="spacer" />
        <Toggle
          label={t('Kanal an')}
          checked={draft.enabled}
          onChange={(enabled) => setDraft({ ...draft, enabled })}
        />
      </div>

      {!channel && (
        <Segmented
          label={t('Art')}
          value={draft.kind}
          onChange={(kind) =>
            setDraft({
              ...draft,
              kind,
              name: draft.name === defaultName(draft.kind) ? defaultName(kind) : draft.name,
              config: configOf(kind, {}),
            })
          }
          options={KINDS.map((k) => ({ value: k.value, label: t(k.label) }))}
        />
      )}

      <div className="field-grid wide">
        <label className="field">
          <span>{t('Name')}</span>
          <input
            value={draft.name}
            maxLength={64}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
        </label>
        {draft.kind === 'ntfy' && (
          <>
            <label className="field">
              <span>{t('Server')}</span>
              <input
                value={config.url ?? ''}
                onChange={(e) => setConfig({ url: e.target.value })}
                placeholder="https://ntfy.example.com"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Thema')}</span>
              <input
                value={config.topic ?? ''}
                onChange={(e) => setConfig({ topic: e.target.value })}
                placeholder="uwulock-alerts"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Priorität')}</span>
              <select
                value={config.priority ?? 3}
                onChange={(e) => setConfig({ priority: Number(e.target.value) })}
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    {n === 1
                      ? t('1 – leise')
                      : n === 3
                        ? t('3 – normal')
                        : n === 5
                          ? t('5 – dringend')
                          : n}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>{t('Zugangs-Token (freiwillig)')}</span>
              <PasswordInput
                value={config.token ?? ''}
                onChange={(token) => setConfig({ token })}
                autoComplete="new-password"
              />
              {secretHint(channel?.config.tokenSet)}
            </label>
          </>
        )}
        {draft.kind === 'gotify' && (
          <>
            <label className="field">
              <span>{t('Server')}</span>
              <input
                value={config.url ?? ''}
                onChange={(e) => setConfig({ url: e.target.value })}
                placeholder="https://gotify.example.com"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Priorität')}</span>
              <input
                type="number"
                min={0}
                max={10}
                value={config.priority ?? 5}
                onChange={(e) => setConfig({ priority: Number(e.target.value) })}
              />
            </label>
            <label className="field">
              <span>{t('App-Token')}</span>
              <PasswordInput
                value={config.token ?? ''}
                onChange={(token) => setConfig({ token })}
                autoComplete="new-password"
              />
              {secretHint(channel?.config.tokenSet)}
            </label>
          </>
        )}
        {draft.kind === 'matrix' && (
          <>
            <label className="field">
              <span>{t('Homeserver')}</span>
              <input
                value={config.homeserver ?? ''}
                onChange={(e) => setConfig({ homeserver: e.target.value })}
                placeholder="https://matrix.example.org"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Raum-ID')}</span>
              <input
                value={config.roomId ?? ''}
                onChange={(e) => setConfig({ roomId: e.target.value })}
                placeholder="!abc:example.org"
                spellCheck={false}
              />
            </label>
            <label className="field">
              <span>{t('Access-Token des Kontos, das schreibt')}</span>
              <PasswordInput
                value={config.accessToken ?? ''}
                onChange={(accessToken) => setConfig({ accessToken })}
                autoComplete="new-password"
              />
              {secretHint(channel?.config.accessTokenSet)}
            </label>
          </>
        )}
      </div>
      {draft.kind === 'mail' && (
        <p className="field-hint">
          {t('Geht an jedes Admin-Konto, über den Mailserver aus den Einstellungen.')}
        </p>
      )}

      <div className="check-grid" role="group" aria-label={t('Meldet')}>
        {events.map((event) => (
          <label key={event} className="check">
            <input
              type="checkbox"
              checked={draft.events.includes(event)}
              onChange={(e) => toggleEvent(event, e.target.checked)}
            />
            <span>{alertTitle(event)}</span>
          </label>
        ))}
      </div>

      {status && (
        <p className="channel-status" data-alarm={status.lastError ? true : undefined}>
          {status.lastError
            ? t('Letzter Fehler {when}: {error}', {
                when: when(status.lastErrorDate) ?? '',
                error: status.lastError,
              })
            : status.lastSuccess
              ? t('Zuletzt zugestellt {when}.', { when: when(status.lastSuccess) ?? '' })
              : t('Noch nichts zugestellt.')}
          {status.queued > 0 &&
            ` ${t('{n} Meldungen warten auf den nächsten Versuch.', { n: status.queued })}`}
        </p>
      )}

      <div className="form-actions">
        {channel && (
          <>
            <button
              disabled={busy || dirty}
              title={dirty ? t('Erst speichern') : undefined}
              onClick={() =>
                void run(async () => {
                  await testChannel(channel.id);
                  setResult({ tone: 'info', text: t('Die Testnachricht ist raus ✧') });
                })
              }
            >
              {t('Testen')}
            </button>
            <button className="danger" disabled={busy} onClick={() => setDeleting(true)}>
              {t('Löschen …')}
            </button>
          </>
        )}
        <span className="spacer" />
        {channel ? (
          <button disabled={busy || !dirty} onClick={() => setDraft(saved)} data-secondary>
            {t('Verwerfen')}
          </button>
        ) : (
          <button disabled={busy} onClick={onCancel} data-secondary>
            {t('Abbrechen')}
          </button>
        )}
        <button
          className="primary"
          disabled={busy || !dirty || !draft.name.trim()}
          onClick={() => void save()}
        >
          {channel ? t('Speichern') : t('Hinzufügen')}
        </button>
      </div>
      <ResultLine result={result} />

      {deleting && channel && (
        <Modal
          title={t('Kanal „{name}“ löschen?', { name: channel.name })}
          tone="warning"
          onCancel={() => setDeleting(false)}
          footer={
            <>
              <span className="spacer" />
              <button onClick={() => setDeleting(false)} data-autofocus>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                data-secondary
                disabled={busy}
                onClick={() => {
                  setDeleting(false);
                  void run(async () => {
                    await deleteChannel(channel.id);
                    onDeleted?.();
                  });
                }}
              >
                {t('Löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">{t('Über diesen Kanal kommen dann keine Meldungen mehr.')}</p>
        </Modal>
      )}
    </section>
  );
}
