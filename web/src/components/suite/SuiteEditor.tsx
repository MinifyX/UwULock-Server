import { useMemo, useState, type FormEvent } from 'react';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import {
  AUTH_TYPES,
  DEFAULT_PORT,
  RDP_DEFAULTS,
  WORKSPACES,
  applyEdit,
  blank,
  bool,
  nextPosition,
  num,
  obj,
  ref,
  str,
  titleOf,
  type Index,
  type Json,
  type Payload,
  type ShownKind,
  type SpaceName,
  type SuiteRecord,
} from '../../lib/suite/model';
import {
  generateKey,
  inspectPrivateKey,
  inspectPublicKey,
  passphraseOpens,
} from '../../lib/suite/keys';
import { Batch, SpaceChanged } from '../../lib/suite/sync';
import { toast } from '../../lib/toast';
import { GeneratorDialog } from '../GeneratorDialog';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { PasswordInput } from '../PasswordInput';
import {
  Callout,
  Checkbox,
  Field,
  FieldGroup,
  FormRow,
  IconButton,
  RepeatRow,
  Segmented,
  Select,
  TextField,
} from '../ui';
import { authLabel, kindLabel, workspaceLabel } from './labels';

export type EditorTarget = {
  kind: ShownKind;
  /** The record to change; none for a new one. */
  record: SuiteRecord | null;
  /** Fields a new record starts with (the host of a new port forward, …). */
  preset?: Payload;
};

type Props = EditorTarget & {
  space: SpaceName;
  records: SuiteRecord[];
  all: Index;
  onClose: () => void;
  onSaved: (id: string) => void;
};

const NONE = '';

function port(text: string): number | null {
  const n = Number(text);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** A number field over a numeric payload field; the text as typed until it is a number. */
function NumberField({
  label,
  value,
  onChange,
  error,
}: {
  label: string;
  value: Json | undefined;
  onChange: (value: number | string) => void;
  error?: string;
}) {
  return (
    <TextField
      label={label}
      value={typeof value === 'number' ? String(value) : str(value)}
      inputMode="numeric"
      mono
      error={error}
      onChange={(text) => onChange(/^\d+$/.test(text) ? Number(text) : text)}
    />
  );
}

export function SuiteEditor({
  space,
  kind,
  record,
  preset,
  records,
  all,
  onClose,
  onSaved,
}: Props) {
  useLanguage();
  const opened = useMemo<Payload>(
    () =>
      record?.payload ?? {
        ...blank(space, kind, nextPosition(records.filter((r) => r.kind === kind))),
        ...preset,
      },
    // Only what the form was opened with: a change elsewhere doesn't reset what is typed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  const [draft, setDraft] = useState<Payload>(opened);
  /** A new password for an identity; `null` keeps the one there is. */
  const [password, setPassword] = useState<string | null>(record ? null : '');
  const [generator, setGenerator] = useState(false);
  // A new key: made here or brought along.
  const [keyMode, setKeyMode] = useState<'generate' | 'import'>('generate');
  const [comment, setComment] = useState('');
  const [privateText, setPrivateText] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [tried, setTried] = useState(false);

  const set = (field: string, value: Json) => setDraft((d) => ({ ...d, [field]: value }));
  const rdp = { ...RDP_DEFAULTS, ...(obj(draft.rdp) ?? {}) };
  const setRdp = (field: string, value: Json | undefined) =>
    setDraft((d) => {
      const next: Payload = { ...RDP_DEFAULTS, ...(obj(d.rdp) ?? {}) };
      if (value === undefined) delete next[field];
      else next[field] = value;
      return { ...d, rdp: next };
    });

  const of = (k: string) => records.filter((r) => r.kind === k);
  const options = (k: string, none: string) => [
    { value: NONE, label: none },
    ...of(k)
      .map((r) => ({ value: r.id, label: titleOf(r) || t('(ohne Namen)') }))
      .sort((a, b) => a.label.localeCompare(b.label)),
  ];

  const problems = (): string | null => {
    switch (kind) {
      case 'host':
        if (!str(draft.address).trim()) return t('Bitte gib eine Adresse ein.');
        if (port(String(draft.port)) === null) return t('Der Port ist eine Zahl von 1 bis 65535.');
        return null;
      case 'group':
        return str(draft.name).trim() ? null : t('Bitte gib einen Namen ein.');
      case 'identity':
        return str(draft.username).trim() || str(draft.label).trim()
          ? null
          : t('Bitte gib einen Benutzernamen ein.');
      case 'key':
        if (!str(draft.label).trim()) return t('Bitte gib einen Namen ein.');
        if (!record && keyMode === 'import' && !privateText.trim() && !str(draft.public_key).trim())
          return t('Füge einen privaten oder öffentlichen Schlüssel ein.');
        return null;
      case 'snippet':
        return str(draft.label).trim() && str(draft.body).trim()
          ? null
          : t('Ein Snippet braucht einen Namen und einen Befehl.');
      case 'port_forward':
        if (!ref(draft.host_id)) return t('Wähle den Host der Weiterleitung.');
        if (port(String(draft.bind_port)) === null || port(String(draft.target_port)) === null)
          return t('Der Port ist eine Zahl von 1 bis 65535.');
        return null;
      default:
        return null;
    }
  };

  /** The key's material for a new key record: its secrets go into the batch. */
  const keyMaterial = async (batch: Batch, payload: Payload): Promise<Payload> => {
    if (keyMode === 'generate') {
      setBusy(
        passphrase
          ? t('Der Schlüssel wird erzeugt und verschlüsselt …')
          : t('Der Schlüssel wird erzeugt …'),
      );
      // Let the words show before the module works.
      await new Promise((resolve) => window.setTimeout(resolve, 30));
      const made = await generateKey(comment.trim(), passphrase);
      return {
        ...payload,
        key_type: made.keyType,
        public_key: made.publicKey,
        private_secret_id: await batch.add('secret', made.privateKey),
        passphrase_secret_id: passphrase ? await batch.add('secret', passphrase) : null,
      };
    }
    const text = privateText.trim() ? privateText.replace(/\r\n/g, '\n').trimEnd() + '\n' : '';
    let keyType = str(payload.key_type);
    let publicKey = str(payload.public_key).trim();
    if (text) {
      // OpenSSH keys say what they are; PEM and PuTTY keys are kept as they are.
      const info = await inspectPrivateKey(text).catch(() => null);
      if (info) {
        keyType = info.keyType;
        publicKey = publicKey || info.publicKey;
        if (info.encrypted && passphrase && !(await passphraseOpens(text, passphrase)))
          throw { kind: 'refused', message: t('Die Passphrase öffnet diesen Schlüssel nicht.') };
      }
    }
    if (publicKey) {
      const info = await inspectPublicKey(publicKey).catch(() => null);
      if (info) keyType = info.keyType;
    }
    return {
      ...payload,
      key_type: keyType || 'unknown',
      public_key: publicKey,
      private_secret_id: text ? await batch.add('secret', text) : null,
      passphrase_secret_id: text && passphrase ? await batch.add('secret', passphrase) : null,
    };
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setTried(true);
    const problem = problems();
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    setBusy(t('Wird gespeichert …'));
    try {
      const batch = new Batch(space);
      let payload: Payload = { ...draft };
      for (const field of ['port', 'bind_port', 'target_port', 'position'])
        if (field in payload && typeof payload[field] === 'string')
          payload[field] = Number(payload[field]) || 0;
      if (kind === 'host' && obj(payload.rdp)) {
        const r = { ...obj(payload.rdp)! };
        for (const field of ['width', 'height', 'colorDepth'])
          if (typeof r[field] === 'string') r[field] = Number(r[field]) || 0;
        const gateway = obj(r.gateway);
        if (gateway && typeof gateway.port === 'string')
          r.gateway = { ...gateway, port: Number(gateway.port) || 443 };
        payload.rdp = r;
      }
      if (kind === 'identity' && password !== null && password !== '') {
        const latest = record ? (all.get(record.id)?.payload ?? opened) : opened;
        const existing = ref(latest.password_secret_id);
        if (existing && all.has(existing)) await batch.edit(existing, password);
        else payload.password_secret_id = await batch.add('secret', password);
      }
      if (kind === 'key' && !record) payload = await keyMaterial(batch, payload);
      setBusy(t('Wird gespeichert …'));
      let id: string;
      if (record) {
        const latest = all.get(record.id)?.payload ?? opened;
        const edited = applyEdit(latest, opened, payload);
        // A secret made just now replaces the old pointer.
        if (payload.password_secret_id !== opened.password_secret_id)
          edited.password_secret_id = payload.password_secret_id ?? null;
        await batch.edit(record.id, edited);
        id = record.id;
      } else {
        id = await batch.add(kind, payload);
      }
      const conflicts = await batch.push();
      if (conflicts.length) {
        setConflict(true);
        return;
      }
      toast(t('Gespeichert ✧'));
      onSaved(id);
    } catch (e) {
      if (e instanceof SpaceChanged) {
        setError(
          t(
            'Der Bereich hat inzwischen einen neuen Schlüssel bekommen und ist neu geladen. Speichere bitte noch einmal.',
          ),
        );
      } else setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const title = record
    ? t('{kind} bearbeiten', { kind: kindLabel(kind) })
    : t('Neu: {kind}', { kind: kindLabel(kind) });

  const workspace = (
    <Field label={t('Bereich')}>
      <Select
        value={str(draft.workspace) === 'business' ? 'business' : 'private'}
        options={WORKSPACES.map((w) => ({ value: w, label: workspaceLabel(w) }))}
        onChange={(w) => set('workspace', w)}
      />
    </Field>
  );

  const drivesEditor = (
    value: Json | undefined,
    onChange: (v: Json | undefined) => void,
    inherit: boolean,
  ) => {
    const drives = obj(value);
    const mode =
      drives === null ? (inherit ? 'group' : 'off') : bool(drives.enabled) ? 'on' : 'off';
    const list = (Array.isArray(drives?.drives) ? drives.drives : []).map((d) => obj(d) ?? {});
    const setList = (next: Payload[]) =>
      onChange({ ...(drives ?? {}), enabled: true, drives: next });
    return (
      <FieldGroup
        title={t('Laufwerke')}
        description={t(
          'Ordner dieses Computers, die der Server als \\\\tsclient\\<Name> sieht. Die Pfade gelten auf dem Gerät, das verbindet.',
        )}
        actions={
          mode === 'on' && (
            <button
              type="button"
              className="quiet"
              onClick={() => setList([...list, { name: '', path: '' }])}
            >
              <Icon name="plus" size={15} />
              {t('Ordner hinzufügen')}
            </button>
          )
        }
      >
        <Segmented
          label={t('Laufwerke')}
          value={mode}
          options={[
            ...(inherit ? [{ value: 'group', label: t('Wie die Gruppe') }] : []),
            { value: 'off', label: t('Aus') },
            { value: 'on', label: t('An') },
          ]}
          onChange={(m) =>
            m === 'group'
              ? onChange(undefined)
              : m === 'off'
                ? inherit || drives
                  ? onChange({ ...(drives ?? {}), enabled: false, drives: list })
                  : onChange(undefined)
                : onChange({ ...(drives ?? {}), enabled: true, drives: list })
          }
        />
        {mode === 'on' &&
          list.map((drive, index) => (
            <RepeatRow key={index}>
              <input
                className="mono"
                aria-label={t('Name auf dem Server')}
                placeholder={t('Name')}
                value={str(drive.name)}
                onChange={(e) =>
                  setList(list.map((d, i) => (i === index ? { ...d, name: e.target.value } : d)))
                }
              />
              <input
                className="mono"
                aria-label={t('Pfad hier ({all} für alle Laufwerke)', { all: '*' })}
                placeholder={t('Pfad')}
                value={str(drive.path)}
                onChange={(e) =>
                  setList(list.map((d, i) => (i === index ? { ...d, path: e.target.value } : d)))
                }
              />
              <IconButton
                label={t('Entfernen')}
                icon="trash"
                onClick={() => setList(list.filter((_, i) => i !== index))}
              />
            </RepeatRow>
          ))}
      </FieldGroup>
    );
  };

  const gateway = obj(rdp.gateway);

  return (
    <>
      <Modal
        title={title}
        size="wide"
        onCancel={onClose}
        footer={
          <>
            <span className="spacer" />
            <button type="button" data-secondary onClick={onClose}>
              {t('Abbrechen')}
            </button>
            <button type="submit" form="suite-editor" className="primary" disabled={busy !== null}>
              {busy ?? t('Speichern')}
            </button>
          </>
        }
      >
        <form id="suite-editor" className="form" onSubmit={(e) => void submit(e)} noValidate>
          {conflict && (
            <Callout tone="warning" title={t('Woanders geändert')}>
              {t(
                'Dieser Eintrag wurde inzwischen auf einem anderen Gerät geändert und ist neu geladen. Deine Änderungen stehen noch hier; prüfe sie und speichere noch einmal, um sie darauf anzuwenden.',
              )}
            </Callout>
          )}
          {error && (
            <Callout tone="error" icon={null}>
              {error}
            </Callout>
          )}

          {kind === 'host' && (
            <>
              <FormRow>
                <TextField
                  label={t('Name')}
                  value={str(draft.name)}
                  onChange={(v) => set('name', v)}
                  autoFocus
                />
                {workspace}
              </FormRow>
              <FormRow min="narrow">
                <TextField
                  label={t('Adresse')}
                  value={str(draft.address)}
                  onChange={(v) => set('address', v.trim())}
                  mono
                  error={
                    tried && !str(draft.address).trim()
                      ? t('Bitte gib eine Adresse ein.')
                      : undefined
                  }
                />
                <NumberField
                  label={t('Port')}
                  value={draft.port ?? DEFAULT_PORT[space]}
                  onChange={(v) => set('port', v)}
                />
              </FormRow>
              <FormRow>
                <Field label={t('Gruppe')}>
                  <Select
                    value={ref(draft.group_id) ?? NONE}
                    options={options('group', t('Keine Gruppe'))}
                    onChange={(v) => set('group_id', v || null)}
                  />
                </Field>
                <Field
                  label={t('Identität')}
                  hint={space === 'rdp' ? t('Ohne eigene gilt die der Gruppe.') : undefined}
                >
                  <Select
                    value={ref(draft.identity_id) ?? NONE}
                    options={options(
                      'identity',
                      space === 'rdp' ? t('Wie die Gruppe') : t('Keine'),
                    )}
                    onChange={(v) => set('identity_id', v || null)}
                  />
                </Field>
              </FormRow>
              {space === 'rdp' && (
                <>
                  <Field label={t('Kommentar')}>
                    <textarea
                      rows={2}
                      value={str(draft.comment)}
                      onChange={(e) => set('comment', e.target.value)}
                    />
                  </Field>
                  <FieldGroup title={t('Anzeige')}>
                    <Segmented
                      label={t('Größe')}
                      value={
                        str(rdp.display) === 'fixed' || str(rdp.display) === 'fullscreen'
                          ? str(rdp.display)
                          : 'fit'
                      }
                      options={[
                        { value: 'fit', label: t('An das Fenster anpassen') },
                        { value: 'fixed', label: t('Feste Größe') },
                        { value: 'fullscreen', label: t('Vollbild') },
                      ]}
                      onChange={(v) => setRdp('display', v)}
                    />
                    <FormRow min="narrow">
                      {str(rdp.display) === 'fixed' && (
                        <>
                          <NumberField
                            label={t('Breite')}
                            value={rdp.width}
                            onChange={(v) => setRdp('width', v)}
                          />
                          <NumberField
                            label={t('Höhe')}
                            value={rdp.height}
                            onChange={(v) => setRdp('height', v)}
                          />
                        </>
                      )}
                      <Field label={t('Farbtiefe')}>
                        <Select
                          value={String(num(rdp.colorDepth, 32))}
                          options={['15', '16', '24', '32'].map((b) => ({
                            value: b,
                            label: t('{bits} Bit', { bits: b }),
                          }))}
                          onChange={(v) => setRdp('colorDepth', Number(v))}
                        />
                      </Field>
                    </FormRow>
                    <div className="checks">
                      <Checkbox
                        label={t('Einpassen statt scrollen')}
                        checked={bool(rdp.smartSizing, true)}
                        onChange={(v) => setRdp('smartSizing', v)}
                      />
                      <Checkbox
                        label={t('Hintergrundbild')}
                        checked={bool(rdp.wallpaper, true)}
                        onChange={(v) => setRdp('wallpaper', v)}
                      />
                      <Checkbox
                        label={t('Grafik-Pipeline (RDPEGFX)')}
                        checked={bool(rdp.graphicsPipeline, true)}
                        onChange={(v) => setRdp('graphicsPipeline', v)}
                      />
                    </div>
                  </FieldGroup>
                  <FieldGroup title={t('Verbindung')}>
                    <Field label={t('Ton')}>
                      <Select
                        value={
                          ['local', 'remote', 'off'].includes(str(rdp.audio))
                            ? str(rdp.audio)
                            : 'local'
                        }
                        options={[
                          { value: 'local', label: t('Hier abspielen') },
                          { value: 'remote', label: t('Auf dem Server lassen') },
                          { value: 'off', label: t('Aus') },
                        ]}
                        onChange={(v) => setRdp('audio', v)}
                      />
                    </Field>
                    <div className="checks">
                      <Checkbox
                        label={t('Zwischenablage')}
                        checked={bool(rdp.clipboard, true)}
                        onChange={(v) => setRdp('clipboard', v)}
                      />
                      <Checkbox
                        label={t('Konsolensitzung (/admin)')}
                        checked={bool(rdp.admin)}
                        onChange={(v) => setRdp('admin', v)}
                      />
                      <Checkbox
                        label={t('Network Level Authentication')}
                        checked={bool(rdp.nla, true)}
                        onChange={(v) => setRdp('nla', v)}
                      />
                    </div>
                  </FieldGroup>
                  <FieldGroup title={t('Gateway')}>
                    <Checkbox
                      label={t('Über ein Remote-Desktop-Gateway verbinden')}
                      checked={gateway !== null}
                      onChange={(on) =>
                        setRdp(
                          'gateway',
                          on
                            ? { address: '', port: 443, useHostLogin: true, bypassLocal: false }
                            : undefined,
                        )
                      }
                    />
                    {gateway && (
                      <>
                        <FormRow min="narrow">
                          <TextField
                            label={t('Gateway-Adresse')}
                            value={str(gateway.address)}
                            mono
                            onChange={(v) => setRdp('gateway', { ...gateway, address: v.trim() })}
                          />
                          <NumberField
                            label={t('Port')}
                            value={gateway.port ?? 443}
                            onChange={(v) => setRdp('gateway', { ...gateway, port: v })}
                          />
                        </FormRow>
                        <div className="checks">
                          <Checkbox
                            label={t('Mit der Anmeldung des Hosts')}
                            checked={bool(gateway.useHostLogin)}
                            onChange={(v) => setRdp('gateway', { ...gateway, useHostLogin: v })}
                          />
                          <Checkbox
                            label={t('Gateway im lokalen Netz umgehen')}
                            checked={bool(gateway.bypassLocal)}
                            onChange={(v) => setRdp('gateway', { ...gateway, bypassLocal: v })}
                          />
                        </div>
                        {!bool(gateway.useHostLogin) && (
                          <Field label={t('Anmeldung am Gateway')}>
                            <Select
                              value={ref(draft.gateway_identity_id) ?? NONE}
                              options={options('identity', t('Keine'))}
                              onChange={(v) => set('gateway_identity_id', v || null)}
                            />
                          </Field>
                        )}
                      </>
                    )}
                  </FieldGroup>
                  {drivesEditor(rdp.drives, (v) => setRdp('drives', v), true)}
                </>
              )}
            </>
          )}

          {kind === 'group' && (
            <>
              <FormRow>
                <TextField
                  label={t('Name')}
                  value={str(draft.name)}
                  onChange={(v) => set('name', v)}
                  autoFocus
                />
                {workspace}
              </FormRow>
              {space === 'rdp' && (
                <>
                  <Field
                    label={t('Identität für alle Hosts')}
                    hint={t('Gilt für jeden Host der Gruppe ohne eigene.')}
                  >
                    <Select
                      value={ref(draft.identity_id) ?? NONE}
                      options={options('identity', t('Keine'))}
                      onChange={(v) =>
                        setDraft((d) => {
                          const next = { ...d };
                          if (v) next.identity_id = v;
                          else delete next.identity_id;
                          return next;
                        })
                      }
                    />
                  </Field>
                  {drivesEditor(
                    draft.drives,
                    (v) =>
                      setDraft((d) => {
                        const next = { ...d };
                        if (v === undefined) delete next.drives;
                        else next.drives = v;
                        return next;
                      }),
                    false,
                  )}
                </>
              )}
            </>
          )}

          {kind === 'identity' && (
            <>
              <FormRow>
                <TextField
                  label={t('Name')}
                  value={str(draft.label)}
                  onChange={(v) => set('label', v)}
                  autoFocus
                />
                <TextField
                  label={t('Benutzername')}
                  value={str(draft.username)}
                  onChange={(v) => set('username', v)}
                  mono
                  autoComplete="off"
                />
                {space === 'rdp' && (
                  <TextField
                    label={t('Domäne')}
                    value={str(draft.domain)}
                    onChange={(v) => set('domain', v)}
                    mono
                    hint={t('Leer für ein lokales Konto.')}
                  />
                )}
              </FormRow>
              <FormRow>
                <Field label={t('Anmeldung mit')}>
                  <Select
                    value={str(draft.auth_type) || 'password'}
                    options={[
                      ...AUTH_TYPES.map((a) => ({ value: a as string, label: authLabel(a) })),
                      ...(AUTH_TYPES.includes(
                        str(draft.auth_type) as (typeof AUTH_TYPES)[number],
                      ) || !str(draft.auth_type)
                        ? []
                        : [{ value: str(draft.auth_type), label: str(draft.auth_type) }]),
                    ]}
                    onChange={(v) => set('auth_type', v)}
                  />
                </Field>
                {space === 'ssh' && (
                  <Field label={t('Schlüssel')}>
                    <Select
                      value={ref(draft.key_id) ?? NONE}
                      options={options('key', t('Keiner'))}
                      onChange={(v) => set('key_id', v || null)}
                    />
                  </Field>
                )}
              </FormRow>
              {password === null ? (
                <Field
                  label={t('Passwort')}
                  hint={
                    ref(opened.password_secret_id)
                      ? t('Gespeichert. Ändern setzt ein neues.')
                      : t('Keins gespeichert.')
                  }
                >
                  <button type="button" onClick={() => setPassword('')}>
                    {ref(opened.password_secret_id)
                      ? t('Passwort ändern')
                      : t('Passwort festlegen')}
                  </button>
                </Field>
              ) : (
                <Field
                  label={
                    record && ref(opened.password_secret_id) ? t('Neues Passwort') : t('Passwort')
                  }
                  hint={t('Leer lassen, um nichts zu ändern.')}
                  tools={
                    <IconButton
                      label={t('Passwort erzeugen')}
                      icon="dice"
                      onClick={() => setGenerator(true)}
                    />
                  }
                >
                  <PasswordInput
                    value={password}
                    onChange={setPassword}
                    autoComplete="new-password"
                  />
                </Field>
              )}
            </>
          )}

          {kind === 'key' && (
            <>
              <TextField
                label={t('Name')}
                value={str(draft.label)}
                onChange={(v) => set('label', v)}
                autoFocus
              />
              {record ? (
                <p className="form-note">
                  {t(
                    'Der Schlüssel selbst bleibt, wie er ist. Für einen anderen lege einen neuen Schlüssel an.',
                  )}
                </p>
              ) : (
                <>
                  <Segmented
                    label={t('Schlüssel')}
                    value={keyMode}
                    options={[
                      { value: 'generate', label: t('Neu erzeugen (Ed25519)') },
                      { value: 'import', label: t('Vorhandenen einfügen') },
                    ]}
                    onChange={setKeyMode}
                  />
                  {keyMode === 'generate' ? (
                    <TextField
                      label={t('Kommentar')}
                      value={comment}
                      onChange={setComment}
                      mono
                      hint={t('Steht am Ende des öffentlichen Schlüssels, oft name@rechner.')}
                    />
                  ) : (
                    <>
                      <Field
                        label={t('Privater Schlüssel')}
                        hint={t('OpenSSH, PEM oder PuTTY; wird unverändert gespeichert.')}
                      >
                        <textarea
                          className="mono"
                          rows={6}
                          spellCheck={false}
                          value={privateText}
                          onChange={(e) => setPrivateText(e.target.value)}
                        />
                      </Field>
                      <label className="button-link suite-file">
                        <input
                          type="file"
                          className="sr-only"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file && file.size < 64 * 1024)
                              void file.text().then(setPrivateText);
                            else if (file)
                              toast(t('Diese Datei ist zu groß für einen Schlüssel.'), 'error');
                          }}
                        />
                        {t('Aus einer Datei laden …')}
                      </label>
                      <TextField
                        label={t('Öffentlicher Schlüssel')}
                        value={str(draft.public_key)}
                        onChange={(v) => set('public_key', v)}
                        mono
                        hint={t(
                          'Bei OpenSSH-Schlüsseln nicht nötig: er wird aus dem privaten gelesen.',
                        )}
                      />
                    </>
                  )}
                  <Field
                    label={t('Passphrase')}
                    hint={
                      keyMode === 'generate'
                        ? t('Optional. Verschlüsselt den privaten Schlüssel wie ssh-keygen.')
                        : t('Nur wenn der Schlüssel eine hat.')
                    }
                  >
                    <PasswordInput
                      value={passphrase}
                      onChange={setPassphrase}
                      autoComplete="new-password"
                    />
                  </Field>
                </>
              )}
            </>
          )}

          {kind === 'snippet' && (
            <>
              <FormRow>
                <TextField
                  label={t('Name')}
                  value={str(draft.label)}
                  onChange={(v) => set('label', v)}
                  autoFocus
                />
                <TextField
                  label={t('Ordner')}
                  value={str(draft.group_path)}
                  onChange={(v) => set('group_path', v || null)}
                />
              </FormRow>
              <Field label={t('Befehl')}>
                <textarea
                  className="mono"
                  rows={6}
                  spellCheck={false}
                  value={str(draft.body)}
                  onChange={(e) => set('body', e.target.value)}
                />
              </Field>
            </>
          )}

          {kind === 'port_forward' && (
            <>
              <FormRow>
                <TextField
                  label={t('Name')}
                  value={str(draft.name)}
                  onChange={(v) => set('name', v)}
                  autoFocus
                />
                <Field label={t('Host')}>
                  <Select
                    value={ref(draft.host_id) ?? NONE}
                    options={options('host', t('Bitte wählen'))}
                    onChange={(v) => set('host_id', v || null)}
                  />
                </Field>
              </FormRow>
              <Segmented
                label={t('Art')}
                value={
                  str(draft.kind) === 'remote'
                    ? 'remote'
                    : str(draft.kind) === 'local'
                      ? 'local'
                      : str(draft.kind)
                }
                options={[
                  { value: 'local', label: t('Lokal (-L)') },
                  { value: 'remote', label: t('Entfernt (-R)') },
                  ...(['local', 'remote'].includes(str(draft.kind))
                    ? []
                    : [{ value: str(draft.kind), label: str(draft.kind) }]),
                ]}
                onChange={(v) => set('kind', v)}
              />
              <FormRow min="narrow">
                <TextField
                  label={
                    str(draft.kind) === 'remote'
                      ? t('Lauscht auf dem Server')
                      : t('Lauscht auf diesem Computer')
                  }
                  value={str(draft.bind_address)}
                  onChange={(v) => set('bind_address', v.trim())}
                  mono
                />
                <NumberField
                  label={t('Port')}
                  value={draft.bind_port}
                  onChange={(v) => set('bind_port', v)}
                />
              </FormRow>
              <FormRow min="narrow">
                <TextField
                  label={t('Führt zu')}
                  value={str(draft.target_host)}
                  onChange={(v) => set('target_host', v.trim())}
                  mono
                />
                <NumberField
                  label={t('Port')}
                  value={draft.target_port}
                  onChange={(v) => set('target_port', v)}
                />
              </FormRow>
              <Checkbox
                label={t('Startet mit dem Terminal zu diesem Host')}
                checked={bool(draft.autostart)}
                onChange={(v) => set('autostart', v)}
              />
            </>
          )}
        </form>
      </Modal>
      {generator && (
        <GeneratorDialog
          onClose={() => setGenerator(false)}
          onUse={(generated) => {
            setPassword(generated);
            setGenerator(false);
          }}
        />
      )}
    </>
  );
}
