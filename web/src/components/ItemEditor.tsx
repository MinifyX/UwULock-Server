import { Fragment, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  revealField,
  saveItem,
  vaultItem,
  type Draft,
  type FieldKind,
  type ItemDetail as Detail,
  type ItemKind,
  type ItemSummary,
  type Overview,
} from '../lib/api';
import { useFeature } from '../lib/branding';
import { errorText, maskedErrorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import {
  CARD_BRANDS,
  FIELD_KIND_LABEL,
  IDENTITY_FIELDS,
  IDENTITY_LABEL,
  KIND_LABEL,
  MATCH_LABEL,
  SECURITY_LABEL,
} from '../lib/items';
import {
  forDomainOf,
  reloadMaskedLinks,
  updateMasked,
  useMaskedLinks,
  useUsableMasked,
  type MaskedAddress,
} from '../lib/masked';
import { toast } from '../lib/toast';
import {
  EAP_METHODS,
  isEnterprise,
  PHASE2_METHODS,
  readWifi,
  SECURITIES,
  wifiFields,
  type WifiView,
} from '../lib/wifi';
import { useCloseGuard } from './CloseGuard';
import { GeneratorDialog } from './GeneratorDialog';
import { Modal } from './Modal';
import { Button, Callout, Checkbox, Field, FieldGroup, FormRow, IconButton, RepeatRow } from './ui';
import { NewMaskedDialog } from './web/MaskedSettings';

/**
 * A value the editor may not have: a password, a card number, a hidden field.
 * `keep` means the item's own value stays — the editor never saw it, and it
 * never goes through the window unless someone asks to see it.
 */
type Sec = { mode: 'keep' | 'value'; value: string; had?: boolean };

// `had`: the item has a value here, so an empty field empties it (and says so).
const keep = (has: boolean): Sec =>
  has ? { mode: 'keep', value: '', had: true } : { mode: 'value', value: '' };
const sent = (secret: Sec): string | null => (secret.mode === 'keep' ? null : secret.value);

type UriRow = { key: number; uri: string; match: number | null };
type FieldRow = {
  key: number;
  name: string;
  kind: FieldKind;
  value: Sec;
  /** Which field of the item this row was, for the value and the link. */
  from: number | null;
};

/** A Wi-Fi network's own fields; the editor's other fields are the item's other ones. */
type WifiForm = {
  ssid: string;
  password: Sec;
  security: string;
  hidden: boolean;
  eap: string;
  phase2: string;
  identity: string;
  anonymous: string;
  ca: string;
  from: WifiView['from'];
};

type Form = {
  name: string;
  folderId: string;
  favorite: boolean;
  reprompt: boolean;
  notes: string;
  username: string;
  password: Sec;
  totp: Sec;
  uris: UriRow[];
  cardholderName: string;
  brand: string;
  number: Sec;
  expMonth: string;
  expYear: string;
  code: Sec;
  identity: Record<string, string>;
  identitySecrets: Record<string, Sec>;
  privateKey: Sec;
  publicKey: string;
  fingerprint: string;
  fields: FieldRow[];
  wifi: WifiForm;
};

function emptyForm(kind: ItemKind): Form {
  return {
    name: '',
    folderId: '',
    favorite: false,
    reprompt: false,
    notes: '',
    username: '',
    password: keep(false),
    totp: keep(false),
    uris: kind === 'login' ? [{ key: 1, uri: '', match: null }] : [],
    cardholderName: '',
    brand: '',
    number: keep(false),
    expMonth: '',
    expYear: '',
    code: keep(false),
    identity: {},
    identitySecrets: {},
    privateKey: keep(false),
    publicKey: '',
    fingerprint: '',
    fields: [],
    wifi: {
      ssid: '',
      password: keep(false),
      security: 'WPA2',
      hidden: false,
      eap: 'PEAP',
      phase2: 'MSCHAPV2',
      identity: '',
      anonymous: '',
      ca: '',
      from: {},
    },
  };
}

function fieldRow(field: NonNullable<Detail['fields']>[number]): FieldRow {
  return {
    key: field.index + 1,
    name: field.name ?? '',
    kind: field.kind,
    value:
      field.kind === 'hidden' ? keep(field.hasValue) : { mode: 'value', value: field.value ?? '' },
    from: field.index,
  };
}

/** The item as it is now, as far as the page is allowed to know it. */
function formOf(summary: ItemSummary, detail: Detail): Form {
  const form = emptyForm(summary.kind);
  form.name = summary.name;
  form.folderId = summary.folderId ?? '';
  form.favorite = summary.favorite;
  form.reprompt = summary.reprompt;
  form.notes = detail.notes ?? '';
  if (detail.login) {
    form.username = detail.login.username ?? '';
    form.password = keep(detail.login.hasPassword);
    form.totp = keep(detail.login.hasTotp);
    form.uris = detail.login.uris.map((uri, index) => ({
      key: index + 1,
      uri: uri.uri,
      match: uri.match,
    }));
  }
  if (detail.card) {
    form.cardholderName = detail.card.cardholderName ?? '';
    form.brand = detail.card.brand ?? '';
    form.number = keep(Boolean(detail.card.numberEnding));
    form.expMonth = detail.card.expMonth ?? '';
    form.expYear = detail.card.expYear ?? '';
    form.code = keep(detail.card.hasCode);
  }
  for (const field of IDENTITY_FIELDS) {
    const entry = detail.identity?.find((e) => e.name === field.name);
    if (field.sensitive) form.identitySecrets[field.name] = keep(Boolean(entry));
    else form.identity[field.name] = entry?.value ?? '';
  }
  if (detail.sshKey) {
    form.privateKey = keep(detail.sshKey.hasPrivateKey);
    form.publicKey = detail.sshKey.publicKey ?? '';
    form.fingerprint = detail.sshKey.fingerprint ?? '';
  }
  if (summary.kind === 'wifi') {
    const wifi = readWifi(detail.fields ?? []);
    const password = wifi.password;
    form.wifi = {
      ssid: wifi.ssid,
      password: !password
        ? keep(false)
        : password.kind === 'hidden'
          ? keep(password.hasValue)
          : { mode: 'value', value: password.value ?? '' },
      security: wifi.security || 'WPA2',
      hidden: wifi.hidden,
      // An Enterprise network without a method gets the usual one shown, and saved.
      eap: wifi.eap || (isEnterprise(wifi.security) ? '' : 'PEAP'),
      phase2: wifi.phase2 || (isEnterprise(wifi.security) ? '' : 'MSCHAPV2'),
      identity: wifi.identity,
      anonymous: wifi.anonymous,
      ca: wifi.ca,
      from: wifi.from,
    };
    form.fields = wifi.others.map(fieldRow);
    return form;
  }
  form.fields = (detail.fields ?? []).map(fieldRow);
  return form;
}

function draftOf(form: Form, kind: ItemKind): Draft {
  const draft: Draft = {
    // A Wi-Fi network is a secure note to the vault.
    kind: kind === 'wifi' ? 'note' : kind,
    name: form.name.trim(),
    notes: form.notes,
    favorite: form.favorite,
    reprompt: form.reprompt,
    folderId: form.folderId || null,
    fields: form.fields.map((field) => ({
      name: field.name.trim() || null,
      kind: field.kind,
      value: field.kind === 'linked' ? null : sent(field.value),
      from: field.from,
    })),
  };
  if (kind === 'login') {
    draft.login = {
      username: form.username,
      password: sent(form.password),
      totp: sent(form.totp),
      uris: form.uris
        .filter((uri) => uri.uri.trim())
        .map((uri) => ({ uri: uri.uri.trim(), match: uri.match })),
    };
  }
  if (kind === 'card') {
    draft.card = {
      cardholderName: form.cardholderName,
      brand: form.brand,
      number: sent(form.number),
      expMonth: form.expMonth,
      expYear: form.expYear,
      code: sent(form.code),
    };
  }
  if (kind === 'identity') {
    const values: Record<string, string> = {};
    for (const field of IDENTITY_FIELDS) {
      if (field.sensitive) {
        const secret = form.identitySecrets[field.name];
        if (secret && secret.mode === 'value') values[field.name] = secret.value;
      } else {
        values[field.name] = form.identity[field.name] ?? '';
      }
    }
    draft.identity = values;
  }
  if (kind === 'wifi') {
    const wifi = form.wifi;
    draft.fields = wifiFields(
      {
        ssid: wifi.ssid.trim(),
        password: sent(wifi.password),
        security: wifi.security,
        hidden: wifi.hidden,
        eap: wifi.eap,
        phase2: wifi.phase2,
        identity: wifi.identity,
        anonymous: wifi.anonymous,
        ca: wifi.ca,
        from: wifi.from,
      },
      draft.fields,
    );
  }
  if (kind === 'ssh-key') {
    draft.sshKey = {
      privateKey: sent(form.privateKey),
      publicKey: form.publicKey,
      fingerprint: form.fingerprint,
    };
  }
  return draft;
}

/**
 * A field for a value the editor may not have. It shows dots until someone
 * asks to see it; typing replaces it, the cross empties it, and an empty field
 * that was never touched leaves the item's value alone. Its tools (the eye,
 * the dice, the way back) sit inside the field.
 */
function SecretField({
  label,
  secret,
  onChange,
  itemId,
  field,
  multiline,
  hint,
  hideLabel,
  children,
}: {
  label: string;
  secret: Sec;
  onChange: (next: Sec) => void;
  /** Where to fetch the value from, for the eye. */
  itemId?: string | null;
  field?: string;
  multiline?: boolean;
  hint?: string;
  /** In a row of a list, where the row names the field. */
  hideLabel?: boolean;
  children?: ReactNode;
}) {
  useLanguage();
  const kept = secret.mode === 'keep';
  const cleared = secret.mode === 'value' && secret.value === '' && Boolean(secret.had);

  const reveal = async () => {
    if (!itemId || !field) return;
    try {
      onChange({ ...secret, mode: 'value', value: await revealField(itemId, field) });
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const type = (value: string) => {
    // Deleting what was typed goes back to leaving the value alone.
    if (value === '' && kept) return;
    onChange({ ...secret, mode: 'value', value });
  };

  const tools = [
    kept && itemId && field && (
      <IconButton
        key="reveal"
        icon="eye"
        label={t('{label} zeigen', { label })}
        title={t('Zeigen')}
        onClick={() => void reveal()}
      />
    ),
    children && <Fragment key="more">{children}</Fragment>,
    !kept && itemId && field && (
      <IconButton
        key="keep"
        icon="history"
        label={t('{label} unverändert lassen', { label })}
        title={t('Unverändert lassen')}
        onClick={() => onChange(keep(true))}
      />
    ),
  ];

  return (
    <Field
      label={label}
      hideLabel={hideLabel}
      tools={tools}
      hint={kept ? t('Bleibt, wie es ist.') : cleared ? t('Wird beim Speichern geleert.') : hint}
      hintTone={cleared ? 'warn' : 'default'}
    >
      {multiline ? (
        <textarea
          className="mono"
          rows={4}
          value={secret.value}
          placeholder={kept ? '••••••••••••' : undefined}
          spellCheck={false}
          onChange={(e) => type(e.target.value)}
        />
      ) : (
        <input
          type="text"
          className="mono"
          value={secret.value}
          placeholder={kept ? '••••••••••••' : undefined}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => type(e.target.value)}
        />
      )}
    </Field>
  );
}

type Props = {
  /** The item to change, or `null` with a kind for a new one. */
  summary: ItemSummary | null;
  kind: ItemKind;
  overview: Overview | null;
  onClose: () => void;
  onSaved: (id: string) => void;
};

export function ItemEditor({ summary, kind, overview, onClose, onSaved }: Props) {
  useLanguage();
  const [form, setForm] = useState<Form>(() => emptyForm(kind));
  const [initial, setInitial] = useState<string>(() => JSON.stringify(emptyForm(kind)));
  const [loading, setLoading] = useState(Boolean(summary));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Behind the master password re-prompt: nothing to edit, and nothing to save over it.
  const [locked, setLocked] = useState(false);
  const [generator, setGenerator] = useState<null | 'password' | 'wifi'>(null);
  const [nextKey, setNextKey] = useState(1000);
  const id = summary?.id ?? null;
  // A masked address as the username, when UwUMail is connected.
  const maskedOn = useFeature('masked-addresses');
  const masked = useUsableMasked(maskedOn && kind === 'login');
  const linked = useMaskedLinks(maskedOn && kind === 'login' && Boolean(id))[id ?? ''];
  const [maskedDialog, setMaskedDialog] = useState(false);
  /** An address made for this new item: linked to it once it is saved and has an id. */
  const [pendingLink, setPendingLink] = useState<string | null>(null);

  useEffect(() => {
    if (!summary) return;
    let stopped = false;
    vaultItem(summary.id)
      .then((detail) => {
        if (stopped) return;
        if (detail.locked) {
          setError(t('Dieser Eintrag fragt zuerst nach deinem Master-Passwort.'));
          setLocked(true);
          return;
        }
        const next = formOf(summary, detail);
        setForm(next);
        setInitial(JSON.stringify(next));
      })
      .catch((e) => !stopped && setError(errorText(e)))
      .finally(() => !stopped && setLoading(false));
    return () => {
      stopped = true;
    };
  }, [summary]);

  const set = (patch: Partial<Form>) => setForm((current) => ({ ...current, ...patch }));
  const setWifi = (patch: Partial<WifiForm>) =>
    setForm((current) => ({ ...current, wifi: { ...current.wifi, ...patch } }));
  /** The SSID, and the name with it as long as the name was the SSID (or empty). */
  const setSsid = (ssid: string) =>
    setForm((current) => ({
      ...current,
      name: !current.name.trim() || current.name === current.wifi.ssid ? ssid : current.name,
      wifi: { ...current.wifi, ssid },
    }));
  const dirty = useMemo(() => JSON.stringify(form) !== initial, [form, initial]);
  const guard = useCloseGuard(dirty && !busy, onClose);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!form.name.trim()) {
      setError(t('Ohne Namen findest du den Eintrag später nicht wieder.'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const saved = await saveItem(id, draftOf(form, kind));
      if (pendingLink && !id) {
        // The item is saved either way; the address just would not know it.
        await updateMasked(pendingLink, { cipherId: saved }).then(
          () => void reloadMaskedLinks(),
          (e) => toast(maskedErrorText(e), 'error'),
        );
        setPendingLink(null);
      }
      setInitial(JSON.stringify(form));
      toast(id ? t('Gespeichert ✧') : t('Angelegt ✧'));
      onSaved(saved);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const key = () => {
    setNextKey((n) => n + 1);
    return nextKey;
  };

  const folders = [...(overview?.folders ?? [])].sort((a, b) => a.name.localeCompare(b.name));

  return (
    <>
      <Modal
        title={
          id
            ? t('{kind} bearbeiten', { kind: t(KIND_LABEL[kind]) })
            : t('Neu: {kind}', { kind: t(KIND_LABEL[kind]) })
        }
        size="wide"
        onCancel={guard.request}
        footer={
          <>
            <span className="spacer" />
            <Button data-secondary onClick={guard.request}>
              {t('Abbrechen')}
            </Button>
            <Button
              type="submit"
              form="item-editor"
              variant="primary"
              disabled={busy || loading || locked || !form.name.trim()}
            >
              {busy ? t('Speichert …') : t('Speichern')}
            </Button>
          </>
        }
      >
        {loading ? (
          <p className="dialog-lead">{t('Einen Moment …')}</p>
        ) : (
          <form id="item-editor" className="editor" onSubmit={save}>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}

            <FormRow>
              <Field label={t('Name')}>
                <input
                  type="text"
                  value={form.name}
                  autoFocus
                  maxLength={200}
                  onChange={(e) => set({ name: e.target.value })}
                />
              </Field>
              <Field label={t('Ordner')}>
                <select
                  value={form.folderId}
                  onChange={(e) => set({ folderId: e.target.value })}
                  disabled={Boolean(summary?.organizationId)}
                >
                  <option value="">{t('Ohne Ordner')}</option>
                  {folders.map((folder) => (
                    <option key={folder.id} value={folder.id}>
                      {folder.name}
                    </option>
                  ))}
                </select>
              </Field>
            </FormRow>

            {kind === 'login' && (
              <>
                <Field
                  label={t('Benutzername')}
                  tools={
                    masked && (
                      <IconButton
                        icon="sparkles"
                        label={t('Maskierte Adresse anlegen')}
                        onClick={() => setMaskedDialog(true)}
                        aria-haspopup="dialog"
                      />
                    )
                  }
                >
                  <input
                    type="text"
                    value={form.username}
                    autoComplete="off"
                    onChange={(e) => set({ username: e.target.value })}
                  />
                </Field>
                <SecretField
                  label={t('Passwort')}
                  secret={form.password}
                  onChange={(password) => set({ password })}
                  itemId={id}
                  field="password"
                >
                  <IconButton
                    icon="dice"
                    label={t('Passwort-Generator')}
                    onClick={() => setGenerator('password')}
                  />
                </SecretField>
                <SecretField
                  label={t('Einmal-Code (TOTP)')}
                  secret={form.totp}
                  onChange={(totp) => set({ totp })}
                  itemId={id}
                  field="totp"
                  hint={t('Der Schlüssel aus der App: Base32 oder eine otpauth://-Adresse.')}
                />

                <FieldGroup
                  title={t('Websites')}
                  actions={
                    <Button
                      variant="quiet"
                      icon="plus"
                      onClick={() =>
                        set({
                          uris: [...form.uris, { key: key(), uri: '', match: null }],
                        })
                      }
                    >
                      {t('Website hinzufügen')}
                    </Button>
                  }
                >
                  {form.uris.map((uri, index) => (
                    <RepeatRow key={uri.key} aux="narrow">
                      <input
                        type="text"
                        value={uri.uri}
                        spellCheck={false}
                        placeholder="https://…"
                        aria-label={t('Adresse {n}', { n: index + 1 })}
                        onChange={(e) =>
                          set({
                            uris: form.uris.map((row) =>
                              row.key === uri.key ? { ...row, uri: e.target.value } : row,
                            ),
                          })
                        }
                      />
                      <select
                        value={uri.match ?? ''}
                        aria-label={t('Wann diese Adresse passt')}
                        onChange={(e) =>
                          set({
                            uris: form.uris.map((row) =>
                              row.key === uri.key
                                ? {
                                    ...row,
                                    match: e.target.value === '' ? null : Number(e.target.value),
                                  }
                                : row,
                            ),
                          })
                        }
                      >
                        <option value="">{t('Standard')}</option>
                        {Object.entries(MATCH_LABEL).map(([value, label]) => (
                          <option key={value} value={value}>
                            {t(label)}
                          </option>
                        ))}
                      </select>
                      <IconButton
                        icon="trash"
                        label={t('Adresse {n} entfernen', { n: index + 1 })}
                        title={t('Entfernen')}
                        onClick={() =>
                          set({
                            uris: form.uris.filter((row) => row.key !== uri.key),
                          })
                        }
                      />
                    </RepeatRow>
                  ))}
                </FieldGroup>
              </>
            )}

            {kind === 'card' && (
              <>
                <FormRow>
                  <Field label={t('Karteninhaber')}>
                    <input
                      type="text"
                      value={form.cardholderName}
                      onChange={(e) => set({ cardholderName: e.target.value })}
                    />
                  </Field>
                  <Field label={t('Marke')}>
                    <select value={form.brand} onChange={(e) => set({ brand: e.target.value })}>
                      <option value="">{t('Keine Angabe')}</option>
                      {CARD_BRANDS.map((brand) => (
                        <option key={brand} value={brand}>
                          {brand}
                        </option>
                      ))}
                      {form.brand && !CARD_BRANDS.includes(form.brand) && (
                        <option value={form.brand}>{form.brand}</option>
                      )}
                    </select>
                  </Field>
                </FormRow>
                <SecretField
                  label={t('Kartennummer')}
                  secret={form.number}
                  onChange={(number) => set({ number })}
                  itemId={id}
                  field="card-number"
                />
                <FormRow min="narrow">
                  <Field label={t('Gültig bis (Monat)')}>
                    <select
                      value={form.expMonth}
                      onChange={(e) => set({ expMonth: e.target.value })}
                    >
                      <option value="">—</option>
                      {Array.from({ length: 12 }, (_, i) => String(i + 1)).map((month) => (
                        <option key={month} value={month}>
                          {month.padStart(2, '0')}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label={t('Gültig bis (Jahr)')}>
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={4}
                      value={form.expYear}
                      onChange={(e) => set({ expYear: e.target.value.replace(/\D/g, '') })}
                    />
                  </Field>
                  <SecretField
                    label={t('Prüfnummer')}
                    secret={form.code}
                    onChange={(code) => set({ code })}
                    itemId={id}
                    field="card-code"
                  />
                </FormRow>
              </>
            )}

            {kind === 'identity' && (
              <FormRow>
                {IDENTITY_FIELDS.map((field) =>
                  field.sensitive ? (
                    <SecretField
                      key={field.name}
                      label={t(IDENTITY_LABEL[field.name] ?? field.name)}
                      secret={form.identitySecrets[field.name] ?? keep(false)}
                      onChange={(value) =>
                        set({
                          identitySecrets: {
                            ...form.identitySecrets,
                            [field.name]: value,
                          },
                        })
                      }
                      itemId={id}
                      field={`identity:${field.name}`}
                    />
                  ) : (
                    <Field key={field.name} label={t(IDENTITY_LABEL[field.name] ?? field.name)}>
                      <input
                        type="text"
                        value={form.identity[field.name] ?? ''}
                        onChange={(e) =>
                          set({
                            identity: {
                              ...form.identity,
                              [field.name]: e.target.value,
                            },
                          })
                        }
                      />
                    </Field>
                  ),
                )}
              </FormRow>
            )}

            {kind === 'ssh-key' && (
              <>
                <Callout>
                  {t(
                    'Ein SSH-Schlüssel braucht alle drei Teile – privater Schlüssel, öffentlicher Schlüssel und Fingerprint. Der Server wirft den Eintrag sonst weg.',
                  )}
                </Callout>
                <SecretField
                  label={t('Privater Schlüssel')}
                  secret={form.privateKey}
                  onChange={(privateKey) => set({ privateKey })}
                  itemId={id}
                  field="ssh-private"
                  multiline
                />
                <Field label={t('Öffentlicher Schlüssel')}>
                  <input
                    type="text"
                    className="mono"
                    value={form.publicKey}
                    spellCheck={false}
                    onChange={(e) => set({ publicKey: e.target.value })}
                  />
                </Field>
                <Field
                  label={t('Fingerprint')}
                  hint={t('Zum Beispiel aus „ssh-keygen -lf schluessel.pub“.')}
                >
                  <input
                    type="text"
                    className="mono"
                    value={form.fingerprint}
                    spellCheck={false}
                    onChange={(e) => set({ fingerprint: e.target.value })}
                  />
                </Field>
              </>
            )}

            {kind === 'wifi' && (
              <>
                <FormRow>
                  <Field label={t('Netzwerkname (SSID)')}>
                    <input
                      type="text"
                      value={form.wifi.ssid}
                      spellCheck={false}
                      autoComplete="off"
                      maxLength={64}
                      onChange={(e) => setSsid(e.target.value)}
                    />
                  </Field>
                  <Field label={t('Sicherheit')}>
                    <select
                      value={form.wifi.security}
                      onChange={(e) => setWifi({ security: e.target.value })}
                    >
                      {SECURITIES.map((security) => (
                        <option key={security} value={security}>
                          {t(SECURITY_LABEL[security] ?? security)}
                        </option>
                      ))}
                      {!(SECURITIES as readonly string[]).includes(form.wifi.security) && (
                        <option value={form.wifi.security}>{form.wifi.security}</option>
                      )}
                    </select>
                  </Field>
                </FormRow>
                {form.wifi.security !== 'None' && (
                  <SecretField
                    label={t('WLAN-Passwort')}
                    secret={form.wifi.password}
                    onChange={(password) => setWifi({ password })}
                    itemId={form.wifi.from.password === undefined ? null : id}
                    field={
                      form.wifi.from.password === undefined
                        ? undefined
                        : `field:${form.wifi.from.password}`
                    }
                  >
                    <IconButton
                      icon="dice"
                      label={t('Passwort-Generator')}
                      onClick={() => setGenerator('wifi')}
                    />
                  </SecretField>
                )}
                <div className="checks">
                  <Checkbox
                    label={t('Verstecktes Netzwerk (sendet seinen Namen nicht)')}
                    checked={form.wifi.hidden}
                    onChange={(hidden) => setWifi({ hidden })}
                  />
                </div>
                {isEnterprise(form.wifi.security) && (
                  <FieldGroup title={t('Enterprise (802.1X)')}>
                    <FormRow>
                      <Field label={t('EAP-Methode')}>
                        <select
                          value={form.wifi.eap}
                          onChange={(e) => setWifi({ eap: e.target.value })}
                        >
                          <option value="">{t('Keine Angabe')}</option>
                          {EAP_METHODS.map((method) => (
                            <option key={method} value={method}>
                              {method}
                            </option>
                          ))}
                          {form.wifi.eap &&
                            !(EAP_METHODS as readonly string[]).includes(form.wifi.eap) && (
                              <option value={form.wifi.eap}>{form.wifi.eap}</option>
                            )}
                        </select>
                      </Field>
                      <Field label={t('Phase 2')}>
                        <select
                          value={form.wifi.phase2}
                          onChange={(e) => setWifi({ phase2: e.target.value })}
                        >
                          <option value="">{t('Keine Angabe')}</option>
                          {PHASE2_METHODS.map((method) => (
                            <option key={method} value={method}>
                              {method === 'none' ? t('Keine') : method}
                            </option>
                          ))}
                          {form.wifi.phase2 &&
                            !(PHASE2_METHODS as readonly string[]).includes(form.wifi.phase2) && (
                              <option value={form.wifi.phase2}>{form.wifi.phase2}</option>
                            )}
                        </select>
                      </Field>
                    </FormRow>
                    <FormRow>
                      <Field label={t('Identität')}>
                        <input
                          type="text"
                          value={form.wifi.identity}
                          spellCheck={false}
                          autoComplete="off"
                          onChange={(e) => setWifi({ identity: e.target.value })}
                        />
                      </Field>
                      <Field label={t('Anonyme Identität')}>
                        <input
                          type="text"
                          value={form.wifi.anonymous}
                          spellCheck={false}
                          autoComplete="off"
                          onChange={(e) => setWifi({ anonymous: e.target.value })}
                        />
                      </Field>
                    </FormRow>
                    <Field
                      label={t('CA-Zertifikat')}
                      hint={t('Die Domain des Servers oder ein Hinweis, welches Zertifikat gilt.')}
                    >
                      <input
                        type="text"
                        value={form.wifi.ca}
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(e) => setWifi({ ca: e.target.value })}
                      />
                    </Field>
                  </FieldGroup>
                )}
              </>
            )}

            <Field label={t('Notizen')}>
              <textarea
                rows={kind === 'note' ? 8 : 3}
                spellCheck={false}
                value={form.notes}
                onChange={(e) => set({ notes: e.target.value })}
              />
            </Field>

            <FieldGroup
              title={t('Eigene Felder')}
              actions={(['text', 'hidden', 'boolean'] as FieldKind[]).map((fieldKind) => (
                <Button
                  key={fieldKind}
                  variant="quiet"
                  icon="plus"
                  onClick={() =>
                    set({
                      fields: [
                        ...form.fields,
                        {
                          key: key(),
                          name: '',
                          kind: fieldKind,
                          value: {
                            mode: 'value',
                            value: fieldKind === 'boolean' ? 'false' : '',
                          },
                          from: null,
                        },
                      ],
                    })
                  }
                >
                  {t(FIELD_KIND_LABEL[fieldKind])}
                </Button>
              ))}
            >
              {form.fields.map((field, index) => (
                <RepeatRow key={field.key}>
                  <input
                    type="text"
                    value={field.name}
                    placeholder={t('Feldname')}
                    aria-label={t('Name von Feld {n}', { n: index + 1 })}
                    onChange={(e) =>
                      set({
                        fields: form.fields.map((row) =>
                          row.key === field.key ? { ...row, name: e.target.value } : row,
                        ),
                      })
                    }
                  />
                  {field.kind === 'linked' ? (
                    <span className="muted linked-note">
                      {t('verknüpft mit einem anderen Feld')}
                    </span>
                  ) : field.kind === 'boolean' ? (
                    <Checkbox
                      label={field.value.value === 'true' ? t('Ja') : t('Nein')}
                      checked={field.value.value === 'true'}
                      onChange={(checked) =>
                        set({
                          fields: form.fields.map((row) =>
                            row.key === field.key
                              ? {
                                  ...row,
                                  value: { mode: 'value', value: checked ? 'true' : 'false' },
                                }
                              : row,
                          ),
                        })
                      }
                    />
                  ) : field.kind === 'hidden' ? (
                    <SecretField
                      label={t('Wert')}
                      hideLabel
                      secret={field.value}
                      itemId={id}
                      field={field.from === null ? undefined : `field:${field.from}`}
                      onChange={(value) =>
                        set({
                          fields: form.fields.map((row) =>
                            row.key === field.key ? { ...row, value } : row,
                          ),
                        })
                      }
                    />
                  ) : (
                    <input
                      type="text"
                      value={field.value.value}
                      aria-label={t('Wert von Feld {n}', { n: index + 1 })}
                      onChange={(e) =>
                        set({
                          fields: form.fields.map((row) =>
                            row.key === field.key
                              ? {
                                  ...row,
                                  value: {
                                    mode: 'value',
                                    value: e.target.value,
                                  },
                                }
                              : row,
                          ),
                        })
                      }
                    />
                  )}
                  <IconButton
                    icon="trash"
                    label={t('Feld {n} entfernen', { n: index + 1 })}
                    title={t('Entfernen')}
                    onClick={() =>
                      set({
                        fields: form.fields.filter((row) => row.key !== field.key),
                      })
                    }
                  />
                </RepeatRow>
              ))}
            </FieldGroup>

            <div className="checks">
              <Checkbox
                label={t('Favorit')}
                checked={form.favorite}
                onChange={(favorite) => set({ favorite })}
              />
              <Checkbox
                label={t('Vor dem Anzeigen nach dem Master-Passwort fragen')}
                checked={form.reprompt}
                onChange={(reprompt) => set({ reprompt })}
              />
            </div>
          </form>
        )}
      </Modal>
      {guard.dialog}
      {generator && (
        <GeneratorDialog
          onClose={() => setGenerator(null)}
          onUse={(password) => {
            if (generator === 'wifi') {
              setWifi({ password: { ...form.wifi.password, mode: 'value', value: password } });
            } else {
              set({ password: { ...form.password, mode: 'value', value: password } });
            }
            setGenerator(null);
          }}
        />
      )}
      {maskedDialog && masked && (
        <NewMaskedDialog
          connection={masked}
          forDomain={forDomainOf(form.uris.find((uri) => uri.uri.trim())?.uri)}
          description={form.name.trim()}
          // The item exists: the address knows it from the start. An address it had goes on
          // existing at UwUMail, only no longer as this item's.
          cipherId={id && !linked ? id : null}
          note={
            linked
              ? t(
                  'Dieser Eintrag hat schon die maskierte Adresse {email}; die neue tritt an ihre Stelle.',
                  {
                    email: linked.email,
                  },
                )
              : undefined
          }
          onClose={() => setMaskedDialog(false)}
          onCreated={async (made: MaskedAddress) => {
            set({ username: made.email });
            setMaskedDialog(false);
            if (!id) setPendingLink(made.id);
            else if (linked) {
              try {
                await updateMasked(linked.id, { cipherId: null });
                await updateMasked(made.id, { cipherId: id });
              } catch (e) {
                toast(maskedErrorText(e), 'error');
              }
            }
            toast(t('Maskierte Adresse angelegt ✧ Speichern nicht vergessen.'));
          }}
        />
      )}
    </>
  );
}
