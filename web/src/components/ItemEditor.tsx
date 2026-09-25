import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
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
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import {
  CARD_BRANDS,
  FIELD_KIND_LABEL,
  IDENTITY_FIELDS,
  IDENTITY_LABEL,
  KIND_LABEL,
  MATCH_LABEL,
} from '../lib/items';
import { toast } from '../lib/toast';
import { useCloseGuard } from './CloseGuard';
import { GeneratorDialog } from './GeneratorDialog';
import { Icon } from './Icon';
import { Modal } from './Modal';

/**
 * A value the editor may not have: a password, a card number, a hidden field.
 * `keep` means the item's own value stays — the editor never saw it, and it
 * never goes through the window unless someone asks to see it.
 */
type Sec = { mode: 'keep' | 'value'; value: string };

const keep = (has: boolean): Sec =>
  has ? { mode: 'keep', value: '' } : { mode: 'value', value: '' };
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
  form.fields = (detail.fields ?? []).map((field) => ({
    key: field.index + 1,
    name: field.name ?? '',
    kind: field.kind,
    value:
      field.kind === 'hidden' ? keep(field.hasValue) : { mode: 'value', value: field.value ?? '' },
    from: field.index,
  }));
  return form;
}

function draftOf(form: Form, kind: ItemKind): Draft {
  const draft: Draft = {
    kind,
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
  if (kind === 'ssh-key') {
    draft.sshKey = {
      privateKey: sent(form.privateKey),
      publicKey: form.publicKey,
      fingerprint: form.fingerprint,
    };
  }
  return draft;
}

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}

/**
 * A field for a value the editor may not have. It shows dots until someone
 * asks to see it; typing replaces it, the cross empties it, and an empty field
 * that was never touched leaves the item's value alone.
 */
function SecretField({
  label,
  secret,
  onChange,
  itemId,
  field,
  multiline,
  hint,
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
  children?: ReactNode;
}) {
  useLanguage();
  const kept = secret.mode === 'keep';
  const cleared = secret.mode === 'value' && secret.value === '' && Boolean(itemId && field);

  const reveal = async () => {
    if (!itemId || !field) return;
    try {
      onChange({ mode: 'value', value: await revealField(itemId, field) });
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const type = (value: string) => {
    // Deleting what was typed goes back to leaving the value alone.
    if (value === '' && kept) return;
    onChange({ mode: 'value', value });
  };

  const input = multiline ? (
    <textarea
      className="mono"
      rows={4}
      aria-label={label}
      value={secret.value}
      placeholder={kept ? '••••••••••••' : undefined}
      spellCheck={false}
      onChange={(e) => type(e.target.value)}
    />
  ) : (
    <input
      type="text"
      className="mono"
      aria-label={label}
      value={secret.value}
      placeholder={kept ? '••••••••••••' : undefined}
      spellCheck={false}
      autoComplete="off"
      onChange={(e) => type(e.target.value)}
    />
  );

  return (
    <div className="field">
      <span className="field-label-row">
        <span>{label}</span>
        <span className="field-actions">
          {kept && itemId && field && (
            <button
              type="button"
              className="icon-button"
              onClick={() => void reveal()}
              title={t('Zeigen')}
              aria-label={t('{label} zeigen', { label })}
            >
              <Icon name="eye" size={15} />
            </button>
          )}
          {children}
          {!kept && itemId && field && (
            <button
              type="button"
              className="icon-button"
              onClick={() => onChange(keep(true))}
              title={t('Unverändert lassen')}
              aria-label={t('{label} unverändert lassen', { label })}
            >
              <Icon name="history" size={15} />
            </button>
          )}
        </span>
      </span>
      {input}
      {kept ? (
        <small className="field-hint">{t('Bleibt, wie es ist.')}</small>
      ) : cleared ? (
        <small className="field-hint" data-tone="warn">
          {t('Wird beim Speichern geleert.')}
        </small>
      ) : (
        hint && <small className="field-hint">{hint}</small>
      )}
    </div>
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
  const [generator, setGenerator] = useState<null | 'password'>(null);
  const [nextKey, setNextKey] = useState(1000);
  const id = summary?.id ?? null;

  useEffect(() => {
    if (!summary) return;
    let stopped = false;
    vaultItem(summary.id)
      .then((detail) => {
        if (stopped) return;
        if (detail.locked) {
          setError(t('Dieser Eintrag fragt zuerst nach deinem Master-Passwort.'));
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
            <button type="button" className="quiet" data-secondary onClick={guard.request}>
              {t('Abbrechen')}
            </button>
            <span className="spacer" />
            <button
              type="submit"
              form="item-editor"
              className="primary"
              disabled={busy || loading || !form.name.trim()}
            >
              {busy ? t('Speichert …') : t('Speichern')}
            </button>
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

            <div className="editor-row">
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
            </div>

            {kind === 'login' && (
              <>
                <Field label={t('Benutzername')}>
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
                  <button
                    type="button"
                    className="icon-button"
                    onClick={() => setGenerator('password')}
                    title={t('Passwort-Generator')}
                    aria-label={t('Passwort-Generator')}
                  >
                    <Icon name="dice" size={15} />
                  </button>
                </SecretField>
                <SecretField
                  label={t('Einmal-Code (TOTP)')}
                  secret={form.totp}
                  onChange={(totp) => set({ totp })}
                  itemId={id}
                  field="totp"
                  hint={t('Der Schlüssel aus der App: Base32 oder eine otpauth://-Adresse.')}
                />

                <fieldset className="editor-list">
                  <legend>{t('Websites')}</legend>
                  {form.uris.map((uri, index) => (
                    <div className="editor-row" key={uri.key}>
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
                      <button
                        type="button"
                        className="icon-button"
                        title={t('Entfernen')}
                        aria-label={t('Adresse {n} entfernen', {
                          n: index + 1,
                        })}
                        onClick={() =>
                          set({
                            uris: form.uris.filter((row) => row.key !== uri.key),
                          })
                        }
                      >
                        <Icon name="trash" size={15} />
                      </button>
                    </div>
                  ))}
                  <button
                    type="button"
                    className="quiet add-row"
                    onClick={() =>
                      set({
                        uris: [...form.uris, { key: key(), uri: '', match: null }],
                      })
                    }
                  >
                    <Icon name="plus" size={14} />
                    {t('Website hinzufügen')}
                  </button>
                </fieldset>
              </>
            )}

            {kind === 'card' && (
              <>
                <div className="editor-row">
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
                </div>
                <SecretField
                  label={t('Kartennummer')}
                  secret={form.number}
                  onChange={(number) => set({ number })}
                  itemId={id}
                  field="card-number"
                />
                <div className="editor-row">
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
                </div>
              </>
            )}

            {kind === 'identity' && (
              <div className="editor-grid">
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
              </div>
            )}

            {kind === 'ssh-key' && (
              <>
                <p className="dialog-lead">
                  {t(
                    'Ein SSH-Schlüssel braucht alle drei Teile – privater Schlüssel, öffentlicher Schlüssel und Fingerprint. Der Server wirft den Eintrag sonst weg.',
                  )}
                </p>
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

            <Field label={t('Notizen')}>
              <textarea
                rows={kind === 'note' ? 8 : 3}
                value={form.notes}
                onChange={(e) => set({ notes: e.target.value })}
              />
            </Field>

            <fieldset className="editor-list">
              <legend>{t('Eigene Felder')}</legend>
              {form.fields.map((field, index) => (
                <div className="editor-row" key={field.key}>
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
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={field.value.value === 'true'}
                        onChange={(e) =>
                          set({
                            fields: form.fields.map((row) =>
                              row.key === field.key
                                ? {
                                    ...row,
                                    value: {
                                      mode: 'value',
                                      value: e.target.checked ? 'true' : 'false',
                                    },
                                  }
                                : row,
                            ),
                          })
                        }
                      />
                      <span>{field.value.value === 'true' ? t('Ja') : t('Nein')}</span>
                    </label>
                  ) : field.kind === 'hidden' ? (
                    <SecretField
                      label={t('Wert')}
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
                  <button
                    type="button"
                    className="icon-button"
                    title={t('Entfernen')}
                    aria-label={t('Feld {n} entfernen', { n: index + 1 })}
                    onClick={() =>
                      set({
                        fields: form.fields.filter((row) => row.key !== field.key),
                      })
                    }
                  >
                    <Icon name="trash" size={15} />
                  </button>
                </div>
              ))}
              <div className="add-kinds">
                {(['text', 'hidden', 'boolean'] as FieldKind[]).map((fieldKind) => (
                  <button
                    key={fieldKind}
                    type="button"
                    className="quiet add-row"
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
                    <Icon name="plus" size={14} />
                    {t(FIELD_KIND_LABEL[fieldKind])}
                  </button>
                ))}
              </div>
            </fieldset>

            <div className="editor-switches">
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.favorite}
                  onChange={(e) => set({ favorite: e.target.checked })}
                />
                <span>{t('Favorit')}</span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.reprompt}
                  onChange={(e) => set({ reprompt: e.target.checked })}
                />
                <span>{t('Vor dem Anzeigen nach dem Master-Passwort fragen')}</span>
              </label>
            </div>
          </form>
        )}
      </Modal>
      {guard.dialog}
      {generator && (
        <GeneratorDialog
          onClose={() => setGenerator(null)}
          onUse={(password) => {
            set({ password: { mode: 'value', value: password } });
            setGenerator(null);
          }}
        />
      )}
    </>
  );
}
