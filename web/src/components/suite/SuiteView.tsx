import { useContext, useMemo, useState } from 'react';
import { errorText } from '../../lib/errors';
import { t, useLanguage } from '../../lib/i18n';
import {
  KINDS,
  RDP_EXTRA_KINDS,
  deletePlan,
  hostSections,
  indexOf,
  matches,
  move,
  ref,
  str,
  subtitleOf,
  titleOf,
  type ShownKind,
  type SpaceName,
  type SuiteRecord,
} from '../../lib/suite/model';
import { Batch, SpaceChanged, createSpace, loadSpace, useSuiteSpace } from '../../lib/suite/sync';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { listbox } from '../listbox';
import { Modal } from '../Modal';
import { BackToList, Panes } from '../panes';
import { Callout, Tabs } from '../ui';
import { KIND_ICON, SPACE_LABEL, kindLabel, kindsLabel, workspaceLabel } from './labels';
import { SuiteDetail } from './SuiteDetail';
import { SuiteEditor, type EditorTarget } from './SuiteEditor';

const APP: Record<SpaceName, string> = { ssh: 'UwUSSH', rdp: 'UwURDP' };

/** One row of the list: a record, or the heading of a workspace or a group of hosts. */
type Line = { heading: string; id?: undefined } | { id: string; record: SuiteRecord };

/**
 * A space of the suite vault (UwUSSH's or UwURDP's records): a list per kind with search, the
 * record's details with its extras, and editors for everything but the apps' own records.
 */
export function SuiteView({ space }: { space: SpaceName }) {
  useLanguage();
  const state = useSuiteSpace(space, true);
  const [creating, setCreating] = useState(false);

  if (state.status === 'open')
    return (
      <OpenSpace key={space} space={space} records={state.records} unreadable={state.unreadable} />
    );

  const label = t(SPACE_LABEL[space]);
  let body;
  switch (state.status) {
    case 'loading':
      body = <p>{t('Wird geladen …')}</p>;
      break;
    case 'off':
      body = <p>{t('Der Suite-Tresor ist auf diesem Server ausgeschaltet.')}</p>;
      break;
    case 'lost':
      body = (
        <p>
          {t(
            'Der Schlüssel für die UwU-Extras dieses Kontos lässt sich nicht mehr öffnen. Unter Einstellungen → Konto kannst du neu beginnen.',
          )}
        </p>
      );
      break;
    case 'error':
      body = (
        <>
          <p>{errorText(state.error)}</p>
          <button onClick={() => void loadSpace(space, true)}>{t('Noch einmal versuchen')}</button>
        </>
      );
      break;
    case 'none':
      body = (
        <>
          <p>
            {t(
              'Noch keine Daten von {app}. Sobald {app} mit diesem Konto synchronisiert, erscheinen seine Hosts hier. Du kannst den Bereich auch hier anlegen und gleich Hosts eintragen.',
              { app: APP[space] },
            )}
          </p>
          <button
            className="primary"
            disabled={creating}
            onClick={() => {
              setCreating(true);
              void createSpace(space)
                .catch((e) => toast(errorText(e), 'error'))
                .finally(() => setCreating(false));
            }}
          >
            {t('Bereich anlegen')}
          </button>
        </>
      );
      break;
  }
  return (
    <>
      <section className="list-pane" aria-label={label} tabIndex={-1} data-main-content>
        <div className="list-head">
          <p className="list-title">
            <span>{label}</span>
          </p>
        </div>
        <div className="list-empty" role={state.status === 'loading' ? 'status' : undefined}>
          {body}
        </div>
      </section>
      <section className="detail-pane">
        <div className="detail-empty" />
      </section>
    </>
  );
}

function OpenSpace({
  space,
  records,
  unreadable,
}: {
  space: SpaceName;
  records: SuiteRecord[];
  unreadable: number;
}) {
  useLanguage();
  const { showDetail } = useContext(Panes);
  const all = useMemo(() => indexOf(records), [records]);
  const kinds = useMemo(
    () => [
      ...KINDS[space],
      ...(space === 'rdp' ? RDP_EXTRA_KINDS.filter((k) => records.some((r) => r.kind === k)) : []),
    ],
    [space, records],
  );
  const [kind, setKind] = useState<ShownKind>('host');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<EditorTarget | null>(null);
  const [deleting, setDeleting] = useState<SuiteRecord | null>(null);
  const [busy, setBusy] = useState(false);

  const count = (k: ShownKind) => records.filter((r) => r.kind === k).length;

  const lines: Line[] = useMemo(() => {
    const hit = (r: SuiteRecord) => matches(space, r, all, query);
    if (kind === 'host') {
      const out: Line[] = [];
      let workspace = '';
      for (const section of hostSections(records)) {
        const hosts = section.hosts.filter(hit);
        const groupHit = section.group && query && hit(section.group);
        if (!hosts.length && !groupHit) continue;
        if (section.workspace !== workspace) {
          workspace = section.workspace;
          out.push({ heading: workspaceLabel(workspace) });
        }
        out.push({ heading: section.group ? titleOf(section.group) : t('Ohne Gruppe') });
        for (const host of hosts) out.push({ id: host.id, record: host });
      }
      return out;
    }
    return records
      .filter((r) => r.kind === kind && hit(r))
      .sort((a, b) =>
        kind === 'group'
          ? str(a.payload?.workspace).localeCompare(str(b.payload?.workspace)) ||
            (Number(a.payload?.position) || 0) - (Number(b.payload?.position) || 0)
          : titleOf(a).localeCompare(titleOf(b)),
      )
      .map((r) => ({ id: r.id, record: r }));
  }, [space, kind, records, all, query]);

  const ids = lines.flatMap((l) => (l.id ? [l.id] : []));
  const current =
    (selected && ids.includes(selected) ? all.get(selected) : undefined) ??
    (ids[0] ? all.get(ids[0]) : undefined) ??
    null;

  const list = listbox({
    prefix: `suite-${space}`,
    ids,
    selected: current?.id ?? null,
    onSelect: setSelected,
    onOpen: (id) => {
      setSelected(id);
      showDetail();
    },
  });

  /** Show a record, wherever it is listed. */
  const open = (id: string) => {
    const target = all.get(id);
    if (!target) return;
    if (
      (KINDS[space] as string[]).includes(target.kind) ||
      RDP_EXTRA_KINDS.includes(target.kind as ShownKind)
    )
      setKind(target.kind as ShownKind);
    setQuery('');
    setSelected(id);
    showDetail();
  };

  const run = async (work: (batch: Batch) => Promise<void>, done: string) => {
    setBusy(true);
    try {
      const batch = new Batch(space);
      await work(batch);
      const conflicts = await batch.push();
      if (conflicts.length)
        toast(t('Inzwischen woanders geändert und neu geladen. Bitte noch einmal.'), 'error');
      else toast(done);
      return conflicts.length === 0;
    } catch (e) {
      toast(
        e instanceof SpaceChanged
          ? t(
              'Der Bereich hat inzwischen einen neuen Schlüssel bekommen und ist neu geladen. Bitte noch einmal.',
            )
          : errorText(e),
        'error',
      );
      return false;
    } finally {
      setBusy(false);
    }
  };

  const siblingsOf = (record: SuiteRecord) =>
    records.filter(
      (r) =>
        r.kind === record.kind &&
        str(r.payload?.workspace) === str(record.payload?.workspace) &&
        (record.kind !== 'host' || ref(r.payload?.group_id) === ref(record.payload?.group_id)),
    );

  const reorder = (record: SuiteRecord, by: -1 | 1) =>
    void run(async (batch) => {
      for (const [id, position] of move(siblingsOf(record), record.id, by)) {
        const target = all.get(id);
        if (target?.payload) await batch.edit(id, { ...target.payload, position });
      }
    }, t('Reihenfolge gespeichert.'));

  const plan = deleting ? deletePlan(records, deleting) : null;
  const label = t(SPACE_LABEL[space]);
  const newKind: ShownKind | null = kind === 'known_host' ? null : kind;

  return (
    <>
      <section className="list-pane" aria-label={label} tabIndex={-1} data-main-content>
        <div className="list-head">
          <p className="list-title">
            <span>{label}</span>
            <span className="list-count">{ids.length}</span>
            <span className="spacer" />
            {newKind && (
              <button
                className="new-item"
                onClick={() =>
                  setEditing({
                    kind: newKind,
                    record: null,
                    preset:
                      newKind === 'host' && current?.kind === 'host'
                        ? {
                            workspace: str(current.payload?.workspace) || 'private',
                            group_id: ref(current.payload?.group_id),
                          }
                        : undefined,
                  })
                }
              >
                <Icon name="plus" size={15} />
                {kindLabel(newKind)}
              </button>
            )}
          </p>
          <label className="search-box">
            <Icon name="search" size={15} />
            <input
              className="search"
              type="search"
              value={query}
              placeholder={t('{kind} durchsuchen', { kind: kindsLabel(kind) })}
              aria-label={t('{kind} durchsuchen', { kind: kindsLabel(kind) })}
              spellCheck={false}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                  e.preventDefault();
                  list.move(e.key === 'ArrowDown' ? 1 : -1);
                } else if (e.key === 'Escape' && query) {
                  e.preventDefault();
                  e.stopPropagation();
                  setQuery('');
                }
              }}
            />
          </label>
          <div className="suite-kinds">
            <Tabs
              label={t('Art der Einträge')}
              variant="segmented"
              value={kind}
              onChange={(k) => {
                setKind(k);
                setSelected(null);
              }}
              tabs={kinds.map((k) => ({
                id: k,
                label: kindsLabel(k),
                extra: count(k) ? <span className="suite-count">{count(k)}</span> : undefined,
              }))}
            />
          </div>
          {unreadable > 0 && (
            <p className="form-note">
              {t('{count} Einträge lassen sich hier nicht öffnen; sie bleiben, wie sie sind.', {
                count: unreadable,
              })}
            </p>
          )}
        </div>
        {ids.length ? (
          <ul className="item-list" aria-label={kindsLabel(kind)} {...list.listProps}>
            {lines.map((line, index) =>
              line.id === undefined ? (
                <li key={`h${index}`} role="presentation" className="suite-heading">
                  {line.heading}
                </li>
              ) : (
                <li
                  key={line.id}
                  id={list.optionId(line.id)}
                  role="option"
                  aria-selected={line.id === current?.id}
                  className="item-row"
                  onClick={() => {
                    setSelected(line.id);
                    showDetail();
                  }}
                >
                  <span className="item-tile" data-hue={space === 'ssh' ? '4' : '5'}>
                    <Icon name={KIND_ICON[line.record.kind] ?? 'note'} size={18} />
                  </span>
                  <span className="item-text">
                    <span className="item-name">{titleOf(line.record) || t('(ohne Namen)')}</span>
                    <span className="item-sub">{subtitleOf(space, line.record, all)}</span>
                  </span>
                </li>
              ),
            )}
          </ul>
        ) : (
          <div className="list-empty">
            <p>
              {query
                ? t('Nichts gefunden.')
                : kind === 'known_host'
                  ? t('Noch keine bekannten Hosts. {app} trägt sie beim ersten Verbinden ein.', {
                      app: APP[space],
                    })
                  : t('Noch nichts hier.')}
            </p>
          </div>
        )}
      </section>

      <section className="detail-pane">
        <BackToList />
        {current ? (
          <SuiteDetail
            space={space}
            record={current}
            all={all}
            records={records}
            onEdit={() => setEditing({ kind: current.kind as ShownKind, record: current })}
            onDelete={() => setDeleting(current)}
            onOpen={open}
            onAddForward={
              current.kind === 'host' && space === 'ssh'
                ? () =>
                    setEditing({
                      kind: 'port_forward',
                      record: null,
                      preset: { host_id: current.id },
                    })
                : undefined
            }
            onMove={
              current.kind === 'host' || current.kind === 'group'
                ? (by) => reorder(current, by)
                : undefined
            }
          />
        ) : (
          <div className="detail-empty" />
        )}
      </section>

      {editing && (
        <SuiteEditor
          {...editing}
          space={space}
          records={records}
          all={all}
          onClose={() => setEditing(null)}
          onSaved={(id) => {
            setEditing(null);
            const saved = editing.kind;
            if (saved === kind || saved === 'host' || saved === 'group') setKind(saved);
            setSelected(id);
          }}
        />
      )}

      {deleting && plan && (
        <Modal
          title={t('„{name}“ löschen?', { name: titleOf(deleting) || t('(ohne Namen)') })}
          tone="warning"
          onCancel={() => setDeleting(null)}
          footer={
            plan.ok ? (
              <>
                <span className="spacer" />
                <button data-secondary data-autofocus onClick={() => setDeleting(null)}>
                  {t('Abbrechen')}
                </button>
                <button
                  className="danger"
                  disabled={busy}
                  onClick={() =>
                    void run(async (batch) => {
                      for (const id of plan.tombstones) await batch.remove(id);
                      for (const edit of plan.edits) await batch.edit(edit.id, edit.payload);
                    }, t('Gelöscht.')).then((ok) => ok && setDeleting(null))
                  }
                >
                  {t('Löschen')}
                </button>
              </>
            ) : (
              <>
                <span className="spacer" />
                <button className="primary" onClick={() => setDeleting(null)}>
                  {t('Verstanden')}
                </button>
              </>
            )
          }
        >
          {plan.ok ? (
            <>
              <p className="dialog-lead">
                {t('Er verschwindet auch aus {app} auf allen Geräten.', { app: APP[space] })}
              </p>
              {plan.tombstones.length > 1 && deleting.kind === 'host' && (
                <p>
                  {t(
                    'Seine Port-Weiterleitungen werden mit gelöscht. Identitäten und Schlüssel bleiben.',
                  )}
                </p>
              )}
              {plan.tombstones.length > 1 && deleting.kind !== 'host' && (
                <p>{t('Das gespeicherte Passwort bzw. der Schlüssel wird mit gelöscht.')}</p>
              )}
              {plan.edits.length > 0 && (
                <p>{t('Ihre {count} Hosts bleiben, ohne Gruppe.', { count: plan.edits.length })}</p>
              )}
            </>
          ) : (
            <Callout tone="warning" title={t('Wird noch verwendet')}>
              <p>{t('Lösche oder ändere zuerst, was darauf zeigt:')}</p>
              <ul>
                {plan.users.map((user) => (
                  <li key={user.id}>
                    {kindLabel(user.kind)}: {titleOf(user) || t('(ohne Namen)')}
                  </li>
                ))}
              </ul>
            </Callout>
          )}
        </Modal>
      )}
    </>
  );
}
