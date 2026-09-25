import { listen } from '../lib/events';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  bulkItems,
  copyField,
  deleteFolder,
  moveItems,
  saveFolder,
  vaultItems,
  vaultOverview,
  type ItemKind,
  type ItemSummary,
  type Overview,
  type Status,
} from '../lib/api';
import { errorText } from '../lib/errors';
import { copiedText } from '../lib/format';
import { N_, t, useLanguage } from '../lib/i18n';
import { KIND_LABEL } from '../lib/items';
import { useSettings } from '../lib/settings';
import { toast } from '../lib/toast';
import { AccountCard } from './AccountCard';
import { ContextMenu, type MenuItem } from './ContextMenu';
import { Icon, type IconName } from './Icon';
import { ItemDetail } from './ItemDetail';
import { ItemEditor } from './ItemEditor';
import { ItemTile } from './ItemTile';
import { Modal } from './Modal';
import { NyuScene } from './nyu/scenes';

export type Filter =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'type'; type: ItemKind }
  | { kind: 'folder'; id: string | null }
  | { kind: 'collection'; id: string }
  | { kind: 'archive' }
  | { kind: 'trash' };

const TYPES: { type: ItemKind; label: string; icon: IconName }[] = [
  { type: 'login', label: N_('Logins'), icon: 'globe' },
  { type: 'card', label: N_('Karten'), icon: 'card' },
  { type: 'identity', label: N_('Identitäten'), icon: 'id' },
  { type: 'note', label: N_('Notizen'), icon: 'note' },
  { type: 'ssh-key', label: N_('SSH-Schlüssel'), icon: 'key' },
];

function matches(filter: Filter, item: ItemSummary): boolean {
  if (filter.kind === 'trash') return item.deleted;
  if (item.deleted) return false;
  // Archived items are out of the way: only in the archive.
  if (filter.kind === 'archive') return item.archived;
  if (item.archived) return false;
  switch (filter.kind) {
    case 'all':
      return true;
    case 'favorites':
      return item.favorite;
    case 'type':
      return item.kind === filter.type;
    case 'folder':
      return !item.organizationId && item.folderId === filter.id;
    case 'collection':
      return item.collectionIds.includes(filter.id);
  }
}

function same(a: Filter, b: Filter) {
  return JSON.stringify(a) === JSON.stringify(b);
}

type Props = {
  status: Status;
  /** The search field, for Ctrl+F from the app. */
  searchRef: React.RefObject<HTMLInputElement | null>;
  onAddAccount: () => void;
};

/** What the editor is open for: an item to change, or a new one of that kind. */
type Editing = { summary: ItemSummary | null; kind: ItemKind };

export function VaultScreen({ status, searchRef, onAddAccount }: Props) {
  useLanguage();
  const settings = useSettings();
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [filter, setFilter] = useState<Filter>({ kind: 'all' });
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [newMenu, setNewMenu] = useState<{ x: number; y: number } | null>(null);
  const [folderMenu, setFolderMenu] = useState<{ x: number; y: number; id: string } | null>(null);
  const [folderDialog, setFolderDialog] = useState<null | { id: string | null; name: string }>(
    null,
  );
  const [folderToDelete, setFolderToDelete] = useState<{ id: string; name: string } | null>(null);
  /** Items ticked for doing something to all of them at once. */
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);
  const listRef = useRef<HTMLUListElement>(null);

  const reload = useCallback(async () => {
    try {
      const [list, info] = await Promise.all([vaultItems(), vaultOverview()]);
      setItems(list);
      setOverview(info);
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setLoaded(true);
    }
  }, []);

  // Also on a switch: the other account's items must not stay on screen while
  // its sync is still on its way.
  useEffect(() => {
    void reload();
    const stop = listen('vault-changed', () => void reload());
    return () => void stop.then((unlisten) => unlisten());
  }, [reload, status.accountId]);

  const counts = useMemo(() => {
    const live = items.filter((i) => !i.deleted && !i.archived);
    return {
      all: live.length,
      favorites: live.filter((i) => i.favorite).length,
      trash: items.filter((i) => i.deleted).length,
      archive: items.filter((i) => i.archived && !i.deleted).length,
      type: (type: ItemKind) => live.filter((i) => i.kind === type).length,
      folder: (id: string | null) =>
        live.filter((i) => !i.organizationId && i.folderId === id).length,
      collection: (id: string) => live.filter((i) => i.collectionIds.includes(id)).length,
    };
  }, [items]);

  const visible = useMemo(() => {
    const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
    return items
      .filter((item) =>
        words.length ? !item.deleted || filter.kind === 'trash' : matches(filter, item),
      )
      .filter((item) => {
        if (!words.length) return true;
        const haystack = `${item.name} ${item.subtitle ?? ''} ${item.host ?? ''}`.toLowerCase();
        return words.every((word) => haystack.includes(word));
      })
      .sort(
        (a, b) =>
          collator.compare(a.name, b.name) || collator.compare(a.subtitle ?? '', b.subtitle ?? ''),
      );
  }, [items, filter, query]);

  // Keep a selection that is still visible, or take the first.
  useEffect(() => {
    if (!loaded) return;
    if (selected && visible.some((i) => i.id === selected)) return;
    setSelected(visible[0]?.id ?? null);
  }, [visible, selected, loaded]);

  const move = (step: number) => {
    if (!visible.length) return;
    const index = visible.findIndex((i) => i.id === selected);
    const next = visible[Math.max(0, Math.min(visible.length - 1, index + step))];
    if (!next) return;
    setSelected(next.id);
    listRef.current
      ?.querySelector<HTMLElement>(`[data-id="${CSS.escape(next.id)}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  };

  const current = items.find((i) => i.id === selected) ?? null;

  // Ctrl+U, Ctrl+P, Ctrl+T copy username, password and code of the selected
  // item, as in Bitwarden's desktop app.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
      if (document.querySelector('.modal')) return;
      const field = { u: 'username', p: 'password', t: 'totp' }[event.key.toLowerCase()];
      if (!field || !current || current.kind !== 'login') return;
      event.preventDefault();
      void copyField(current.id, field)
        .then(() => toast(copiedText(field, settings.clipboardClear)))
        .catch((e) => toast(errorText(e), 'error'));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [current, settings.clipboardClear]);

  const title = query.trim()
    ? t('Suche')
    : filter.kind === 'all'
      ? t('Alle Einträge')
      : filter.kind === 'favorites'
        ? t('Favoriten')
        : filter.kind === 'trash'
          ? t('Papierkorb')
          : filter.kind === 'archive'
            ? t('Archiv')
            : filter.kind === 'type'
              ? t(TYPES.find((x) => x.type === filter.type)?.label ?? '')
              : filter.kind === 'folder'
                ? (overview?.folders.find((f) => f.id === filter.id)?.name ?? t('Ohne Ordner'))
                : (overview?.collections.find((c) => c.id === filter.id)?.name ?? '');

  const pick = (next: Filter) => {
    setFilter(next);
    setQuery('');
    setChecked(new Set());
  };

  // A ticked item that is no longer shown is no longer ticked.
  useEffect(() => {
    setChecked((current) => {
      const shown = new Set(visible.map((item) => item.id));
      const kept = [...current].filter((id) => shown.has(id));
      return kept.length === current.size ? current : new Set(kept);
    });
  }, [visible]);

  /** Tick or untick; with Shift, everything from the last ticked one to this one. */
  const toggle = (id: string, range: boolean) => {
    setChecked((current) => {
      const next = new Set(current);
      if (range && lastChecked) {
        const from = visible.findIndex((item) => item.id === lastChecked);
        const to = visible.findIndex((item) => item.id === id);
        if (from >= 0 && to >= 0) {
          for (const item of visible.slice(Math.min(from, to), Math.max(from, to) + 1))
            next.add(item.id);
          return next;
        }
      }
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setLastChecked(id);
  };

  const bulk = async (work: () => Promise<void>, done: string) => {
    try {
      await work();
      toast(done);
      setChecked(new Set());
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const nav = (target: Filter, icon: IconName, label: string, count: number) => (
    <li key={JSON.stringify(target)}>
      <button
        className="nav-row"
        aria-current={!query.trim() && same(filter, target) ? 'true' : undefined}
        onClick={() => pick(target)}
      >
        <Icon name={icon} size={16} />
        <span className="nav-label">{label}</span>
        {count > 0 && <span className="nav-count">{count}</span>}
      </button>
    </li>
  );

  const folderActions = (id: string): MenuItem[] => {
    const folder = overview?.folders.find((f) => f.id === id);
    if (!folder) return [];
    return [
      {
        label: t('Umbenennen'),
        icon: 'pencil',
        onSelect: () => setFolderDialog({ id, name: folder.name }),
      },
      {
        label: t('Löschen'),
        icon: 'trash',
        danger: true,
        onSelect: () => setFolderToDelete({ id, name: folder.name }),
      },
    ];
  };

  const noFolder = counts.folder(null);

  return (
    <div className="vault">
      <nav className="sidebar" aria-label={t('Tresor')}>
        <ul className="nav-list">
          {nav({ kind: 'all' }, 'layers', t('Alle Einträge'), counts.all)}
          {nav({ kind: 'favorites' }, 'star', t('Favoriten'), counts.favorites)}
        </ul>

        <h2>{t('Typen')}</h2>
        <ul className="nav-list">
          {TYPES.filter((x) => counts.type(x.type) > 0 || x.type === 'login').map((x) =>
            nav({ kind: 'type', type: x.type }, x.icon, t(x.label), counts.type(x.type)),
          )}
        </ul>

        {overview && (
          <>
            <h2 className="nav-heading">
              {t('Ordner')}
              <button
                className="icon-button tiny"
                title={t('Neuer Ordner')}
                aria-label={t('Neuer Ordner')}
                onClick={() => setFolderDialog({ id: null, name: '' })}
              >
                <Icon name="folderPlus" size={14} />
              </button>
            </h2>
            <ul className="nav-list">
              {[...overview.folders]
                .sort((a, b) => a.name.localeCompare(b.name))
                .map((f) => (
                  <li
                    key={f.id}
                    onContextMenu={(event) => {
                      event.preventDefault();
                      setFolderMenu({
                        x: event.clientX,
                        y: event.clientY,
                        id: f.id,
                      });
                    }}
                  >
                    <button
                      className="nav-row"
                      aria-current={
                        !query.trim() && same(filter, { kind: 'folder', id: f.id })
                          ? 'true'
                          : undefined
                      }
                      onClick={() => pick({ kind: 'folder', id: f.id })}
                    >
                      <Icon name="folder" size={16} />
                      <span className="nav-label">{f.name}</span>
                      {counts.folder(f.id) > 0 && (
                        <span className="nav-count">{counts.folder(f.id)}</span>
                      )}
                    </button>
                  </li>
                ))}
              {overview.folders.length > 0 &&
                noFolder > 0 &&
                nav({ kind: 'folder', id: null }, 'folder', t('Ohne Ordner'), noFolder)}
            </ul>
          </>
        )}

        {overview?.organizations.map((org) => (
          <div key={org.id}>
            <h2 className="org-heading">
              <Icon name="building" size={13} />
              {org.name}
            </h2>
            <ul className="nav-list">
              {overview.collections
                .filter((c) => c.organizationId === org.id)
                .sort((a, b) => a.name.localeCompare(b.name))
                .map((c) =>
                  nav({ kind: 'collection', id: c.id }, 'grid', c.name, counts.collection(c.id)),
                )}
            </ul>
          </div>
        ))}

        {(counts.archive > 0 || (settings.showTrash && counts.trash > 0)) && (
          <ul className="nav-list nav-trash">
            {counts.archive > 0 && nav({ kind: 'archive' }, 'archive', t('Archiv'), counts.archive)}
            {settings.showTrash &&
              counts.trash > 0 &&
              nav({ kind: 'trash' }, 'trash', t('Papierkorb'), counts.trash)}
          </ul>
        )}

        <span className="spacer" />
        <AccountCard status={status} onAddAccount={onAddAccount} />
      </nav>

      <section className="list-pane" aria-label={title}>
        <div className="list-head">
          <label className="search-box">
            <Icon name="search" size={15} />
            <input
              ref={searchRef}
              className="search"
              type="search"
              value={query}
              placeholder={t('Tresor durchsuchen (Strg+F)')}
              aria-label={t('Tresor durchsuchen')}
              spellCheck={false}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                  e.preventDefault();
                  move(e.key === 'ArrowDown' ? 1 : -1);
                } else if (e.key === 'Escape' && query) {
                  e.preventDefault();
                  e.stopPropagation();
                  setQuery('');
                }
              }}
            />
          </label>
          {checked.size > 0 ? (
            <div className="bulk-bar" role="toolbar" aria-label={t('Ausgewählte Einträge')}>
              <span className="bulk-count">{t('{n} ausgewählt', { n: checked.size })}</span>
              <span className="spacer" />
              {filter.kind === 'trash' ? (
                <>
                  <button
                    className="quiet"
                    onClick={() =>
                      void bulk(() => bulkItems('restore', [...checked]), t('Wiederhergestellt ✧'))
                    }
                  >
                    {t('Wiederherstellen')}
                  </button>
                  <button className="quiet danger-text" onClick={() => setConfirmBulkDelete(true)}>
                    {t('Endgültig löschen')}
                  </button>
                </>
              ) : (
                <>
                  {overview && overview.folders.length > 0 && (
                    <select
                      className="select"
                      value=""
                      aria-label={t('In Ordner verschieben')}
                      onChange={(e) => {
                        const target = e.target.value === '-' ? null : e.target.value;
                        void bulk(() => moveItems([...checked], target), t('Verschoben ✧'));
                      }}
                    >
                      <option value="" disabled>
                        {t('Verschieben …')}
                      </option>
                      <option value="-">{t('Ohne Ordner')}</option>
                      {overview.folders.map((folder) => (
                        <option key={folder.id} value={folder.id}>
                          {folder.name}
                        </option>
                      ))}
                    </select>
                  )}
                  <button
                    className="icon-button"
                    title={filter.kind === 'archive' ? t('Aus dem Archiv holen') : t('Archivieren')}
                    aria-label={
                      filter.kind === 'archive' ? t('Aus dem Archiv holen') : t('Archivieren')
                    }
                    onClick={() =>
                      void bulk(
                        () =>
                          bulkItems(filter.kind === 'archive' ? 'unarchive' : 'archive', [
                            ...checked,
                          ]),
                        filter.kind === 'archive' ? t('Aus dem Archiv geholt ✧') : t('Archiviert.'),
                      )
                    }
                  >
                    <Icon name="archive" size={15} />
                  </button>
                  <button
                    className="icon-button"
                    title={t('In den Papierkorb')}
                    aria-label={t('In den Papierkorb')}
                    onClick={() =>
                      void bulk(() => bulkItems('trash', [...checked]), t('Im Papierkorb.'))
                    }
                  >
                    <Icon name="trash" size={15} />
                  </button>
                </>
              )}
              <button
                className="icon-button"
                title={t('Auswahl aufheben')}
                aria-label={t('Auswahl aufheben')}
                onClick={() => setChecked(new Set())}
              >
                ×
              </button>
            </div>
          ) : (
            <p className="list-title">
              <span>{title}</span>
              <span className="list-count">{visible.length}</span>
              <span className="spacer" />
              <button
                className="new-item"
                aria-haspopup="menu"
                aria-expanded={Boolean(newMenu)}
                title={t('Neuer Eintrag')}
                onClick={(event) => {
                  const rect = event.currentTarget.getBoundingClientRect();
                  setNewMenu({ x: rect.right - 180, y: rect.bottom + 4 });
                }}
              >
                <Icon name="plus" size={15} />
                {t('Neu')}
              </button>
            </p>
          )}
        </div>

        {visible.length > 0 ? (
          <ul
            ref={listRef}
            className="item-list"
            role="listbox"
            aria-label={title}
            tabIndex={0}
            aria-activedescendant={selected ? `item-${selected}` : undefined}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                move(e.key === 'ArrowDown' ? 1 : -1);
              } else if (e.key === 'Home' || e.key === 'End') {
                e.preventDefault();
                move(e.key === 'Home' ? -visible.length : visible.length);
              }
            }}
          >
            {visible.map((item) => (
              <li
                key={item.id}
                id={`item-${item.id}`}
                data-id={item.id}
                role="option"
                aria-selected={item.id === selected}
                className="item-row"
                data-checked={checked.has(item.id) || undefined}
                onClick={(event) => {
                  if (event.ctrlKey || event.metaKey || event.shiftKey) {
                    event.preventDefault();
                    toggle(item.id, event.shiftKey);
                  } else setSelected(item.id);
                }}
              >
                <input
                  type="checkbox"
                  className="item-check"
                  checked={checked.has(item.id)}
                  aria-label={t('{name} auswählen', { name: item.name || t('(ohne Namen)') })}
                  onClick={(event) => {
                    event.stopPropagation();
                    toggle(item.id, event.shiftKey);
                  }}
                  onChange={() => undefined}
                />
                <ItemTile item={item} />
                <span className="item-text">
                  <span className="item-name">{item.name || t('(ohne Namen)')}</span>
                  {item.subtitle && <span className="item-sub">{item.subtitle}</span>}
                </span>
                <span className="item-badges">
                  {item.broken && (
                    <span title={t('Nicht alles ließ sich entschlüsseln')}>
                      <Icon name="warning" size={13} className="badge-warning" />
                    </span>
                  )}
                  {item.reprompt && (
                    <Icon name="lock" size={13} title={t('Fragt nach dem Master-Passwort')} />
                  )}
                  {item.hasTotp && <Icon name="clock" size={13} title={t('Mit Einmal-Code')} />}
                  {item.organizationId && (
                    <Icon name="building" size={13} title={t('Organisation')} />
                  )}
                  {item.favorite && (
                    <Icon name="star" size={13} className="badge-star" title={t('Favorit')} />
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="list-empty">
            {loaded && (
              <>
                <NyuScene
                  name={query ? 'puzzled' : items.length ? 'sleepy' : 'pick'}
                  className="empty-scene"
                />
                <p>
                  {query
                    ? t('Nichts gefunden für „{query}“.', {
                        query: query.trim(),
                      })
                    : items.length
                      ? t('Hier ist nichts. (˘ω˘)')
                      : t('Dein Tresor ist noch leer. Leg oben rechts den ersten Eintrag an.')}
                </p>
              </>
            )}
          </div>
        )}
      </section>

      <section className="detail-pane">
        {current ? (
          <ItemDetail
            key={current.id}
            summary={current}
            overview={overview}
            onEdit={() => setEditing({ summary: current, kind: current.kind })}
          />
        ) : (
          <div className="detail-empty">
            {loaded && <NyuScene name="vault" className="empty-scene" />}
          </div>
        )}
      </section>

      {confirmBulkDelete && (
        <Modal
          title={t('Endgültig löschen?')}
          tone="warning"
          onCancel={() => setConfirmBulkDelete(false)}
          footer={
            <>
              <span className="spacer" />
              <button onClick={() => setConfirmBulkDelete(false)} data-secondary>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  setConfirmBulkDelete(false);
                  void bulk(() => bulkItems('delete', [...checked]), t('Gelöscht.'));
                }}
              >
                {t('Endgültig löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t('{n} Einträge sind danach für immer weg, auf jedem Gerät.', { n: checked.size })}
          </p>
        </Modal>
      )}

      {newMenu && (
        <ContextMenu
          x={newMenu.x}
          y={newMenu.y}
          label={t('Neuer Eintrag')}
          onClose={() => setNewMenu(null)}
          items={TYPES.map((type) => ({
            label: t(KIND_LABEL[type.type]),
            icon: type.icon,
            onSelect: () => setEditing({ summary: null, kind: type.type }),
          }))}
        />
      )}

      {folderMenu && (
        <ContextMenu
          x={folderMenu.x}
          y={folderMenu.y}
          label={t('Ordner')}
          onClose={() => setFolderMenu(null)}
          items={folderActions(folderMenu.id)}
        />
      )}

      {folderDialog && (
        <FolderDialog
          folder={folderDialog}
          onClose={() => setFolderDialog(null)}
          onSaved={() => {
            setFolderDialog(null);
            void reload();
          }}
        />
      )}

      {folderToDelete && (
        <Modal
          title={t('Ordner löschen?')}
          onCancel={() => setFolderToDelete(null)}
          footer={
            <>
              <span className="spacer" />
              <button
                className="danger"
                data-secondary
                onClick={() => {
                  const id = folderToDelete.id;
                  setFolderToDelete(null);
                  void deleteFolder(id)
                    .then(() => {
                      if (filter.kind === 'folder' && filter.id === id) setFilter({ kind: 'all' });
                      toast(t('Ordner gelöscht.'));
                    })
                    .catch((e) => toast(errorText(e), 'error'));
                }}
              >
                {t('Löschen')}
              </button>
              <button className="primary" data-autofocus onClick={() => setFolderToDelete(null)}>
                {t('Abbrechen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t('„{name}“ verschwindet. Die Einträge darin bleiben – dann ohne Ordner.', {
              name: folderToDelete.name,
            })}
          </p>
        </Modal>
      )}

      {editing && (
        <ItemEditor
          key={editing.summary?.id ?? `new-${editing.kind}`}
          summary={editing.summary}
          kind={editing.kind}
          overview={overview}
          onClose={() => setEditing(null)}
          onSaved={(id) => {
            setEditing(null);
            setSelected(id);
            void reload();
          }}
        />
      )}
    </div>
  );
}

function FolderDialog({
  folder,
  onClose,
  onSaved,
}: {
  folder: { id: string | null; name: string };
  onClose: () => void;
  onSaved: () => void;
}) {
  useLanguage();
  const [name, setName] = useState(folder.name);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    try {
      await saveFolder(folder.id, name.trim());
      onSaved();
    } catch (e) {
      toast(errorText(e), 'error');
      setBusy(false);
    }
  };
  return (
    <Modal
      title={folder.id ? t('Ordner umbenennen') : t('Neuer Ordner')}
      onCancel={onClose}
      footer={
        <>
          <button className="quiet" data-secondary onClick={onClose}>
            {t('Abbrechen')}
          </button>
          <span className="spacer" />
          <button className="primary" disabled={!name.trim() || busy} onClick={() => void save()}>
            {folder.id ? t('Übernehmen') : t('Anlegen')}
          </button>
        </>
      }
    >
      <label className="field">
        <span>{t('Name')}</span>
        <input
          type="text"
          value={name}
          maxLength={100}
          autoFocus
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void save()}
        />
      </label>
    </Modal>
  );
}
