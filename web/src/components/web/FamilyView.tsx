import { useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { errorText } from '../../lib/errors';
import {
  MEMBER,
  OWNER,
  STATUS,
  collectionsOf,
  confirmMember,
  createFamily,
  deleteCollection,
  deleteFamily,
  families,
  inviteMembers,
  leaveFamily,
  manages,
  memberKey,
  members,
  reinviteMember,
  removeMember,
  renameFamily,
  saveCollection,
  updateMember,
  type Access,
  type CollectionDetails,
  type Member,
} from '../../lib/families';
import { N_, t, useLanguage } from '../../lib/i18n';
import { toast } from '../../lib/toast';
import { Icon } from '../Icon';
import { Modal } from '../Modal';
import { BackToList, Panes } from '../panes';
import { Badge, Tabs } from '../ui';
import { PasswordPrompt } from './controls';

/** What one member may do with one collection: nothing, read, or read and write. */
type Right = 'none' | 'read' | 'write';

const RIGHTS: { value: Right; label: string }[] = [
  { value: 'none', label: N_('Kein Zugriff') },
  { value: 'read', label: N_('Nur lesen') },
  { value: 'write', label: N_('Lesen und ändern') },
];

const rightOf = (access: Access | undefined): Right =>
  !access ? 'none' : access.readOnly ? 'read' : 'write';

const accessFor = (id: string, right: Right): Access | null =>
  right === 'none' ? null : { id, readOnly: right === 'read', hidePasswords: false, manage: false };

const STATUS_LABEL: Record<number, string> = {
  [STATUS.invited]: N_('Eingeladen'),
  [STATUS.accepted]: N_('Angenommen – bestätigen'),
  [STATUS.confirmed]: N_('Bestätigt'),
};

const who = (member: Member) => member.name || member.email;

type Dialog =
  | { kind: 'invite' }
  | { kind: 'confirm'; member: Member; publicKey: string; phrase: string }
  | { kind: 'collection'; collection: CollectionDetails | null }
  | { kind: 'rename' }
  | { kind: 'delete' }
  | { kind: 'leave' }
  | { kind: 'remove'; member: Member }
  | { kind: 'delete-collection'; collection: CollectionDetails }
  | null;

/**
 * A family's page (route `#/organizations/<id>`): its members and collections. Owners invite,
 * confirm with the fingerprint phrase, give each member read or write access per collection,
 * and make, rename and delete collections; every member sees who is in it and may leave.
 */
export function FamilyView({ orgId, onGone }: { orgId: string; onGone: () => void }) {
  useLanguage();
  const family = families().find((entry) => entry.id === orgId);
  const owner = manages(family);
  const [tab, setTab] = useState<'members' | 'collections'>('members');
  const [people, setPeople] = useState<Member[] | null>(null);
  const [collections, setCollections] = useState<CollectionDetails[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const { showDetail } = useContext(Panes);

  const reload = useCallback(async () => {
    try {
      const [list, cols] = await Promise.all([members(orgId), collectionsOf(orgId)]);
      setPeople(list);
      setCollections(cols);
    } catch (e) {
      toast(errorText(e), 'error');
      setPeople([]);
    }
  }, [orgId]);
  useEffect(() => void reload(), [reload]);

  const act = async (work: () => Promise<unknown>, done: string) => {
    try {
      await work();
      toast(done);
      await reload();
    } catch (e) {
      toast(errorText(e), 'error');
    }
  };

  const sortedPeople = useMemo(
    () =>
      [...(people ?? [])].sort(
        (a, b) => a.type - b.type || a.status - b.status || who(a).localeCompare(who(b)),
      ),
    [people],
  );
  const currentMember =
    tab === 'members'
      ? (sortedPeople.find((m) => m.id === selected) ?? sortedPeople[0] ?? null)
      : null;
  const currentCollection =
    tab === 'collections'
      ? (collections.find((c) => c.id === selected) ?? collections[0] ?? null)
      : null;
  const waiting = (people ?? []).filter((m) => m.status === STATUS.accepted).length;

  if (!family)
    return (
      <section className="list-pane">
        <div className="list-empty">
          <p>{t('Diese Familie gibt es nicht (mehr), oder du bist nicht darin.')}</p>
        </div>
      </section>
    );

  return (
    <>
      <section className="list-pane" aria-label={family.name}>
        <div className="list-head">
          <p className="list-title">
            <span>{family.name}</span>
            <span className="list-count">{people?.length ?? ''}</span>
            <span className="spacer" />
            {owner && tab === 'members' && (
              <button className="new-item" onClick={() => setDialog({ kind: 'invite' })}>
                <Icon name="plus" size={15} />
                {t('Einladen')}
              </button>
            )}
            {owner && tab === 'collections' && (
              <button
                className="new-item"
                onClick={() => setDialog({ kind: 'collection', collection: null })}
              >
                <Icon name="plus" size={15} />
                {t('Neu')}
              </button>
            )}
          </p>
          <Tabs
            variant="segmented"
            label={t('Ansicht')}
            value={tab}
            onChange={(next) => {
              setTab(next);
              setSelected(null);
            }}
            tabs={[
              {
                id: 'members',
                label: t('Mitglieder'),
                extra: waiting > 0 && owner && <Badge>{waiting}</Badge>,
              },
              { id: 'collections', label: t('Sammlungen') },
            ]}
          />
        </div>

        {tab === 'members' ? (
          <ul className="item-list" role="listbox" aria-label={t('Mitglieder')}>
            {sortedPeople.map((member) => (
              <li
                key={member.id}
                role="option"
                aria-selected={member.id === currentMember?.id}
                className="item-row"
                onClick={() => {
                  setSelected(member.id);
                  showDetail();
                }}
              >
                <span className="item-tile" data-hue={member.type === OWNER ? '2' : '5'}>
                  <Icon name={member.type === OWNER ? 'crown' : 'user'} size={18} />
                </span>
                <span className="item-text">
                  <span className="item-name">{who(member)}</span>
                  <span className="item-sub">
                    {member.type === OWNER ? t('Eigentümer') : t('Mitglied')} ·{' '}
                    {t(STATUS_LABEL[member.status] ?? '')}
                  </span>
                </span>
                <span className="item-badges">
                  {member.status === STATUS.accepted && owner && (
                    <Icon name="bell" size={13} title={t('Wartet auf Bestätigung')} />
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : collections.length ? (
          <ul className="item-list" role="listbox" aria-label={t('Sammlungen')}>
            {collections.map((collection) => (
              <li
                key={collection.id}
                role="option"
                aria-selected={collection.id === currentCollection?.id}
                className="item-row"
                onClick={() => {
                  setSelected(collection.id);
                  showDetail();
                }}
              >
                <span className="item-tile" data-hue="3">
                  <Icon name="grid" size={18} />
                </span>
                <span className="item-text">
                  <span className="item-name">{collection.name}</span>
                  <span className="item-sub">
                    {owner
                      ? t('{n} Mitglieder mit Zugriff', { n: collection.users.length })
                      : collection.readOnly
                        ? t('Nur lesen')
                        : t('Lesen und ändern')}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="list-empty">
            <p>{t('Noch keine Sammlungen.')}</p>
          </div>
        )}

        <div className="family-actions">
          {owner && (
            <button className="quiet" onClick={() => setDialog({ kind: 'rename' })}>
              <Icon name="pencil" size={14} />
              {t('Umbenennen')}
            </button>
          )}
          <button className="quiet" onClick={() => setDialog({ kind: 'leave' })}>
            <Icon name="logout" size={14} />
            {t('Verlassen')}
          </button>
          {owner && (
            <button className="quiet danger-text" onClick={() => setDialog({ kind: 'delete' })}>
              <Icon name="trash" size={14} />
              {t('Familie löschen')}
            </button>
          )}
        </div>
      </section>

      <section className="detail-pane">
        <BackToList />
        {currentMember ? (
          <MemberDetail
            key={currentMember.id}
            orgId={orgId}
            member={currentMember}
            collections={collections}
            owner={owner}
            onConfirm={() =>
              void memberKey(orgId, currentMember).then(
                (key) => setDialog({ kind: 'confirm', member: currentMember, ...key }),
                (e) => toast(errorText(e), 'error'),
              )
            }
            onReinvite={() =>
              void act(
                () => reinviteMember(orgId, currentMember.id),
                t('Einladung neu verschickt.'),
              )
            }
            onRemove={() => setDialog({ kind: 'remove', member: currentMember })}
            onSaved={() => void reload()}
          />
        ) : currentCollection ? (
          <CollectionDetail
            key={currentCollection.id}
            orgId={orgId}
            collection={currentCollection}
            people={sortedPeople}
            owner={owner}
            onRename={() => setDialog({ kind: 'collection', collection: currentCollection })}
            onDelete={() => setDialog({ kind: 'delete-collection', collection: currentCollection })}
            onSaved={() => void reload()}
          />
        ) : (
          <div className="detail-empty" />
        )}
      </section>

      {dialog?.kind === 'invite' && (
        <InviteDialog
          orgId={orgId}
          collections={collections}
          seats={family.seats}
          taken={people?.length ?? 0}
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            void reload();
          }}
        />
      )}
      {dialog?.kind === 'confirm' && (
        <Modal
          title={t('Mitglied bestätigen')}
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="primary"
                onClick={() => {
                  const { member, publicKey } = dialog;
                  setDialog(null);
                  void act(() => confirmMember(orgId, member.id, publicKey), t('Bestätigt ✧'));
                }}
              >
                {t('Bestätigen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Vergleiche diesen Satz mit {who}. Er steht in deren Einstellungen unter Konto → Fingerabdruck. Nur wenn er gleich ist, bestätige: Dann bekommt genau diese Person den Schlüssel der Familie.',
              { who: who(dialog.member) },
            )}
          </p>
          <p className="fingerprint">{dialog.phrase}</p>
        </Modal>
      )}
      {dialog?.kind === 'collection' && (
        <CollectionDialog
          orgId={orgId}
          collection={dialog.collection}
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null);
            void reload();
          }}
        />
      )}
      {dialog?.kind === 'rename' && (
        <NameDialog
          title={t('Familie umbenennen')}
          label={t('Name der Familie')}
          initial={family.name}
          max={50}
          onClose={() => setDialog(null)}
          onSave={async (name) => {
            await renameFamily(orgId, name);
            setDialog(null);
            toast(t('Umbenannt ✧'));
          }}
        />
      )}
      {dialog?.kind === 'delete' && (
        <PasswordPrompt
          title={t('Familie löschen?')}
          tone="warning"
          lead={t(
            '„{name}“ verschwindet für alle Mitglieder, mit allen Sammlungen und allen Einträgen darin. Das lässt sich nicht rückgängig machen.',
            { name: family.name },
          )}
          confirm={t('Familie löschen')}
          onCancel={() => setDialog(null)}
          action={async (password) => {
            await deleteFamily(orgId, password);
            setDialog(null);
            toast(t('Gelöscht.'));
            onGone();
          }}
        />
      )}
      {dialog?.kind === 'leave' && (
        <Modal
          title={t('Familie verlassen?')}
          tone="warning"
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  setDialog(null);
                  void leaveFamily(orgId).then(
                    () => {
                      toast(t('Du bist nicht mehr in der Familie.'));
                      onGone();
                    },
                    (e) => toast(errorText(e), 'error'),
                  );
                }}
              >
                {t('Verlassen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              'Was in „{name}“ geteilt ist, verschwindet aus deinem Tresor. Zurück kommst du nur mit einer neuen Einladung.',
              { name: family.name },
            )}
          </p>
        </Modal>
      )}
      {dialog?.kind === 'remove' && (
        <Modal
          title={t('Aus der Familie nehmen?')}
          tone="warning"
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  const id = dialog.member.id;
                  setDialog(null);
                  setSelected(null);
                  void act(() => removeMember(orgId, id), t('Entfernt.'));
                }}
              >
                {t('Entfernen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              '{who} sieht danach nichts mehr aus der Familie. Was schon auf ihren Geräten war, kann noch dort sein, bis sie synchronisieren – ändere wichtige Passwörter, wenn nötig.',
              { who: who(dialog.member) },
            )}
          </p>
        </Modal>
      )}
      {dialog?.kind === 'delete-collection' && (
        <Modal
          title={t('Sammlung löschen?')}
          tone="warning"
          onCancel={() => setDialog(null)}
          footer={
            <>
              <span className="spacer" />
              <button data-secondary onClick={() => setDialog(null)}>
                {t('Abbrechen')}
              </button>
              <button
                className="danger"
                onClick={() => {
                  const id = dialog.collection.id;
                  setDialog(null);
                  setSelected(null);
                  void act(() => deleteCollection(orgId, id), t('Gelöscht.'));
                }}
              >
                {t('Löschen')}
              </button>
            </>
          }
        >
          <p className="dialog-lead">
            {t(
              '„{name}“ verschwindet. Die Einträge darin bleiben in der Familie, sichtbar nur noch für die Eigentümer, bis sie in eine andere Sammlung kommen.',
              { name: dialog.collection.name },
            )}
          </p>
        </Modal>
      )}
    </>
  );
}

function RightSelect({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: Right;
  onChange: (right: Right) => void;
  disabled?: boolean;
}) {
  return (
    <select
      className="select"
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value as Right)}
    >
      {RIGHTS.map((right) => (
        <option key={right.value} value={right.value}>
          {t(right.label)}
        </option>
      ))}
    </select>
  );
}

function MemberDetail({
  orgId,
  member,
  collections,
  owner,
  onConfirm,
  onReinvite,
  onRemove,
  onSaved,
}: {
  orgId: string;
  member: Member;
  collections: CollectionDetails[];
  owner: boolean;
  onConfirm: () => void;
  onReinvite: () => void;
  onRemove: () => void;
  onSaved: () => void;
}) {
  useLanguage();
  const [type, setType] = useState(member.type);
  const [rights, setRights] = useState<Record<string, Right>>(() =>
    Object.fromEntries(
      collections.map((c) => [c.id, rightOf(member.collections.find((a) => a.id === c.id))]),
    ),
  );
  const [busy, setBusy] = useState(false);
  const dirty =
    type !== member.type ||
    collections.some(
      (c) => rights[c.id] !== rightOf(member.collections.find((a) => a.id === c.id)),
    );

  const saveChanges = async () => {
    setBusy(true);
    try {
      const access = collections
        .map((c) => accessFor(c.id, rights[c.id] ?? 'none'))
        .filter((a): a is Access => a !== null);
      await updateMember(orgId, member.id, type, access);
      toast(t('Gespeichert ✧'));
      onSaved();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="detail" aria-label={who(member)}>
      <header className="detail-head">
        <span className="item-tile" data-size="large" data-hue={member.type === OWNER ? '2' : '5'}>
          <Icon name={member.type === OWNER ? 'crown' : 'user'} size={24} />
        </span>
        <div className="detail-title">
          <h2>{who(member)}</h2>
          <p className="chips">
            <span className="chip">{member.type === OWNER ? t('Eigentümer') : t('Mitglied')}</span>
            <span className="chip">{t(STATUS_LABEL[member.status] ?? '')}</span>
            {member.twoFactorEnabled && (
              <span className="chip">
                <Icon name="shield" size={12} />
                {t('Zwei-Schritt-Anmeldung')}
              </span>
            )}
          </p>
        </div>
        {owner && (
          <div className="detail-tools">
            {member.status === STATUS.accepted && (
              <button className="primary" onClick={onConfirm}>
                <Icon name="check" size={15} />
                {t('Bestätigen …')}
              </button>
            )}
            {member.status === STATUS.invited && (
              <button className="quiet" onClick={onReinvite}>
                <Icon name="send" size={15} />
                {t('Nochmal einladen')}
              </button>
            )}
            <button className="quiet danger-text" onClick={onRemove}>
              <Icon name="trash" size={15} />
              {t('Entfernen')}
            </button>
          </div>
        )}
      </header>

      {member.name && (
        <section className="detail-card">
          <div className="detail-row">
            <div className="detail-text">
              <span className="detail-label">{t('E-Mail')}</span>
              <span className="detail-value">{member.email}</span>
            </div>
          </div>
        </section>
      )}

      {member.status === STATUS.invited && (
        <p className="empty-note">
          {t(
            'Die Einladung ist unterwegs. Hat die Person noch kein Konto, legt sie es mit dem Link aus der Mail an – sofern du Leute auf diesen Server einladen darfst.',
          )}
        </p>
      )}
      {member.status === STATUS.accepted && owner && (
        <p className="empty-note">
          {t(
            'Angenommen. Bestätige das Mitglied, nachdem ihr den Fingerabdruck-Satz verglichen habt – erst dann sieht es, was die Familie teilt.',
          )}
        </p>
      )}

      {owner && (
        <>
          <h3 className="detail-subhead">{t('Rolle')}</h3>
          <section className="detail-card">
            <div className="detail-row">
              <div className="detail-text">
                <span className="detail-label">{t('Rolle in der Familie')}</span>
                <span className="detail-value">
                  {t('Eigentümer verwalten Mitglieder und Sammlungen und sehen alles.')}
                </span>
              </div>
              <select
                className="select"
                aria-label={t('Rolle in der Familie')}
                value={type}
                onChange={(e) => setType(Number(e.target.value))}
              >
                <option value={MEMBER}>{t('Mitglied')}</option>
                <option value={OWNER}>{t('Eigentümer')}</option>
              </select>
            </div>
          </section>

          {type !== OWNER && (
            <>
              <h3 className="detail-subhead">{t('Sammlungen')}</h3>
              <section className="detail-card">
                {collections.length === 0 && (
                  <p className="detail-line">{t('Noch keine Sammlungen.')}</p>
                )}
                {collections.map((collection) => (
                  <div key={collection.id} className="detail-row">
                    <div className="detail-text">
                      <span className="detail-value">{collection.name}</span>
                    </div>
                    <RightSelect
                      label={t('Zugriff auf {name}', { name: collection.name })}
                      value={rights[collection.id] ?? 'none'}
                      onChange={(right) => setRights({ ...rights, [collection.id]: right })}
                    />
                  </div>
                ))}
              </section>
            </>
          )}
          <p className="family-save">
            <button
              className="primary"
              disabled={!dirty || busy}
              onClick={() => void saveChanges()}
            >
              {t('Speichern')}
            </button>
          </p>
        </>
      )}
    </article>
  );
}

function CollectionDetail({
  orgId,
  collection,
  people,
  owner,
  onRename,
  onDelete,
  onSaved,
}: {
  orgId: string;
  collection: CollectionDetails;
  people: Member[];
  owner: boolean;
  onRename: () => void;
  onDelete: () => void;
  onSaved: () => void;
}) {
  useLanguage();
  const others = people.filter((m) => m.type !== OWNER);
  const [rights, setRights] = useState<Record<string, Right>>(() =>
    Object.fromEntries(
      others.map((m) => [m.id, rightOf(collection.users.find((a) => a.id === m.id))]),
    ),
  );
  const [busy, setBusy] = useState(false);
  const dirty = others.some(
    (m) => rights[m.id] !== rightOf(collection.users.find((a) => a.id === m.id)),
  );

  const saveChanges = async () => {
    setBusy(true);
    try {
      const users = others
        .map((m) => accessFor(m.id, rights[m.id] ?? 'none'))
        .filter((a): a is Access => a !== null);
      await saveCollection(orgId, collection.id, collection.name, users);
      toast(t('Gespeichert ✧'));
      onSaved();
    } catch (e) {
      toast(errorText(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="detail" aria-label={collection.name}>
      <header className="detail-head">
        <span className="item-tile" data-size="large" data-hue="3">
          <Icon name="grid" size={24} />
        </span>
        <div className="detail-title">
          <h2>{collection.name}</h2>
          <p className="chips">
            <span className="chip">{t('Sammlung')}</span>
          </p>
        </div>
        {owner && (
          <div className="detail-tools">
            <button className="quiet" onClick={onRename}>
              <Icon name="pencil" size={15} />
              {t('Umbenennen')}
            </button>
            <button className="quiet danger-text" onClick={onDelete}>
              <Icon name="trash" size={15} />
              {t('Löschen')}
            </button>
          </div>
        )}
      </header>
      {owner ? (
        <>
          <h3 className="detail-subhead">{t('Wer darf was')}</h3>
          <section className="detail-card">
            <p className="detail-line">{t('Eigentümer sehen und ändern alles.')}</p>
            {others.map((member) => (
              <div key={member.id} className="detail-row">
                <div className="detail-text">
                  <span className="detail-value">{who(member)}</span>
                </div>
                <RightSelect
                  label={t('Zugriff für {who}', { who: who(member) })}
                  value={rights[member.id] ?? 'none'}
                  onChange={(right) => setRights({ ...rights, [member.id]: right })}
                />
              </div>
            ))}
          </section>
          <p className="family-save">
            <button
              className="primary"
              disabled={!dirty || busy}
              onClick={() => void saveChanges()}
            >
              {t('Speichern')}
            </button>
          </p>
        </>
      ) : (
        <p className="empty-note">
          {collection.readOnly
            ? t('Du kannst die Einträge dieser Sammlung lesen, aber nicht ändern.')
            : t('Du kannst Einträge in dieser Sammlung lesen, ändern und neue hineinlegen.')}
        </p>
      )}
    </article>
  );
}

function InviteDialog({
  orgId,
  collections,
  seats,
  taken,
  onClose,
  onDone,
}: {
  orgId: string;
  collections: CollectionDetails[];
  seats: number | null;
  taken: number;
  onClose: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [emails, setEmails] = useState('');
  const [type, setType] = useState(MEMBER);
  const [rights, setRights] = useState<Record<string, Right>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = emails
    .split(/[\s,;]+/)
    .map((email) => email.trim())
    .filter(Boolean);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const access = collections
        .map((c) => accessFor(c.id, rights[c.id] ?? 'none'))
        .filter((a): a is Access => a !== null);
      await inviteMembers(orgId, list, type, access);
      toast(t('Eingeladen ✧'));
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('In die Familie einladen')}
      size="wide"
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="primary" onClick={() => void submit()} disabled={busy || !list.length}>
            {t('Einladen')}
          </button>
        </>
      }
    >
      <div className="form">
        <p className="dialog-lead">
          {seats !== null
            ? t(
                'Eine Familie hat auf diesem Server höchstens {seats} Mitglieder; {taken} Plätze sind vergeben (Eingeladene zählen mit). Wer schon ein Konto hat, nimmt die Einladung an; wer noch keins hat, legt es mit dem Link an, wenn du Leute einladen darfst.',
                { seats, taken },
              )
            : t('Wer schon ein Konto hat, nimmt die Einladung an.')}
        </p>
        <label className="field">
          <span>{t('E-Mail-Adressen')}</span>
          <textarea
            value={emails}
            rows={3}
            autoFocus
            placeholder="mio@example.com"
            onChange={(e) => setEmails(e.target.value)}
          />
        </label>
        <label className="field">
          <span>{t('Rolle')}</span>
          <select className="select" value={type} onChange={(e) => setType(Number(e.target.value))}>
            <option value={MEMBER}>{t('Mitglied')}</option>
            <option value={OWNER}>{t('Eigentümer')}</option>
          </select>
        </label>
        {type !== OWNER && collections.length > 0 && (
          <fieldset className="field">
            <legend>{t('Sammlungen')}</legend>
            {collections.map((collection) => (
              <div key={collection.id} className="detail-row">
                <span className="detail-value">{collection.name}</span>
                <RightSelect
                  label={t('Zugriff auf {name}', { name: collection.name })}
                  value={rights[collection.id] ?? 'none'}
                  onChange={(right) => setRights({ ...rights, [collection.id]: right })}
                />
              </div>
            ))}
          </fieldset>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

function CollectionDialog({
  orgId,
  collection,
  onClose,
  onDone,
}: {
  orgId: string;
  collection: CollectionDetails | null;
  onClose: () => void;
  onDone: () => void;
}) {
  useLanguage();
  return (
    <NameDialog
      title={collection ? t('Sammlung umbenennen') : t('Neue Sammlung')}
      label={t('Name der Sammlung')}
      initial={collection?.name ?? ''}
      max={100}
      onClose={onClose}
      onSave={async (name) => {
        await saveCollection(orgId, collection?.id ?? null, name, collection ? null : []);
        toast(collection ? t('Umbenannt ✧') : t('Angelegt ✧'));
        onDone();
      }}
    />
  );
}

/** A name to type, for a family or a collection. */
export function NameDialog({
  title,
  label,
  initial,
  max,
  onClose,
  onSave,
  children,
}: {
  title: string;
  label: string;
  initial: string;
  max: number;
  onClose: () => void;
  onSave: (name: string) => Promise<void>;
  children?: ReactNode;
}) {
  useLanguage();
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSave(name.trim());
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button className="primary" disabled={!name.trim() || busy} onClick={() => void submit()}>
            {t('Übernehmen')}
          </button>
        </>
      }
    >
      <div className="form">
        {children}
        <label className="field">
          <span>{label}</span>
          <input
            type="text"
            value={name}
            maxLength={max}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}

/** A new family: its name and its first collection. */
export function NewFamilyDialog({
  maxMembers,
  onClose,
  onDone,
}: {
  maxMembers: number;
  onClose: () => void;
  onDone: (id: string) => void;
}) {
  useLanguage();
  const [name, setName] = useState('');
  const [collection, setCollection] = useState(t('Allgemein'));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if (!name.trim() || !collection.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      onDone(await createFamily(name, collection));
      toast(t('Familie angelegt ✧'));
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Neue Familie')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          <button data-secondary onClick={onClose} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            className="primary"
            disabled={!name.trim() || !collection.trim() || busy}
            onClick={() => void submit()}
          >
            {busy ? t('Nyu macht die Schlüssel …') : t('Anlegen')}
          </button>
        </>
      }
    >
      <div className="form">
        <p className="dialog-lead">
          {t(
            'Teilt Passwörter und mehr mit bis zu {n} Menschen, verschlüsselt mit einem eigenen Schlüssel der Familie. Du bist Eigentümer und lädst die anderen ein.',
            { n: maxMembers },
          )}
        </p>
        <label className="field">
          <span>{t('Name der Familie')}</span>
          <input
            type="text"
            value={name}
            maxLength={50}
            autoFocus
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label className="field">
          <span>{t('Erste Sammlung')}</span>
          <input
            type="text"
            value={collection}
            maxLength={100}
            onChange={(e) => setCollection(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void submit()}
          />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  );
}
