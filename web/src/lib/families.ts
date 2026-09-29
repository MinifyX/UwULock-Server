/**
 * Families (docs/uwu-api.md §16): Bitwarden's organisation API, with the keys made and wrapped
 * in the WebAssembly module. The family key never leaves it: collection names are encrypted
 * and opened in there, and a member being confirmed gets it wrapped for their public key — after
 * the owner compared the fingerprint phrase.
 */

import { currentProfile, sync } from './api';
import { call, callJson } from './web/core';
import { request } from './web/http';

type List<T> = { data: T[] };

export const OWNER = 0;
export const MEMBER = 2;

export const STATUS = { invited: 0, accepted: 1, confirmed: 2 } as const;

/** A family (or organisation) the account is in, from the profile of the last sync. */
export type Family = {
  id: string;
  name: string;
  /** The account's role in it: 0 owner, 2 member (others in Stufe 5's organisations). */
  type: number;
  status: number;
  family: boolean;
  seats: number | null;
};

export type Access = { id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean };

export type Member = {
  id: string;
  userId: string | null;
  type: number;
  status: number;
  name: string | null;
  email: string;
  twoFactorEnabled: boolean;
  collections: Access[];
};

export type CollectionDetails = {
  id: string;
  organizationId: string;
  name: string;
  users: Access[];
  assigned: boolean;
  readOnly: boolean;
  manage: boolean;
};

export type Invitation = {
  id: string;
  organizationId: string;
  organizationName: string;
  family: boolean;
  creationDate: string;
};

/** The families of the account, as the last sync has them. */
export function families(): Family[] {
  const list = (currentProfile()?.organizations ?? []) as Record<string, unknown>[];
  return list.map((org) => ({
    id: String(org.id),
    name: String(org.name ?? ''),
    type: Number(org.type),
    status: Number(org.status),
    family: Number(org.planType) === 22,
    seats: typeof org.seats === 'number' ? org.seats : null,
  }));
}

/** Whether the account manages `family`: a confirmed owner of a family. */
export const manages = (family: Family | undefined) =>
  !!family && family.family && family.type === OWNER && family.status === STATUS.confirmed;

async function changed<T>(work: Promise<T>): Promise<T> {
  const result = await work;
  await sync().catch(() => undefined);
  return result;
}

const base = (orgId: string) => `/api/organizations/${encodeURIComponent(orgId)}`;

export async function createFamily(name: string, collection: string): Promise<string> {
  const body = await callJson<Record<string, unknown>>((core) =>
    core.newFamily(name.trim(), collection.trim()),
  );
  const made = await changed(request<{ id: string }>('/api/organizations', { body }));
  return made.id;
}

export const renameFamily = (orgId: string, name: string) =>
  changed(request(base(orgId), { method: 'PUT', body: { name: name.trim() } }));

export async function deleteFamily(orgId: string, password: string) {
  const masterPasswordHash = await call((core) => core.passwordHash(password));
  await changed(request(base(orgId), { method: 'DELETE', body: { masterPasswordHash } }));
}

export const leaveFamily = (orgId: string) =>
  changed(request(`${base(orgId)}/leave`, { method: 'POST' }));

// ── Members ───────────────────────────────────────────────

export const members = async (orgId: string) =>
  (await request<List<Member>>(`${base(orgId)}/users?includeCollections=true`)).data;

export const inviteMembers = (
  orgId: string,
  emails: string[],
  type: number,
  collections: Access[],
) =>
  request(`${base(orgId)}/users/invite`, {
    body: { emails, type, collections: type === OWNER ? [] : collections, groups: [] },
  });

export const reinviteMember = (orgId: string, id: string) =>
  request(`${base(orgId)}/users/${encodeURIComponent(id)}/reinvite`, { method: 'POST' });

export const removeMember = (orgId: string, id: string) =>
  changed(request(`${base(orgId)}/users/${encodeURIComponent(id)}`, { method: 'DELETE' }));

export const updateMember = (orgId: string, id: string, type: number, collections: Access[]) =>
  changed(
    request(`${base(orgId)}/users/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: { type, collections: type === OWNER ? [] : collections, groups: [] },
    }),
  );

/** A member's public key, and its fingerprint phrase for the owner to compare. */
export async function memberKey(
  orgId: string,
  member: Member,
): Promise<{ publicKey: string; phrase: string }> {
  const keys = await request<List<{ id: string; userId: string; key: string }>>(
    `${base(orgId)}/users/public-keys`,
    { body: { ids: [member.id] } },
  );
  const found = keys.data.find((entry) => entry.id === member.id);
  if (!found)
    throw { kind: 'not-found', message: 'This member has no key yet. Ask them to log in once.' };
  const phrase = await call((core) => core.fingerprint(found.userId, found.key));
  return { publicKey: found.key, phrase };
}

/** Confirm a member: the family key, wrapped for the public key whose phrase was compared. */
export async function confirmMember(orgId: string, id: string, publicKey: string) {
  const key = await call((core) => core.wrapFamilyKey(orgId, publicKey));
  await changed(
    request(`${base(orgId)}/users/${encodeURIComponent(id)}/confirm`, { body: { key } }),
  );
}

// ── Collections ───────────────────────────────────────────

/** The family's collections the account sees, their names opened. */
export async function collectionsOf(orgId: string): Promise<CollectionDetails[]> {
  const list = await request<List<CollectionDetails>>(`${base(orgId)}/collections/details`);
  const opened: CollectionDetails[] = [];
  for (const collection of list.data) {
    const name = await call((core) => core.familyDecrypt(orgId, collection.name)).catch(() => '?');
    opened.push({ ...collection, name });
  }
  return opened.sort((a, b) => a.name.localeCompare(b.name));
}

export async function saveCollection(
  orgId: string,
  id: string | null,
  name: string,
  users: Access[] | null,
) {
  const encrypted = await call((core) => core.familyEncrypt(orgId, name.trim()));
  const body: Record<string, unknown> = { name: encrypted, externalId: null, groups: [] };
  if (users) body.users = users;
  await changed(
    id
      ? request(`${base(orgId)}/collections/${encodeURIComponent(id)}`, { method: 'PUT', body })
      : request(`${base(orgId)}/collections`, { body }),
  );
}

export const deleteCollection = (orgId: string, id: string) =>
  changed(request(`${base(orgId)}/collections/${encodeURIComponent(id)}`, { method: 'DELETE' }));

// ── Invitations to this account ───────────────────────────

export const pendingInvitations = async () =>
  (await request<List<Invitation>>('/uwu/v1/organizations/invitations')).data;

/** Take an invitation: from the mail's link (with its token) or from the list (without). */
export const acceptInvitation = (orgId: string, id: string, token = '') =>
  changed(
    request(`${base(orgId)}/users/${encodeURIComponent(id)}/accept`, {
      body: { token: token || null, resetPasswordKey: null },
    }),
  );

export const declineInvitation = (id: string) =>
  request(`/uwu/v1/organizations/invitations/${encodeURIComponent(id)}`, { method: 'DELETE' });

// ── Items ─────────────────────────────────────────────────

/** Move a personal item into a family's collections, encrypted anew for the family. */
export async function shareItem(itemId: string, orgId: string, collectionIds: string[]) {
  const body = await callJson<Record<string, unknown>>((core) =>
    core.shareToFamily(itemId, orgId, JSON.stringify(collectionIds)),
  );
  await changed(
    request(`/api/ciphers/${encodeURIComponent(itemId)}/share`, { method: 'PUT', body }),
  );
}

/** The collections a family's item is in (those the account may change). */
export const setItemCollections = (itemId: string, collectionIds: string[]) =>
  changed(
    request(`/api/ciphers/${encodeURIComponent(itemId)}/collections_v2`, {
      method: 'PUT',
      body: { collectionIds },
    }),
  );

/** The collections of `orgId` the account may put items into. */
export async function writableCollections(orgId: string): Promise<CollectionDetails[]> {
  const family = families().find((entry) => entry.id === orgId);
  const all = await collectionsOf(orgId);
  return family?.type === OWNER ? all : all.filter((c) => c.assigned && !c.readOnly);
}
