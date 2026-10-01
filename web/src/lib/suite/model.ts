/**
 * UwUSSH's and UwURDP's records as the web vault shows and changes them (docs/uwu-api.md §6):
 * what points at what, what a delete takes along, the extras of a host (its command, an `.rdp`
 * file, the link into the app) and how an edit lands on a record that changed meanwhile.
 *
 * Payloads are the apps' JSON (snake_case, `uwussh-proto`/`uwurdp-proto` `entities.rs`). The
 * web vault never round-trips them through a type of its own: an edit changes the fields it
 * touched and keeps every other one, also those a newer app added.
 */

export type SpaceName = 'ssh' | 'rdp';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Payload = { [key: string]: Json };

/** A record as `suiteRecords` gives it: no secret's content, no tombstones, no manifests. */
export type SuiteRecord = {
  id: string;
  kind: string;
  seq: number;
  updatedAt: { wallMs: number; counter: number; device: number };
  /** Every kind but `secret`. */
  payload?: Payload;
};

/** The kinds the web vault shows, in the order of its tabs. Others pass through unseen. */
export type ShownKind =
  'host' | 'group' | 'identity' | 'key' | 'snippet' | 'port_forward' | 'known_host';

export const KINDS: Record<SpaceName, ShownKind[]> = {
  ssh: ['host', 'group', 'identity', 'key', 'snippet', 'port_forward', 'known_host'],
  rdp: ['host', 'group', 'identity'],
};

/** UwURDP knows these too but has nothing for them yet: shown only when a record is there. */
export const RDP_EXTRA_KINDS: ShownKind[] = ['key', 'snippet', 'known_host'];

export const WORKSPACES = ['private', 'business'] as const;
export const AUTH_TYPES = ['password', 'key', 'agent', 'keyboard-interactive', 'cert'] as const;

export const DEFAULT_PORT: Record<SpaceName, number> = { ssh: 22, rdp: 3389 };

/** UwURDP's `RdpSettings::default()`. */
export const RDP_DEFAULTS: Payload = {
  display: 'fit',
  width: 1920,
  height: 1080,
  smartSizing: true,
  colorDepth: 32,
  audio: 'local',
  clipboard: true,
  admin: false,
  nla: true,
  wallpaper: true,
  graphicsPipeline: true,
};

export const str = (value: Json | undefined): string => (typeof value === 'string' ? value : '');
export const num = (value: Json | undefined, fallback = 0): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;
export const bool = (value: Json | undefined, fallback = false): boolean =>
  typeof value === 'boolean' ? value : fallback;
export const obj = (value: Json | undefined): Payload | null =>
  value && typeof value === 'object' && !Array.isArray(value) ? value : null;
/** A uuid field (`group_id`, …), `null` when unset. */
export const ref = (value: Json | undefined): string | null =>
  typeof value === 'string' && value ? value : null;

/** What a new record of a kind starts as: every field the apps require. */
export function blank(space: SpaceName, kind: ShownKind, position = 0): Payload {
  switch (kind) {
    case 'host':
      return {
        name: '',
        address: '',
        port: DEFAULT_PORT[space],
        workspace: 'private',
        position,
        group_id: null,
        identity_id: null,
        ...(space === 'rdp' ? { rdp: { ...RDP_DEFAULTS } } : {}),
      };
    case 'group':
      return { workspace: 'private', name: '', position };
    case 'identity':
      return {
        label: '',
        username: '',
        auth_type: 'password',
        key_id: null,
        password_secret_id: null,
      };
    case 'key':
      return {
        label: '',
        key_type: 'ssh-ed25519',
        public_key: '',
        private_secret_id: null,
        passphrase_secret_id: null,
      };
    case 'snippet':
      return { label: '', body: '', group_path: null };
    case 'port_forward':
      return {
        host_id: null,
        name: '',
        kind: 'local',
        bind_address: '127.0.0.1',
        bind_port: 8080,
        target_host: 'localhost',
        target_port: 80,
        autostart: false,
      };
    case 'known_host':
      return {};
  }
}

function same(a: Json | undefined, b: Json | undefined): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/**
 * An edit, onto the record as it is now: the fields the form changed (draft against what the
 * form was opened with) go onto `latest`, everything else stays as `latest` has it. Objects
 * (`rdp`, its `gateway`) merge field by field, so a change elsewhere to another field of them
 * survives too.
 */
export function applyEdit(latest: Payload, opened: Payload, draft: Payload): Payload {
  const out: Payload = { ...latest };
  for (const key of new Set([...Object.keys(opened), ...Object.keys(draft)])) {
    const before = opened[key];
    const after = draft[key];
    if (same(before, after)) continue;
    const a = obj(before);
    const b = obj(after);
    const now = obj(latest[key]);
    if (a && b && now) out[key] = applyEdit(now, a, b);
    else if (after === undefined) delete out[key];
    else out[key] = after;
  }
  return out;
}

// ── Labels and lists ──────────────────────────────────────

/** The name a record goes by in a list. */
export function titleOf(record: SuiteRecord): string {
  const p = record.payload ?? {};
  switch (record.kind) {
    case 'host':
      return str(p.name) || str(p.address);
    case 'group':
      return str(p.name);
    case 'identity':
    case 'key':
    case 'snippet':
      return str(p.label) || (record.kind === 'identity' ? str(p.username) : '');
    case 'port_forward':
      return str(p.name) || forwardText(p);
    case 'known_host':
      return portSuffix(str(p.address), num(p.port), 22);
    default:
      return record.id;
  }
}

function portSuffix(address: string, port: number, standard: number): string {
  if (!port || port === standard) return address;
  return address.includes(':') && !address.startsWith('[')
    ? `[${address}]:${port}`
    : `${address}:${port}`;
}

/** `-L 127.0.0.1:8080 → localhost:80`. */
export function forwardText(p: Payload): string {
  const flag = str(p.kind) === 'remote' ? '-R' : str(p.kind) === 'local' ? '-L' : str(p.kind);
  return `${flag} ${str(p.bind_address)}:${num(p.bind_port)} → ${str(p.target_host)}:${num(p.target_port)}`;
}

/** The second line in a list. */
export function subtitleOf(space: SpaceName, record: SuiteRecord, all: Index): string {
  const p = record.payload ?? {};
  switch (record.kind) {
    case 'host': {
      const identity = all.get(ref(p.identity_id) ?? '');
      const user = identity ? str(identity.payload?.username) : '';
      const address = portSuffix(str(p.address), num(p.port), DEFAULT_PORT[space]);
      return user ? `${user}@${address}` : address;
    }
    case 'identity':
      return [str(p.domain), str(p.username)].filter(Boolean).join('\\');
    case 'key':
      return str(p.key_type);
    case 'snippet':
      return str(p.body).split('\n')[0] ?? '';
    case 'port_forward':
      return forwardText(p);
    case 'known_host':
      return `${str(p.algorithm)} ${str(p.fingerprint_sha256)}`.trim();
    default:
      return '';
  }
}

export type Index = Map<string, SuiteRecord>;

export function indexOf(records: SuiteRecord[]): Index {
  return new Map(records.map((r) => [r.id, r]));
}

/** Does a record match the search? Every word somewhere in its name or second line. */
export function matches(space: SpaceName, record: SuiteRecord, all: Index, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const p = record.payload ?? {};
  const text = [
    titleOf(record),
    subtitleOf(space, record, all),
    str(p.address),
    str(p.comment),
    str(p.group_path),
  ]
    .join(' ')
    .toLowerCase();
  return words.every((word) => text.includes(word));
}

const byPosition = (a: SuiteRecord, b: SuiteRecord) =>
  num(a.payload?.position) - num(b.payload?.position) ||
  titleOf(a).localeCompare(titleOf(b)) ||
  a.id.localeCompare(b.id);

export type HostSection = {
  workspace: string;
  group: SuiteRecord | null;
  hosts: SuiteRecord[];
};

/**
 * Hosts as the apps show them: per workspace, its groups in their order (a group's hosts in
 * theirs), then the hosts without a group. A workspace the build doesn't know shows as private,
 * as in the apps; a group that is gone counts as none.
 */
export function hostSections(records: SuiteRecord[]): HostSection[] {
  const groups = records.filter((r) => r.kind === 'group').sort(byPosition);
  const hosts = records.filter((r) => r.kind === 'host').sort(byPosition);
  const workspaceOf = (r: SuiteRecord) =>
    str(r.payload?.workspace) === 'business' ? 'business' : 'private';
  const known = new Set(groups.map((g) => g.id));
  const sections: HostSection[] = [];
  for (const workspace of WORKSPACES) {
    for (const group of groups.filter((g) => workspaceOf(g) === workspace)) {
      sections.push({
        workspace,
        group,
        hosts: hosts.filter((h) => ref(h.payload?.group_id) === group.id),
      });
    }
    const loose = hosts.filter(
      (h) => workspaceOf(h) === workspace && !known.has(ref(h.payload?.group_id) ?? ''),
    );
    if (loose.length) sections.push({ workspace, group: null, hosts: loose });
  }
  return sections;
}

/** The position after the last one among `siblings`. */
export function nextPosition(siblings: SuiteRecord[]): number {
  return siblings.reduce((max, r) => Math.max(max, num(r.payload?.position) + 1), 0);
}

/**
 * Moving a record one place up or down among its siblings: the edits (id → new position) that
 * put them in order 0, 1, 2, … with it moved. Empty when it is at that end already.
 */
export function move(siblings: SuiteRecord[], id: string, by: -1 | 1): Map<string, number> {
  const ordered = [...siblings].sort(byPosition);
  const at = ordered.findIndex((r) => r.id === id);
  const to = at + by;
  if (at < 0 || to < 0 || to >= ordered.length) return new Map();
  [ordered[at], ordered[to]] = [ordered[to]!, ordered[at]!];
  const edits = new Map<string, number>();
  ordered.forEach((r, position) => {
    if (num(r.payload?.position) !== position) edits.set(r.id, position);
  });
  return edits;
}

// ── What points at what ───────────────────────────────────

/** Records that point at `id`: hosts and groups at an identity, identities at a key. */
export function usersOf(records: SuiteRecord[], id: string): SuiteRecord[] {
  return records.filter((r) => {
    const p = r.payload ?? {};
    switch (r.kind) {
      case 'host':
        return ref(p.identity_id) === id || ref(p.gateway_identity_id) === id;
      case 'group':
        return ref(p.identity_id) === id;
      case 'identity':
        return ref(p.key_id) === id;
      default:
        return false;
    }
  });
}

/** The `secret` records a record owns. */
export function secretsOf(record: SuiteRecord): string[] {
  const p = record.payload ?? {};
  const ids =
    record.kind === 'identity'
      ? [ref(p.password_secret_id)]
      : record.kind === 'key'
        ? [ref(p.private_secret_id), ref(p.passphrase_secret_id)]
        : [];
  return ids.filter((id): id is string => !!id);
}

export type DeletePlan =
  | {
      ok: true;
      /** Tombstones, the record itself first. */
      tombstones: string[];
      /** Records that only change (a group's hosts lose their group). */
      edits: { id: string; payload: Payload }[];
    }
  | { ok: false; users: SuiteRecord[] };

/**
 * What deleting a record does, as the apps do it: a host takes its port forwards along; an
 * identity or a key only when nothing points at it any more, and then its secrets with it; a
 * group leaves its hosts without a group.
 */
export function deletePlan(records: SuiteRecord[], record: SuiteRecord): DeletePlan {
  const live = new Set(records.map((r) => r.id));
  switch (record.kind) {
    case 'host': {
      const forwards = records
        .filter((r) => r.kind === 'port_forward' && ref(r.payload?.host_id) === record.id)
        .map((r) => r.id);
      return { ok: true, tombstones: [record.id, ...forwards], edits: [] };
    }
    case 'identity':
    case 'key': {
      const users = usersOf(records, record.id);
      if (users.length) return { ok: false, users };
      return {
        ok: true,
        tombstones: [record.id, ...secretsOf(record).filter((id) => live.has(id))],
        edits: [],
      };
    }
    case 'group': {
      const edits = records
        .filter(
          (r) =>
            (r.kind === 'host' || r.kind === 'group') && ref(r.payload?.group_id) === record.id,
        )
        .map((r) => ({ id: r.id, payload: { ...r.payload, group_id: null } }));
      return { ok: true, tombstones: [record.id], edits };
    }
    default:
      return { ok: true, tombstones: [record.id], edits: [] };
  }
}

// ── A host's extras ───────────────────────────────────────

/** The identity a host logs in with: its own, else (UwURDP) its group's. */
export function identityOf(host: SuiteRecord, all: Index): SuiteRecord | null {
  const own = all.get(ref(host.payload?.identity_id) ?? '');
  if (own) return own;
  const group = all.get(ref(host.payload?.group_id) ?? '');
  return all.get(ref(group?.payload?.identity_id) ?? '') ?? null;
}

/** `ssh -p 2222 nyu@host.example.com`, or for RDP `host.example.com:3390`. */
export function connectCommand(space: SpaceName, host: SuiteRecord, all: Index): string {
  const p = host.payload ?? {};
  const address = str(p.address);
  const port = num(p.port, DEFAULT_PORT[space]);
  if (space === 'rdp') return portSuffix(address, port, 3389);
  const user = str(identityOf(host, all)?.payload?.username);
  const target = user ? `${quote(user)}@${quote(address)}` : quote(address);
  return port && port !== 22 ? `ssh -p ${port} ${target}` : `ssh ${target}`;
}

/** Quoted for a shell when it has to be. */
function quote(text: string): string {
  return /^[\w@%+=:,./-]+$/.test(text) ? text : `'${text.replace(/'/g, `'\\''`)}'`;
}

/** An `.rdp` value: one line, no line breaks smuggled into another setting. */
function rdpValue(text: string): string {
  return text.replace(/[\r\n]+/g, ' ');
}

/**
 * The host as an `.rdp` file for mstsc and other clients. No password (an `.rdp` file can't
 * keep one safely), and drives never redirected — as UwURDP's importer, which drops them too.
 */
export function rdpFile(host: SuiteRecord, all: Index): string {
  const p = host.payload ?? {};
  const rdp = { ...RDP_DEFAULTS, ...(obj(p.rdp) ?? {}) };
  const identity = identityOf(host, all)?.payload ?? {};
  const user = str(identity.username);
  const domain = str(identity.domain);
  const display = str(rdp.display);
  const lines: string[] = [
    `full address:s:${rdpValue(portSuffix(str(p.address), num(p.port, 3389), 3389))}`,
    `screen mode id:i:${display === 'fullscreen' ? 2 : 1}`,
    `desktopwidth:i:${num(rdp.width, 1920)}`,
    `desktopheight:i:${num(rdp.height, 1080)}`,
    `dynamic resolution:i:${display === 'fit' ? 1 : 0}`,
    `smart sizing:i:${bool(rdp.smartSizing, true) ? 1 : 0}`,
    `session bpp:i:${num(rdp.colorDepth, 32)}`,
    `audiomode:i:${str(rdp.audio) === 'remote' ? 1 : str(rdp.audio) === 'off' ? 2 : 0}`,
    `redirectclipboard:i:${bool(rdp.clipboard, true) ? 1 : 0}`,
    `administrative session:i:${bool(rdp.admin) ? 1 : 0}`,
    `enablecredsspsupport:i:${bool(rdp.nla, true) ? 1 : 0}`,
    `disable wallpaper:i:${bool(rdp.wallpaper, true) ? 0 : 1}`,
    `redirectdrives:i:0`,
    `drivestoredirect:s:`,
    `prompt for credentials:i:1`,
  ];
  if (user) lines.push(`username:s:${rdpValue(domain ? `${domain}\\${user}` : user)}`);
  const gateway = obj(rdp.gateway);
  if (gateway && str(gateway.address)) {
    lines.push(
      `gatewayhostname:s:${rdpValue(portSuffix(str(gateway.address), num(gateway.port, 443), 443))}`,
      `gatewayusagemethod:i:${bool(gateway.bypassLocal) ? 2 : 1}`,
      `gatewaycredentialssource:i:4`,
      `promptcredentialonce:i:${bool(gateway.useHostLogin) ? 1 : 0}`,
    );
  } else {
    lines.push('gatewayusagemethod:i:0');
  }
  return lines.join('\r\n') + '\r\n';
}

/** A file name from the host's name. */
export function rdpFileName(host: SuiteRecord): string {
  const name =
    titleOf(host)
      .replace(/[^\p{L}\p{N}._ -]+/gu, '_')
      .trim() || 'host';
  return `${name}.rdp`;
}

/** `uwussh://connect/<id>`: only the record's id travels, never an address or a login. */
export function deepLink(space: SpaceName, id: string): string {
  return `${space === 'ssh' ? 'uwussh' : 'uwurdp'}://connect/${encodeURIComponent(id)}`;
}

/** Whether the browser runs on a desktop system, where UwUSSH and UwURDP are. */
export function desktopSystem(agent: string, touchPoints = 0): boolean {
  if (/android|iphone|ipad|ipod/i.test(agent)) return false;
  // iPadOS says it is a Mac; a Mac has no touch screen.
  if (/macintosh/i.test(agent) && touchPoints > 1) return false;
  return true;
}
