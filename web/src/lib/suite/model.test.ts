import { describe, expect, it } from 'vitest';
import {
  applyEdit,
  blank,
  connectCommand,
  deepLink,
  deletePlan,
  desktopSystem,
  hostSections,
  indexOf,
  matches,
  move,
  rdpFile,
  rdpFileName,
  usersOf,
  type Payload,
  type SuiteRecord,
} from './model';

let seq = 0;
const rec = (id: string, kind: string, payload: Payload): SuiteRecord => ({
  id,
  kind,
  seq: ++seq,
  updatedAt: { wallMs: 1_790_000_000_000, counter: 0, device: 1 },
  payload,
});

const identity = rec('i1', 'identity', {
  label: 'Nyu',
  username: 'nyu',
  auth_type: 'password',
  key_id: 'k1',
  password_secret_id: 's1',
});
const key = rec('k1', 'key', {
  label: 'Laptop',
  key_type: 'ssh-ed25519',
  public_key: 'ssh-ed25519 AAAA nyu@example.com',
  private_secret_id: 's2',
  passphrase_secret_id: 's3',
});
const secrets = ['s1', 's2', 's3'].map((id) => rec(id, 'secret', undefined as unknown as Payload));
const group = rec('g1', 'group', { workspace: 'business', name: 'Clients', position: 0 });
const host = rec('h1', 'host', {
  name: 'Router',
  address: 'router.example.com',
  port: 2222,
  workspace: 'business',
  position: 0,
  group_id: 'g1',
  identity_id: 'i1',
  tags: ['lab'],
});
const loose = rec('h2', 'host', {
  name: 'NAS',
  address: '192.0.2.10',
  port: 22,
  workspace: 'private',
  position: 0,
  group_id: null,
  identity_id: null,
});
const forward = rec('f1', 'port_forward', {
  host_id: 'h1',
  name: 'web',
  kind: 'local',
  bind_address: '127.0.0.1',
  bind_port: 8080,
  target_host: 'localhost',
  target_port: 80,
  autostart: false,
});
const records = [identity, key, ...secrets, group, host, loose, forward];
const all = indexOf(records);

describe('an edit', () => {
  it('changes what the form changed and keeps everything else, also what an app added since', () => {
    const opened = {
      name: 'Router',
      port: 22,
      rdp: { display: 'fit', clipboard: true },
      tags: ['a'],
    };
    const draft = { ...opened, name: 'Router (Keller)', rdp: { display: 'fit', clipboard: false } };
    const latest = {
      ...opened,
      port: 2222,
      rdp: { display: 'fit', clipboard: true, newer: 1 },
      added: true,
    };
    expect(applyEdit(latest, opened, draft)).toEqual({
      name: 'Router (Keller)',
      port: 2222,
      rdp: { display: 'fit', clipboard: false, newer: 1 },
      tags: ['a'],
      added: true,
    });
  });

  it('removes a field the form removed', () => {
    const opened = { rdp: { gateway: { address: 'gw.example.com' }, nla: true } };
    const draft = { rdp: { nla: true } };
    expect(applyEdit(opened, opened, draft)).toEqual({ rdp: { nla: true } });
  });

  it('starts a new RDP host with the defaults UwURDP has', () => {
    const fresh = blank('rdp', 'host', 3);
    expect(fresh.port).toBe(3389);
    expect(fresh.position).toBe(3);
    expect((fresh.rdp as Payload).nla).toBe(true);
    expect(blank('ssh', 'host').rdp).toBeUndefined();
  });
});

describe('the list', () => {
  it('shows hosts per workspace and group, the hosts of a group that is gone without one', () => {
    const orphan = rec('h3', 'host', { ...loose.payload, name: 'Old', group_id: 'gone' });
    const sections = hostSections([...records, orphan]);
    expect(
      sections.map((s) => [s.workspace, s.group?.id ?? null, s.hosts.map((h) => h.id)]),
    ).toEqual([
      ['private', null, ['h2', 'h3']],
      ['business', 'g1', ['h1']],
    ]);
  });

  it('finds a host by its user, its address or its name', () => {
    expect(matches('ssh', host, all, 'nyu router')).toBe(true);
    expect(matches('ssh', host, all, '2222')).toBe(true);
    expect(matches('ssh', host, all, 'nas')).toBe(false);
    expect(matches('ssh', loose, all, '')).toBe(true);
  });

  it('moves a record one place and renumbers its siblings', () => {
    const a = rec('a', 'group', { position: 0, name: 'A' });
    const b = rec('b', 'group', { position: 0, name: 'B' });
    const c = rec('c', 'group', { position: 5, name: 'C' });
    expect([...move([a, b, c], 'c', -1)]).toEqual([
      ['c', 1],
      ['b', 2],
    ]);
    expect([...move([a, b, c], 'a', -1)]).toEqual([]);
  });
});

describe('deleting', () => {
  it('takes a host’s port forwards along, not its identity', () => {
    expect(deletePlan(records, host)).toEqual({ ok: true, tombstones: ['h1', 'f1'], edits: [] });
  });

  it('keeps an identity or a key while something points at it', () => {
    const plan = deletePlan(records, identity);
    expect(plan.ok).toBe(false);
    expect(!plan.ok && plan.users.map((u) => u.id)).toEqual(['h1']);
    expect(usersOf(records, 'k1').map((u) => u.id)).toEqual(['i1']);
  });

  it('takes an unused identity’s or key’s secrets along', () => {
    expect(deletePlan([key, ...secrets], key)).toEqual({
      ok: true,
      tombstones: ['k1', 's2', 's3'],
      edits: [],
    });
    const rdpHost = rec('h9', 'host', { gateway_identity_id: 'i1' });
    expect(deletePlan([identity, rdpHost], identity).ok).toBe(false);
  });

  it('takes along only secrets, whatever ids a record names as its own', () => {
    // Written by another device: the "secrets" of this key are a host and a group.
    const odd = rec('k9', 'key', { private_secret_id: 'h2', passphrase_secret_id: 'g1' });
    expect(deletePlan([odd, loose, group, ...secrets], odd)).toEqual({
      ok: true,
      tombstones: ['k9'],
      edits: [],
    });
  });

  it('leaves a group’s hosts without a group, every other field kept', () => {
    const plan = deletePlan(records, group);
    expect(plan.ok && plan.tombstones).toEqual(['g1']);
    expect(plan.ok && plan.edits).toEqual([
      { id: 'h1', payload: { ...host.payload, group_id: null } },
    ]);
  });
});

describe('a host’s extras', () => {
  it('copies the ssh command with port and user, quoted for a shell when needed', () => {
    expect(connectCommand('ssh', host, all)).toBe('ssh -p 2222 nyu@router.example.com');
    expect(connectCommand('ssh', loose, all)).toBe('ssh 192.0.2.10');
    const odd = rec('o', 'host', {
      address: "x.example.com; rm -rf ~'",
      port: 22,
      identity_id: null,
    });
    expect(connectCommand('ssh', odd, all)).toBe(`ssh 'x.example.com; rm -rf ~'\\'''`);
    // An option in the user or the address stays a destination; control characters go.
    const option = rec('p', 'host', { address: '-oProxyCommand=touch${IFS}/tmp/x', port: 22 });
    expect(connectCommand('ssh', option, all)).toBe(`ssh -- '-oProxyCommand=touch\${IFS}/tmp/x'`);
    const sneakyUser = rec('su', 'identity', { username: '-oProxyCommand=id' });
    const viaUser = rec('vu', 'host', { address: 'a.example.com', port: 2200, identity_id: 'su' });
    expect(connectCommand('ssh', viaUser, indexOf([sneakyUser, viaUser]))).toBe(
      'ssh -p 2200 -- -oProxyCommand=id@a.example.com',
    );
    const controls = rec('c', 'host', { address: 'a.example.com\n\u001b[2Jrm -rf ~', port: 22 });
    expect(connectCommand('ssh', controls, all)).toBe(`ssh 'a.example.com [2Jrm -rf ~'`);
    // Only an identity logs in: a pointer at another kind is none.
    const wrong = rec('w', 'host', { address: 'b.example.com', port: 22, identity_id: 'k1' });
    expect(connectCommand('ssh', wrong, all)).toBe('ssh b.example.com');
    const v6 = rec('v', 'host', { address: '2001:db8::1', port: 3390 });
    expect(connectCommand('rdp', v6, all)).toBe('[2001:db8::1]:3390');
  });

  it('writes an .rdp file without a password and without drives', () => {
    const user = rec('u', 'identity', {
      username: 'admin',
      domain: 'CORP',
      password_secret_id: 's1',
    });
    const desk = rec('d', 'host', {
      name: 'Desk / 1',
      address: 'desk.example.com',
      port: 3389,
      identity_id: 'u',
      rdp: {
        display: 'fixed',
        width: 1280,
        height: 720,
        audio: 'off',
        drives: { enabled: true, drives: [{ name: 'C', path: '*' }] },
        gateway: { address: 'gw.example.com', port: 443, useHostLogin: true, bypassLocal: true },
      },
    });
    const text = rdpFile(desk, indexOf([user, desk]));
    expect(text).toContain('full address:s:desk.example.com\r\n');
    expect(text).toContain('desktopwidth:i:1280');
    expect(text).toContain('audiomode:i:2');
    expect(text).toContain('username:s:CORP\\admin');
    expect(text).toContain('redirectdrives:i:0');
    expect(text).toContain('drivestoredirect:s:\r\n');
    expect(text).toContain('gatewayhostname:s:gw.example.com');
    expect(text).toContain('gatewayusagemethod:i:2');
    expect(text).not.toMatch(/password/i);
    expect(rdpFileName(desk)).toBe('Desk _ 1.rdp');
    // A line break in a field can't smuggle in a setting.
    const sneaky = rec('s', 'host', { address: 'a.example.com\r\ndrivestoredirect:s:*' });
    expect(rdpFile(sneaky, all)).not.toContain('\r\ndrivestoredirect:s:*');
    for (const lineBreak of ['\r', '\n', '\u000b', '\u000c', '\u0085', '\u2028', '\u2029']) {
      const other = rec('s', 'host', { address: `a.example.com${lineBreak}redirectdrives:i:1` });
      expect(rdpFile(other, all).split('\r\n')[0]).toBe(
        'full address:s:a.example.com redirectdrives:i:1',
      );
    }
  });

  it('opens the app with nothing but the record’s id', () => {
    expect(deepLink('ssh', 'h1')).toBeNull();
    expect(deepLink('ssh', '9B2D0C1E-0000-4000-8000-000000000001')).toBeNull();
    expect(deepLink('ssh', '9b2d0c1e-0000-4000-8000-000000000001/../x')).toBeNull();
    expect(deepLink('rdp', '9b2d0c1e-0000-4000-8000-000000000001')).toBe(
      'uwurdp://connect/9b2d0c1e-0000-4000-8000-000000000001',
    );
  });

  it('offers the app only on a desktop system', () => {
    expect(desktopSystem('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe(true);
    expect(desktopSystem('Mozilla/5.0 (X11; Linux x86_64)')).toBe(true);
    expect(desktopSystem('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)', 0)).toBe(true);
    expect(desktopSystem('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)', 5)).toBe(false);
    expect(desktopSystem('Mozilla/5.0 (Linux; Android 15; Pixel 9)')).toBe(false);
    expect(desktopSystem('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')).toBe(false);
  });
});
