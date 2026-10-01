import { beforeEach, describe, expect, it, vi } from 'vitest';

// The server and the WebAssembly module, faked: what matters here is which requests go out and
// what the page is told, not the crypto (the module's own tests and uwulock-e2e cover that).
const { request, core } = vi.hoisted(() => ({
  request: vi.fn(),
  core: {
    suiteOpenSpace: vi.fn((space: string) => JSON.stringify({ id: JSON.parse(space).id })),
    suiteCreateSpace: vi.fn(() => JSON.stringify({ id: 'new-space', key: '2.key' })),
    suiteForgetRecords: vi.fn(),
    suiteMerge: vi.fn(),
    suiteRecords: vi.fn(() => JSON.stringify({ records: [], unreadable: 0 })),
    suiteSealNew: vi.fn((_s: string, kind: string, payload: string, now: number, device: number) =>
      JSON.stringify({ id: `new-${kind}`, kind, payload, now, device }),
    ),
    suiteSealEdit: vi.fn((_s: string, id: string) => JSON.stringify({ id, kind: 'host' })),
    suiteSealTombstone: vi.fn((_s: string, id: string) =>
      JSON.stringify({ id, kind: 'host', deleted: true }),
    ),
    suitePushRequest: vi.fn((_s: string, envelopes: string) =>
      JSON.stringify({ schema: 2, spaceId: 'space-1', records: JSON.parse(envelopes) }),
    ),
    suiteApplyPush: vi.fn((_s: string, _p: string, answer: string) =>
      JSON.stringify(
        (JSON.parse(answer) as { conflicts: { id: string }[] }).conflicts.map((c) => c.id),
      ),
    ),
  },
}));
vi.mock('../web/http', async (original) => ({
  ...(await original<typeof import('../web/http')>()),
  request,
  currentSession: () => ({ email: 'nyu@example.com' }),
}));
vi.mock('../requests', () => ({ openExtras: async () => undefined }));
vi.mock('./live', () => ({ watchSuite: () => () => undefined }));
vi.mock('../web/core', () => ({
  call: async (work: (c: typeof core) => unknown) => work(core),
  callJson: async (work: (c: typeof core) => string) => JSON.parse(work(core)) as unknown,
}));

const { Batch, SpaceChanged, createSpace, loadSpace, stateOf, suiteDevice, forgetSuite } =
  await import('./sync');
const { ApiError } = await import('../web/http');

const conflict = (code: string, status = 409) => new ApiError(status, code, { code });

beforeEach(() => {
  request.mockReset();
  for (const fn of Object.values(core)) fn.mockClear();
  forgetSuite();
  window.localStorage.clear();
});

describe('the device in a record’s clock', () => {
  it('is one per browser and account, never 0, and kept', () => {
    const first = suiteDevice('nyu@example.com');
    expect(first).toBeGreaterThan(0);
    expect(suiteDevice('NYU@example.com')).toBe(first);
    expect(suiteDevice('other@example.com')).not.toBe(first);
  });

  it('is one per page without local storage', () => {
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied');
    });
    const one = suiteDevice('nyu@example.com');
    expect(suiteDevice('nyu@example.com')).toBe(one);
    spy.mockRestore();
  });
});

describe('a space', () => {
  it('is pulled page by page, and from 0 again when the server says reset', async () => {
    const pages = [
      { reset: false, records: [{ id: 'a' }], cursor: 5, hasMore: true },
      { reset: true, records: [], cursor: 0, hasMore: false },
      { reset: false, records: [{ id: 'a' }, { id: 'b' }], cursor: 9, hasMore: false },
    ];
    request.mockImplementation(async (path: string) => {
      if (path === '/uwu/v1/suite/spaces')
        return { data: [{ space: 'ssh', id: 'space-1', key: '2.k' }] };
      return pages.shift();
    });
    await loadSpace('ssh');
    expect(stateOf('ssh').status).toBe('open');
    const pulls = request.mock.calls
      .map(([path]) => path as string)
      .filter((p) => p.includes('records'));
    expect(pulls).toEqual([
      '/uwu/v1/suite/spaces/ssh/records?since=0&limit=500',
      '/uwu/v1/suite/spaces/ssh/records?since=5&limit=500',
      '/uwu/v1/suite/spaces/ssh/records?since=0&limit=500',
    ]);
    expect(core.suiteForgetRecords).toHaveBeenCalled();
    expect(core.suiteMerge).toHaveBeenCalledTimes(2);
  });

  it('that no app made yet says so, and is made with a fresh key; a quicker app’s is taken', async () => {
    request.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (path === '/uwu/v1/suite/spaces') return { data: [] };
      if (options?.method === 'PUT') throw conflict('exists');
      return { reset: false, records: [], cursor: 0, hasMore: false };
    });
    await loadSpace('rdp');
    expect(stateOf('rdp').status).toBe('none');

    request.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (path === '/uwu/v1/suite/spaces')
        return { data: [{ space: 'rdp', id: 'theirs', key: '2.t' }] };
      if (options?.method === 'PUT') throw conflict('exists');
      return { reset: false, records: [], cursor: 0, hasMore: false };
    });
    await createSpace('rdp');
    expect(core.suiteCreateSpace).toHaveBeenCalledWith('rdp');
    expect(core.suiteOpenSpace).toHaveBeenCalledWith(
      JSON.stringify({ space: 'rdp', id: 'theirs', key: '2.t' }),
    );
    expect(stateOf('rdp').status).toBe('open');
  });

  it('is off when the server switched the suite vault off', async () => {
    request.mockRejectedValue(new ApiError(404, 'off', { code: 'feature_off' }));
    await loadSpace('ssh');
    expect(stateOf('ssh').status).toBe('off');
  });
});

describe('a push', () => {
  beforeEach(async () => {
    request.mockImplementation(async (path: string) =>
      path === '/uwu/v1/suite/spaces'
        ? { data: [{ space: 'ssh', id: 'space-1', key: '2.k' }] }
        : { reset: false, records: [], cursor: 3, hasMore: false },
    );
    await loadSpace('ssh');
    request.mockClear();
  });

  it('seals with this browser’s device and now, and answers what changed elsewhere', async () => {
    const batch = new Batch('ssh');
    const secret = await batch.add('secret', 'hunter2');
    expect(secret).toBe('new-secret');
    await batch.add('identity', { username: 'nyu', password_secret_id: secret });
    await batch.edit('h1', { name: 'Router' });
    const [, kind, payload, now, device] = core.suiteSealNew.mock.calls[0]!;
    expect([kind, JSON.parse(payload)]).toEqual(['secret', { text: 'hunter2' }]);
    expect(JSON.parse(core.suiteSealNew.mock.calls[1]![2])).toEqual({
      json: { username: 'nyu', password_secret_id: 'new-secret' },
    });
    expect(Math.abs(now - Date.now())).toBeLessThan(5_000);
    expect(device).toBe(suiteDevice());

    request.mockImplementation(async (_path: string, options?: { body?: unknown }) => {
      if (options?.body)
        return { accepted: [{ id: 'new-secret', seq: 4 }], conflicts: [{ id: 'h1' }], cursor: 6 };
      return { reset: false, records: [], cursor: 6, hasMore: false };
    });
    expect(await batch.push()).toEqual(['h1']);
    const [path, options] = request.mock.calls[0]!;
    expect(path).toBe('/uwu/v1/suite/spaces/ssh/records');
    expect((options as { body: { schema: number; spaceId: string } }).body).toMatchObject({
      schema: 2,
      spaceId: 'space-1',
    });
  });

  it('after a rekey elsewhere reads the space again from 0 and says so', async () => {
    const batch = new Batch('ssh');
    await batch.remove('h1');
    request.mockImplementation(async (path: string, options?: { body?: unknown }) => {
      if (options?.body) throw conflict('space_changed');
      if (path === '/uwu/v1/suite/spaces')
        return { data: [{ space: 'ssh', id: 'space-2', key: '2.n' }] };
      return { reset: false, records: [], cursor: 0, hasMore: false };
    });
    await expect(batch.push()).rejects.toBeInstanceOf(SpaceChanged);
    expect(core.suiteOpenSpace).toHaveBeenLastCalledWith(
      JSON.stringify({ space: 'ssh', id: 'space-2', key: '2.n' }),
    );
    expect(
      request.mock.calls.some(([p]) => p === '/uwu/v1/suite/spaces/ssh/records?since=0&limit=500'),
    ).toBe(true);
  });
});
