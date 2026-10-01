import { beforeEach, describe, expect, it, vi } from 'vitest';

// The server's answers, faked: a hostile or broken server must not turn them into links, and
// the ignore list must survive another device saving in between.
const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('./web/http', async (original) => ({
  ...(await original<typeof import('./web/http')>()),
  request,
}));
vi.mock('./requests', () => ({ openExtras: async () => undefined }));
// "Sealing" is plain JSON here; what matters is what goes over the wire.
vi.mock('./web/core', () => ({
  call: async (work: (core: unknown) => unknown) =>
    work({
      sealReport: (text: string) => `sealed:${text}`,
      openReport: (data: string) => data.replace(/^sealed:/, ''),
    }),
}));

const { changeIgnores, changePasswordPage, ignore, pageToOpen } = await import('./breaches');
const { ApiError } = await import('./web/http');

beforeEach(() => request.mockReset());

describe('change-password pages from the server', () => {
  it("only say whether there is one; the address is the login host's own", async () => {
    const answers: Record<string, string | null> = {
      'evil.example.com': 'javascript:alert(document.domain)',
      'phish.example.com': 'https://login.example.net/steal',
      'none.example.com': null,
      'good.example.com': 'https://good.example.com/.well-known/change-password',
    };
    request.mockImplementation(async (path?: string) => ({
      url: answers[decodeURIComponent(String(path).split('/').pop() ?? '')] ?? null,
    }));
    expect(await changePasswordPage('evil.example.com')).toBe(
      'https://evil.example.com/.well-known/change-password',
    );
    expect(await changePasswordPage('phish.example.com')).toBe(
      'https://phish.example.com/.well-known/change-password',
    );
    expect(await changePasswordPage('none.example.com')).toBeNull();
    expect(await changePasswordPage('good.example.com')).toBe(
      'https://good.example.com/.well-known/change-password',
    );
    // What is not a plain host is never asked for, nor linked.
    const asked = request.mock.calls.length;
    expect(await changePasswordPage('user@bad.example.com')).toBeNull();
    expect(await changePasswordPage('bad.example.com:8443')).toBeNull();
    expect(request.mock.calls.length).toBe(asked);
    // Without a page, the login's own https address.
    expect(await pageToOpen({ host: 'none.example.com', uri: null }, true)).toBe(
      'https://none.example.com/',
    );
  });
});

describe('the ignore list', () => {
  it('is sent sealed, and a 409 applies the change to the newer list', async () => {
    const other = { version: 1, ignored: [{ itemId: 'b', kind: 'weak', since: 'x' }] };
    const puts: unknown[] = [];
    request.mockImplementation(
      async (path?: string, init?: { method?: string; body?: unknown }) => {
        // (vitest itself pokes the mock once, without arguments)
        if (path === undefined) return undefined;
        if (init?.method === 'PUT') {
          puts.push(init.body);
          if (puts.length === 1) throw new ApiError(409, 'conflict', null);
          return { data: null, revisionDate: 'r3' };
        }
        expect(path).toBe('/uwu/v1/reports/health/ignored');
        return { data: `sealed:${JSON.stringify(other)}`, revisionDate: 'r2' };
      },
    );
    const saved = await changeIgnores(
      { list: { version: 1, ignored: [] }, revision: 'r1' },
      (list) => ignore(list, 'a', 'reused'),
    );
    expect(saved.revision).toBe('r3');
    expect(saved.list.ignored.map((e) => e.itemId).sort()).toEqual(['a', 'b']);
    for (const body of puts as { data: string }[]) {
      expect(body.data.startsWith('sealed:')).toBe(true);
    }
    expect((puts[1] as { revisionDate: string }).revisionDate).toBe('r2');
  });
});
