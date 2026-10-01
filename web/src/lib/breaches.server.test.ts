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
  it('are only ever http(s) links', async () => {
    const answers: Record<string, string> = {
      'evil.example.com': 'javascript:alert(document.domain)',
      'data.example.com': 'data:text/html,<script>alert(1)</script>',
      'spaced.example.com': ' JaVaScRiPt:alert(1)',
      'good.example.com': 'https://good.example.com/account/password',
    };
    request.mockImplementation(async (path?: string) => ({
      url: answers[decodeURIComponent(String(path).split('/').pop()!)],
    }));
    expect(await changePasswordPage('evil.example.com')).toBeNull();
    expect(await changePasswordPage('data.example.com')).toBeNull();
    expect(await changePasswordPage('spaced.example.com')).toBeNull();
    expect(await changePasswordPage('good.example.com')).toBe(
      'https://good.example.com/account/password',
    );
    // A refused page falls back to the login's own https address.
    expect(await pageToOpen({ host: 'evil.example.com', uri: null }, true)).toBe(
      'https://evil.example.com/',
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
