import { beforeEach, describe, expect, it, vi } from 'vitest';

// The vault's WebAssembly is not needed here (nor built before every test run).
vi.mock('./web/core', () => ({ call: vi.fn(), callJson: vi.fn() }));
vi.mock('./requests', () => ({ openExtras: vi.fn() }));
vi.mock('./web/http', async (actual) => ({
  ...(await actual<typeof import('./web/http')>()),
  request: vi.fn(),
}));

import { loginSso } from './api';
import { ApiError, request } from './web/http';

const asked = (email: string) =>
  new ApiError(400, 'Two factor required.', {
    error: 'invalid_grant',
    TwoFactorProviders2: { '0': null },
    Email: email,
  });

describe('remember this device after SSO', () => {
  beforeEach(() => {
    vi.mocked(request).mockReset();
    localStorage.setItem(
      'uwulock.remember',
      JSON.stringify({
        tokens: { 'mia@example.com': 'mia-token', 'nyu@example.com': 'nyu-token' },
      }),
    );
  });

  const sent = () =>
    vi.mocked(request).mock.calls.map(([, options]) => {
      const form = (options as { form: URLSearchParams }).form;
      return [form.get('twoFactorProvider'), form.get('twoFactorToken')];
    });

  it('sends only the remembered token of the account the server named', async () => {
    vi.mocked(request).mockRejectedValueOnce(asked('NYU@example.com'));
    vi.mocked(request).mockRejectedValueOnce(asked('nyu@example.com'));
    const step = await loginSso('code', 'verifier');
    expect(sent()).toEqual([
      [null, null],
      ['5', 'nyu-token'],
    ]);
    // It did not hold: forgotten, asked for the second step without a wrong-code message.
    expect(step).toMatchObject({ step: 'two-factor', message: null });
    const kept = JSON.parse(localStorage.getItem('uwulock.remember')!);
    expect(kept.tokens).toEqual({ 'mia@example.com': 'mia-token' });
  });

  it('tries nothing for an account this browser does not remember', async () => {
    vi.mocked(request).mockRejectedValueOnce(asked('other@example.com'));
    const step = await loginSso('code', 'verifier');
    expect(sent()).toEqual([[null, null]]);
    expect(step).toMatchObject({ step: 'two-factor' });
  });
});
