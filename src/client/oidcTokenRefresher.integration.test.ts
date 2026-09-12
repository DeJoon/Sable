import { expect, it, vi } from 'vitest';
import {
  createClient,
  HttpApiEvent,
  MatrixError,
  Method,
  TokenRefreshError,
  TokenRefreshLogoutError,
} from '$types/matrix-sdk';
import type { MatrixClient } from '$types/matrix-sdk';
import { MATRIX_SESSIONS_KEY, type Session } from '$state/sessions';
import { createSessionTokenRefresher } from './oidcTokenRefresher';

vi.mock('../sw-session', () => ({
  pushSessionToSW: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
}));

it.each([401, 429, 503])(
  'does not log out when authentication metadata returns %s',
  async (status) => {
    const session: Session = {
      baseUrl: 'https://hs.example',
      userId: '@alice:hs.example',
      deviceId: 'DEVICE',
      accessToken: 'expired-access',
      refreshToken: 'valid-refresh',
      oidc: { issuer: 'https://issuer.example', clientId: 'client' },
    };
    localStorage.setItem(MATRIX_SESSIONS_KEY, JSON.stringify([session]));
    const metadataClient = {
      getAuthMetadata: vi
        .fn<MatrixClient['getAuthMetadata']>()
        .mockRejectedValue(new MatrixError({ errcode: 'M_UNKNOWN', error: 'unavailable' }, status)),
    } as unknown as MatrixClient;
    const refresher = createSessionTokenRefresher(session, metadataClient)!;
    const mx = createClient({
      baseUrl: session.baseUrl,
      userId: session.userId,
      deviceId: session.deviceId,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      tokenRefreshFunction: refresher.tokenRefreshFunction,
      fetchFn: vi.fn<typeof fetch>().mockImplementation(
        async () =>
          new Response(
            JSON.stringify({
              errcode: 'M_UNKNOWN_TOKEN',
              error: 'expired',
              soft_logout: true,
            }),
            { status: 401, headers: { 'Content-Type': 'application/json' } }
          )
      ),
    });
    const logout = vi.fn<() => void>();
    mx.on(HttpApiEvent.SessionLoggedOut, logout);
    await expect(mx.http.authedRequest(Method.Get, '/account/whoami')).rejects.toBeInstanceOf(
      TokenRefreshError
    );
    expect(logout).not.toHaveBeenCalled();
  }
);

it('still requests reauthentication when the refresh token is rejected', async () => {
  const mx = createClient({
    baseUrl: 'https://hs.example',
    accessToken: 'expired-access',
    refreshToken: 'revoked-refresh',
    tokenRefreshFunction: async () => {
      throw new TokenRefreshLogoutError(new Error('invalid_grant'));
    },
    fetchFn: async () =>
      new Response(JSON.stringify({ errcode: 'M_UNKNOWN_TOKEN' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
  });
  const logout = vi.fn<() => void>();
  mx.on(HttpApiEvent.SessionLoggedOut, logout);
  await expect(mx.http.authedRequest(Method.Get, '/account/whoami')).rejects.toBeInstanceOf(
    MatrixError
  );
  expect(logout).toHaveBeenCalledTimes(1);
});
