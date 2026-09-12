import { act, renderHook } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { createClient, HttpApiEvent, MatrixError } from '$types/matrix-sdk';
import { MATRIX_SESSIONS_KEY } from '$state/sessions';
import { stopClient } from '$client/initMatrix';
import { useSessionLogout } from './useSessionLogout';

vi.mock('$client/initMatrix', () => ({ stopClient: vi.fn<() => void>() }));
vi.mock('@sentry/react', () => ({
  addBreadcrumb: vi.fn<() => void>(),
  metrics: { count: vi.fn<() => void>() },
}));

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

it.each([true, false])(
  'preserves all accounts and stores on logout with soft_logout=%s',
  (softLogout) => {
    const mx = createClient({ baseUrl: 'https://hs.example' });
    const clearStores = vi.spyOn(mx, 'clearStores');
    const accounts = JSON.stringify([
      { userId: '@alice:hs.example' },
      { userId: '@bob:hs.example' },
    ]);
    localStorage.setItem(MATRIX_SESSIONS_KEY, accounts);
    localStorage.setItem('settings', 'saved-settings');
    const { result, unmount } = renderHook(() => useSessionLogout(mx));
    expect(result.current).toBe(false);
    const error = new MatrixError({ errcode: 'M_UNKNOWN_TOKEN', soft_logout: softLogout }, 401);
    act(() => {
      mx.emit(HttpApiEvent.SessionLoggedOut, error);
      mx.emit(HttpApiEvent.SessionLoggedOut, error);
    });
    expect(result.current).toBe(true);
    expect(stopClient).toHaveBeenCalledExactlyOnceWith(mx);
    expect(clearStores).not.toHaveBeenCalled();
    expect(localStorage.getItem(MATRIX_SESSIONS_KEY)).toBe(accounts);
    expect(localStorage.getItem('settings')).toBe('saved-settings');
    unmount();
    expect(stopClient).toHaveBeenCalledTimes(1);
    expect(mx.listenerCount(HttpApiEvent.SessionLoggedOut)).toBe(0);
  }
);

it('does not carry the expired state to another client', () => {
  const first = createClient({ baseUrl: 'https://hs.example' });
  const second = createClient({ baseUrl: 'https://hs.example' });
  const { result, rerender } = renderHook(({ mx }) => useSessionLogout(mx), {
    initialProps: { mx: first },
  });
  act(() =>
    first.emit(HttpApiEvent.SessionLoggedOut, new MatrixError({ errcode: 'M_UNKNOWN_TOKEN' }, 401))
  );
  rerender({ mx: second });
  expect(result.current).toBe(false);
});
