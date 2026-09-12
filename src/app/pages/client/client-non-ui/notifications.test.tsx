import { render, waitFor } from '@testing-library/react';
import { Provider, createStore } from 'jotai';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NativeNotificationActionRouting,
  NativeNotificationClickRouting,
  getLastLiveSyncTs,
  setLastLiveSyncTs,
  MAX_LIVE_SYNC_CHECKPOINT_AGE,
} from './notifications';
import { activeSessionIdAtom, pendingNotificationAtom } from '$state/sessions';
import { nativeNotificationRepliesAtom } from '$state/nativeNotificationReplies';

// Controllable platform gates + a capturable notifications API. The click-routing
// effect only calls onNotificationClicked, so the rest of the plugin surface is stubbed
// to satisfy notifications.tsx's top-level imports.
const platform = vi.hoisted(() => ({
  isAndroidTauri: vi.fn<() => boolean>(),
  isIosTauri: vi.fn<() => boolean>(),
  isDesktopTauri: vi.fn<() => boolean>(),
}));

const notificationsApi = vi.hoisted(() => ({
  onNotificationClicked: vi
    .fn<
      (
        handler: (event: { data?: Record<string, string> }) => void
      ) => Promise<{ unregister: () => void }>
    >()
    .mockResolvedValue({ unregister: () => {} }),
}));

const matrixClient = vi.hoisted(() => ({
  getUserId: vi.fn<() => string>(() => '@user:example.com'),
  getRoom: vi.fn<() => { getMyMembership: () => string }>(() => ({
    getMyMembership: () => 'join',
  })),
  getSyncState: vi.fn<() => string>(() => 'SYNCING'),
  sendMessage: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
}));

const notificationUtils = vi.hoisted(() => ({
  markAsRead: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
}));

const toast = vi.hoisted(() => ({
  showToast: vi.fn<(message: string) => void>(),
  showErrorToast: vi.fn<(message: string) => void>(),
}));

const getTauriNotificationsApi = vi.hoisted(() =>
  vi.fn<() => Promise<typeof notificationsApi>>().mockResolvedValue(notificationsApi)
);

vi.mock('$features/settings/notifications/TauriNotificationsApiClient', () => ({
  getTauriNotificationsApi,
  isAndroidTauri: platform.isAndroidTauri,
  isIosTauri: platform.isIosTauri,
  isDesktopTauri: platform.isDesktopTauri,
  isNativeNotificationTauri: vi.fn<() => boolean>(() => false),
  sendNativeTauriNotification: vi.fn<() => void>(),
  IOS_INVITE_SOUND: 'invite.caf',
  IOS_NOTIFICATION_SOUND: 'notification.caf',
}));

vi.mock('$hooks/useMatrixClient', () => ({ useMatrixClient: () => matrixClient }));
vi.mock('$state/hooks/settings', () => ({
  useSetting: () => [false, vi.fn<(value: unknown) => void>()],
}));
vi.mock('$utils/notifications', () => notificationUtils);
vi.mock('$state/toast', () => toast);

function setPlatform(kind: 'android' | 'ios' | 'desktop' | 'web') {
  platform.isAndroidTauri.mockReturnValue(kind === 'android');
  platform.isIosTauri.mockReturnValue(kind === 'ios');
  platform.isDesktopTauri.mockReturnValue(kind === 'desktop');
}

function renderRouting(store = createStore()) {
  return render(
    <Provider store={store}>
      <MemoryRouter>
        <NativeNotificationClickRouting />
      </MemoryRouter>
    </Provider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  getTauriNotificationsApi.mockResolvedValue(notificationsApi);
  notificationsApi.onNotificationClicked.mockResolvedValue({ unregister: () => {} });
  matrixClient.sendMessage.mockResolvedValue(undefined);
  notificationUtils.markAsRead.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('NativeNotificationClickRouting', () => {
  it('registers the click listener on Android (previously excluded by isNativeNotificationTauri)', async () => {
    setPlatform('android');
    renderRouting();

    await waitFor(() => {
      expect(notificationsApi.onNotificationClicked).toHaveBeenCalledTimes(1);
    });
  });

  it('registers the click listener on iOS', async () => {
    setPlatform('ios');
    renderRouting();

    await waitFor(() => {
      expect(notificationsApi.onNotificationClicked).toHaveBeenCalledTimes(1);
    });
  });

  it('registers the click listener on desktop', async () => {
    setPlatform('desktop');
    renderRouting();

    await waitFor(() => {
      expect(notificationsApi.onNotificationClicked).toHaveBeenCalledTimes(1);
    });
  });

  it('does not register the click listener on web', async () => {
    setPlatform('web');
    renderRouting();

    // The effect bails before calling getTauriNotificationsApi on web; flush any
    // pending microtasks before asserting nothing was scheduled.
    await Promise.resolve();

    expect(getTauriNotificationsApi).not.toHaveBeenCalled();
    expect(notificationsApi.onNotificationClicked).not.toHaveBeenCalled();
  });

  it('ignores unscoped clicks and switches account before routing scoped invites', async () => {
    setPlatform('android');
    const store = createStore();
    let clickHandler!: (event: { data?: Record<string, string> }) => void;
    notificationsApi.onNotificationClicked.mockImplementation(async (handler) => {
      clickHandler = handler;
      return { unregister: () => {} };
    });
    renderRouting(store);
    await waitFor(() => expect(clickHandler).toBeTypeOf('function'));

    clickHandler({ data: { type: 'invite', room_id: '!room:example.com' } });
    expect(store.get(activeSessionIdAtom)).not.toBe('@other:example.com');
    expect(store.get(pendingNotificationAtom)).toBeNull();

    clickHandler({
      data: {
        type: 'invite',
        user_id: '@other:example.com',
        room_id: '!room:example.com',
      },
    });
    expect(store.get(activeSessionIdAtom)).toBe('@other:example.com');
  });
});

describe('NativeNotificationActionRouting', () => {
  it('does not report a successful reply as failed when marking it read fails', async () => {
    setPlatform('web');
    const store = createStore();
    store.set(nativeNotificationRepliesAtom, [
      {
        key: 'reply',
        userId: '@user:example.com',
        roomId: '!room:example.com',
        eventId: '$event',
        text: 'hello',
        createdAt: Date.now(),
      },
    ]);
    notificationUtils.markAsRead.mockRejectedValueOnce(new Error('receipt failed'));

    render(
      <Provider store={store}>
        <MemoryRouter>
          <NativeNotificationActionRouting />
        </MemoryRouter>
      </Provider>
    );

    await waitFor(() => expect(matrixClient.sendMessage).toHaveBeenCalledOnce());
    await waitFor(() => expect(store.get(nativeNotificationRepliesAtom)).toEqual([]));
    expect(notificationUtils.markAsRead).toHaveBeenCalledOnce();
    expect(toast.showErrorToast).not.toHaveBeenCalled();
  });
});

describe('last-live-sync checkpoint', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('round-trips a persisted timestamp', () => {
    setLastLiveSyncTs('@user:example.com', 12345);
    expect(getLastLiveSyncTs('@user:example.com')).toBe(12345);
  });

  it('returns undefined when nothing has been persisted yet', () => {
    expect(getLastLiveSyncTs('@nobody:example.com')).toBeUndefined();
  });

  it('does not confuse one user with another', () => {
    setLastLiveSyncTs('@alice:example.com', 111);
    expect(getLastLiveSyncTs('@bob:example.com')).toBeUndefined();
  });

  it('does not throw when storage is unavailable', () => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = () => {
      throw new Error('storage disabled');
    };
    try {
      expect(() => setLastLiveSyncTs('@user:example.com', 1)).not.toThrow();
    } finally {
      Storage.prototype.setItem = original;
    }
    expect(getLastLiveSyncTs('@user:example.com')).toBeUndefined();
  });

  it('exposes a multi-day staleness cutoff so an abandoned session is not treated as fresh', () => {
    // Regression guard for the actual bug: a reload must reuse a recent checkpoint,
    // but a checkpoint from weeks ago must not suppress notifications for that long.
    expect(MAX_LIVE_SYNC_CHECKPOINT_AGE).toBeGreaterThan(24 * 60 * 60 * 1000);
  });
});
