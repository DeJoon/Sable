import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';

const {
  pause,
  resume,
  getSlidingSyncManager,
  listen,
  listenOff,
  mockIsTauri,
  mockIsMobileTauri,
  mockCallEmbed,
  transport,
} = vi.hoisted(() => ({
  pause: vi.fn<() => void>(),
  resume: vi.fn<() => void>(),
  getSlidingSyncManager: vi.fn<() => unknown>(),
  listen: vi.fn<(_event: string, _cb: () => void) => Promise<() => void>>(),
  listenOff: vi.fn<() => void>(),
  mockIsTauri: { value: false },
  mockIsMobileTauri: { value: true },
  mockCallEmbed: { value: undefined as unknown },
  transport: { paused: false, draining: false, listeners: new Set<() => void>() },
}));

vi.mock('$client/initMatrix', () => ({ getSlidingSyncManager }));

vi.mock('jotai', () => ({
  useAtomValue: () => mockCallEmbed.value,
  atom: vi.fn<() => unknown>(),
}));

vi.mock('../state/callEmbed', () => ({ callEmbedAtom: {} }));

vi.mock('@tauri-apps/api/event', () => ({
  listen,
  TauriEvent: { WINDOW_RESUMED: 'tauri://resumed' },
}));

vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => mockIsTauri.value }));

vi.mock('$utils/platform', () => ({ isMobileTauri: () => mockIsMobileTauri.value }));

import { useSyncOrchestrator } from './useSyncOrchestrator';

const STOP_DELAY_MS = 3000;

const setVisibility = (state: 'visible' | 'hidden') =>
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue(state);

const setTransport = (next: { paused?: boolean; draining?: boolean }) => {
  Object.assign(transport, next);
  act(() => {
    transport.listeners.forEach((listener) => listener());
  });
};

const client = { clientRunning: true } as never;

describe('useSyncOrchestrator', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.useFakeTimers();
    pause.mockReset().mockImplementation(() => setTransport({ paused: true }));
    resume.mockReset().mockImplementation(() => setTransport({ paused: false }));
    listenOff.mockReset();
    listen.mockReset().mockResolvedValue(listenOff);
    transport.paused = false;
    transport.draining = false;
    transport.listeners.clear();
    getSlidingSyncManager.mockReset().mockReturnValue({
      pause,
      resume,
      isPaused: () => transport.paused,
      isDrainingPush: () => transport.draining,
      onTransportStateChange: (listener: () => void) => {
        transport.listeners.add(listener);
        return () => transport.listeners.delete(listener);
      },
    });
    mockIsTauri.value = false;
    mockIsMobileTauri.value = true;
    mockCallEmbed.value = undefined;
  });

  it('stops the transport once the app has been hidden for the grace period', () => {
    setVisibility('visible');
    renderHook(() => useSyncOrchestrator(client));

    setVisibility('hidden');
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(pause).not.toHaveBeenCalled();

    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));
    expect(pause).toHaveBeenCalled();
  });

  it('does not stop for a glance at another app', () => {
    setVisibility('visible');
    renderHook(() => useSyncOrchestrator(client));

    setVisibility('hidden');
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS - 500));
    setVisibility('visible');
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));

    expect(pause).not.toHaveBeenCalled();
  });

  it('starts immediately when the app becomes visible', () => {
    setVisibility('hidden');
    transport.paused = true;
    renderHook(() => useSyncOrchestrator(client));
    resume.mockClear();

    setVisibility('visible');
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    expect(resume).toHaveBeenCalled();
  });

  it('starts a parked transport when every visibility event is missed', () => {
    setVisibility('hidden');
    transport.paused = true;
    renderHook(() => useSyncOrchestrator(client));
    resume.mockClear();

    setVisibility('visible');
    act(() => vi.advanceTimersByTime(2000));

    expect(resume).toHaveBeenCalled();
  });

  it('starts a parked transport for a push drain while still hidden', () => {
    setVisibility('hidden');
    transport.paused = true;
    renderHook(() => useSyncOrchestrator(client));
    resume.mockClear();

    setTransport({ draining: true });

    expect(resume).toHaveBeenCalled();
  });

  it('parks again once the push drain settles', () => {
    setVisibility('hidden');
    transport.draining = true;
    renderHook(() => useSyncOrchestrator(client));

    setTransport({ draining: false });
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));

    expect(pause).toHaveBeenCalled();
  });

  it('keeps polling in the background during a call', () => {
    mockCallEmbed.value = { dispose: vi.fn<() => void>() };
    setVisibility('hidden');

    renderHook(() => useSyncOrchestrator(client));
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));

    expect(pause).not.toHaveBeenCalled();
  });

  it('starts a parked transport even when the browser reports offline', () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    setVisibility('visible');
    transport.paused = true;

    renderHook(() => useSyncOrchestrator(client));

    expect(resume).toHaveBeenCalled();
  });

  it('starts on tauri://resumed without waiting for visibilitychange', async () => {
    mockIsTauri.value = true;
    setVisibility('hidden');
    transport.paused = true;
    renderHook(() => useSyncOrchestrator(client));
    await act(async () => {
      await Promise.resolve();
    });
    resume.mockClear();

    const resumedCallback = listen.mock.calls.find(([event]) => event === 'tauri://resumed')?.[1];
    setVisibility('visible');
    act(() => resumedCallback?.());

    expect(resume).toHaveBeenCalled();
  });

  it('keeps polling when a browser tab is hidden', () => {
    mockIsMobileTauri.value = false;
    setVisibility('hidden');

    renderHook(() => useSyncOrchestrator(client));
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));

    expect(pause).not.toHaveBeenCalled();
  });

  it('does nothing without a client', () => {
    renderHook(() => useSyncOrchestrator(undefined));
    act(() => vi.advanceTimersByTime(STOP_DELAY_MS));

    expect(pause).not.toHaveBeenCalled();
    expect(resume).not.toHaveBeenCalled();
  });

  it('starts the transport on unmount so it is never left parked', () => {
    setVisibility('hidden');
    transport.paused = true;
    const { unmount } = renderHook(() => useSyncOrchestrator(client));
    resume.mockClear();

    unmount();

    expect(resume).toHaveBeenCalled();
  });
});
