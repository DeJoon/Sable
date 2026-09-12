import { EventEmitter } from 'events';
import { afterEach, expect, it, vi } from 'vitest';
import { ClientEvent, SyncState, type MatrixClient } from '$types/matrix-sdk';
import { waitForSync } from './backgroundNotificationSync';

afterEach(() => vi.useRealTimers());

it('allows a background sync poll to finish after thirty seconds', async () => {
  vi.useFakeTimers();
  const mx = Object.assign(new EventEmitter(), { getSyncState: () => null });
  const ready = waitForSync(mx as unknown as MatrixClient);
  const outcome = ready.then(
    () => 'ready',
    () => 'failed'
  );
  await vi.advanceTimersByTimeAsync(45_000);
  mx.emit(ClientEvent.Sync, SyncState.Prepared);
  await expect(outcome).resolves.toBe('ready');
  expect(mx.listenerCount(ClientEvent.Sync)).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
});

it('cancels an in-flight wait when its background client is disposed', async () => {
  vi.useFakeTimers();
  const mx = Object.assign(new EventEmitter(), { getSyncState: () => null });
  const controller = new AbortController();
  const ready = waitForSync(mx as unknown as MatrixClient, controller.signal);
  controller.abort();
  await expect(ready).rejects.toMatchObject({ name: 'AbortError' });
  expect(mx.listenerCount(ClientEvent.Sync)).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
});

it('still times out a stalled client and releases its listener', async () => {
  vi.useFakeTimers();
  const mx = Object.assign(new EventEmitter(), { getSyncState: () => null });
  const result = waitForSync(mx as unknown as MatrixClient).catch((error) => error);
  await vi.advanceTimersByTimeAsync(90_000);
  expect(await result).toMatchObject({ message: 'background client sync timed out' });
  expect(mx.listenerCount(ClientEvent.Sync)).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
});
