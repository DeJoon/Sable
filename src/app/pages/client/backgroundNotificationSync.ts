import { ClientEvent, SyncState, type MatrixClient } from '$types/matrix-sdk';

export const BACKGROUND_SYNC_POLL_TIMEOUT_MS = 60_000;
const INITIAL_SYNC_TIMEOUT_MS = BACKGROUND_SYNC_POLL_TIMEOUT_MS + 30_000;

export const isClientReadyForNotifications = (state: SyncState | string | null): boolean =>
  state === SyncState.Prepared || state === SyncState.Syncing || state === SyncState.Catchup;

export const waitForSync = (mx: MatrixClient, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    if (isClientReadyForNotifications(mx.getSyncState())) {
      resolve();
      return;
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      clearTimeout(timer);
      mx.removeListener(ClientEvent.Sync, onSync);
      signal?.removeEventListener('abort', onAbort);
    };
    const onSync = (state: SyncState) => {
      if (!isClientReadyForNotifications(state)) return;
      cleanup();
      resolve();
    };
    const onAbort = () => {
      cleanup();
      reject(signal?.reason);
    };
    timer = setTimeout(() => {
      cleanup();
      reject(new Error('background client sync timed out'));
    }, INITIAL_SYNC_TIMEOUT_MS);
    mx.on(ClientEvent.Sync, onSync);
    signal?.addEventListener('abort', onAbort, { once: true });
    onSync(mx.getSyncState() as SyncState);
  });
