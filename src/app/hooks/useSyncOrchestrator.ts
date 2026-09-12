import { useCallback, useEffect, useSyncExternalStore } from 'react';
import { useAtomValue } from 'jotai';
import { TauriEvent, listen } from '@tauri-apps/api/event';
import { isTauri } from '@tauri-apps/api/core';
import type { MatrixClient } from '$types/matrix-sdk';
import { getSlidingSyncManager } from '$client/initMatrix';
import { nextSyncAction } from '$client/syncActivity';
import { isMobileTauri } from '$utils/platform';
import { callEmbedAtom } from '../state/callEmbed';

const VISIBILITY_RECHECK_MS = 2000;

const STOP_DELAY_MS = 3000;

const noopUnsubscribe = () => {};

const subscribeToVisibility = (onChange: () => void): (() => void) => {
  document.addEventListener('visibilitychange', onChange);
  window.addEventListener('focus', onChange);
  window.addEventListener('pageshow', onChange);
  const recheck = window.setInterval(onChange, VISIBILITY_RECHECK_MS);

  let cancelled = false;
  let unlistenResumed: (() => void) | undefined;
  if (isTauri()) {
    void listen(TauriEvent.WINDOW_RESUMED, onChange).then((off) => {
      if (cancelled) off();
      else unlistenResumed = off;
    });
  }

  return () => {
    cancelled = true;
    document.removeEventListener('visibilitychange', onChange);
    window.removeEventListener('focus', onChange);
    window.removeEventListener('pageshow', onChange);
    window.clearInterval(recheck);
    unlistenResumed?.();
  };
};

const getVisible = () => document.visibilityState !== 'hidden';

export const useSyncOrchestrator = (mx: MatrixClient | undefined): void => {
  const callActive = useAtomValue(callEmbedAtom) !== undefined;

  const visible = useSyncExternalStore(subscribeToVisibility, getVisible);

  const subscribeToTransport = useCallback(
    (onChange: () => void) =>
      mx
        ? (getSlidingSyncManager(mx)?.onTransportStateChange(onChange) ?? noopUnsubscribe)
        : noopUnsubscribe,
    [mx]
  );
  const paused = useSyncExternalStore(
    subscribeToTransport,
    useCallback(() => (mx ? (getSlidingSyncManager(mx)?.isPaused() ?? false) : false), [mx])
  );
  const drainingPush = useSyncExternalStore(
    subscribeToTransport,
    useCallback(() => (mx ? (getSlidingSyncManager(mx)?.isDrainingPush() ?? false) : false), [mx])
  );

  useEffect(() => {
    if (!mx || !isMobileTauri()) return undefined;
    const manager = getSlidingSyncManager(mx);
    if (!manager) return undefined;

    const action = nextSyncAction(paused, { visible, callActive, drainingPush });
    if (action === 'none') return undefined;
    if (action === 'start') {
      manager.resume();
      return undefined;
    }

    const timer = window.setTimeout(() => manager.pause(), STOP_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [mx, paused, visible, callActive, drainingPush]);

  useEffect(
    () => () => {
      if (mx) getSlidingSyncManager(mx)?.resume();
    },
    [mx]
  );
};
