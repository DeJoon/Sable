import { useCallback, useEffect, useRef, useState } from 'react';
import * as Sentry from '@sentry/react';
import { HttpApiEvent, type MatrixClient } from '$types/matrix-sdk';
import { stopClient } from '$client/initMatrix';
import { useMatrixEvent } from './useMatrixEvent';

export const useSessionLogout = (mx?: MatrixClient): boolean => {
  const [expiredClient, setExpiredClient] = useState<MatrixClient>();
  const handledClient = useRef<MatrixClient | undefined>(undefined);
  const handleLogout = useCallback(() => {
    if (!mx || handledClient.current === mx) return;
    handledClient.current = mx;
    Sentry.addBreadcrumb({
      category: 'auth',
      message: 'Session requires reauthentication',
      level: 'warning',
    });
    Sentry.metrics.count('sable.auth.forced_logout', 1);
    stopClient(mx);
    setExpiredClient(mx);
  }, [mx]);

  useMatrixEvent(mx, HttpApiEvent.SessionLoggedOut, handleLogout);
  useEffect(
    () => () => {
      if (mx && handledClient.current !== mx) stopClient(mx);
    },
    [mx]
  );
  return mx !== undefined && expiredClient === mx;
};
