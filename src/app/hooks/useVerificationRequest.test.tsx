import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { VerificationPhase, VerifierEvent } from '$types/matrix-sdk';
import { useVerificationRequestPhase, useVerifierShowSas } from './useVerificationRequest';

describe('useVerifierShowSas', () => {
  it('publishes SAS callbacks that were ready before the listener subscribed', () => {
    const sasCallbacks = { sas: { emoji: [] } };
    const on = vi.fn<(event: string, handler: () => void) => void>();
    const removeListener = vi.fn<(event: string, handler: () => void) => void>();
    const getShowSasCallbacks = vi.fn<() => typeof sasCallbacks | null>(() => sasCallbacks);
    const onCallback = vi.fn<(callbacks: unknown) => void>();

    const { unmount } = renderHook(() =>
      useVerifierShowSas(
        {
          on,
          removeListener,
          getShowSasCallbacks,
        } as never,
        onCallback as never
      )
    );

    expect(on).toHaveBeenCalledWith(VerifierEvent.ShowSas, onCallback);
    expect(getShowSasCallbacks).toHaveBeenCalledOnce();
    expect(onCallback).toHaveBeenCalledWith(sasCallbacks);
    expect(on.mock.invocationCallOrder[0]).toBeLessThan(
      getShowSasCallbacks.mock.invocationCallOrder[0] ?? 0
    );

    unmount();
    expect(removeListener).toHaveBeenCalledWith(VerifierEvent.ShowSas, onCallback);
  });
});

describe('useVerificationRequestPhase', () => {
  it('reports the new request phase when the request is swapped out', () => {
    const stub = (phase: VerificationPhase) => ({
      phase,
      on: vi.fn<() => void>(),
      removeListener: vi.fn<() => void>(),
    });
    const cancelled = stub(VerificationPhase.Cancelled);
    const fresh = stub(VerificationPhase.Requested);

    const { result, rerender } = renderHook(
      ({ request }) => useVerificationRequestPhase(request as never),
      { initialProps: { request: cancelled } }
    );

    expect(result.current).toBe(VerificationPhase.Cancelled);

    rerender({ request: fresh });
    expect(result.current).toBe(VerificationPhase.Requested);
  });
});
