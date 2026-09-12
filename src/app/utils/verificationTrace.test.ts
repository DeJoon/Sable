import * as Sentry from '@sentry/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { traceVerification, warnVerification } from './verificationTrace';

vi.mock('@sentry/react', () => ({
  addBreadcrumb: vi.fn<(input: unknown) => void>(),
  logger: {
    info: vi.fn<(message: string, attrs: unknown) => void>(),
    warn: vi.fn<(message: string, attrs: unknown) => void>(),
  },
}));

describe('verification tracing', () => {
  beforeEach(() => vi.clearAllMocks());

  it('reaches Sentry without depending on the opt-in debug logger', () => {
    traceVerification('Received a verification to-device event', {
      sender: '@me:e.org',
      transactionId: '$f',
    });

    expect(Sentry.logger.info).toHaveBeenCalledWith(
      '[crypto:verification] Received a verification to-device event',
      { sender: '@me:e.org', transactionId: '$f' }
    );
    expect(Sentry.addBreadcrumb).toHaveBeenCalledOnce();
  });

  it('drops attributes Sentry cannot index instead of failing', () => {
    warnVerification('The engine kept ignoring a verification request', {
      sender: '@me:e.org',
      clockSkewSeconds: null,
    });

    expect(Sentry.logger.warn).toHaveBeenCalledWith(
      '[crypto:verification] The engine kept ignoring a verification request',
      { sender: '@me:e.org' }
    );
  });
});
