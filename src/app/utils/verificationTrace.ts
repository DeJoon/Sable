import * as Sentry from '@sentry/react';

type TraceData = Record<string, string | number | boolean | null | undefined>;

const attributes = (data: TraceData): Record<string, string | number | boolean> => {
  const out: Record<string, string | number | boolean> = {};
  Object.entries(data).forEach(([key, value]) => {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      out[key] = value;
    }
  });
  return out;
};

export const traceVerification = (message: string, data: TraceData = {}): void => {
  Sentry.addBreadcrumb({
    category: 'crypto.verification',
    message,
    level: 'info',
    data: attributes(data),
  });
  Sentry.logger.info(`[crypto:verification] ${message}`, attributes(data));
};

export const warnToDevice = (message: string, data: TraceData = {}): void => {
  Sentry.addBreadcrumb({
    category: 'crypto.to-device',
    message,
    level: 'warning',
    data: attributes(data),
  });
  Sentry.logger.warn(`[crypto:to-device] ${message}`, attributes(data));
};

export const warnVerification = (message: string, data: TraceData = {}): void => {
  Sentry.addBreadcrumb({
    category: 'crypto.verification',
    message,
    level: 'warning',
    data: attributes(data),
  });
  Sentry.logger.warn(`[crypto:verification] ${message}`, attributes(data));
};
