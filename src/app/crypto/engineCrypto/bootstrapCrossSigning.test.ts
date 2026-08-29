import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Method } from 'matrix-js-sdk/lib/http-api';
import type { MatrixClient } from '$types/matrix-sdk';
import { engineInvoke } from '../olmMachine/engineInvoke';
import { EngineCrypto } from './EngineCrypto';

vi.mock('../olmMachine/engineInvoke', () => ({
  engineInvoke: vi.fn<(...args: never[]) => Promise<unknown>>(),
}));

const mockInvoke = vi.mocked(engineInvoke);

const BOOTSTRAP_REQUESTS = {
  uploadKeysRequest: {
    id: 'u1',
    type: 0,
    className: 'KeysUploadRequest',
    body: '{"device_keys":{}}',
  },
  uploadSigningKeysRequest: {
    className: 'UploadSigningKeysRequest',
    id: null,
    body: '{"master_key":{"keys":{}}}',
  },
  uploadSignaturesRequest: { type: 4, className: 'SignatureUploadRequest', body: '{}' },
};

const STORED_KEYS = {
  'm.cross_signing.master': 'msk',
  'm.cross_signing.self_signing': 'ssk',
  'm.cross_signing.user_signing': 'usk',
};

type ClientOptions = {
  storage?: Record<string, string>;
  hasKey?: boolean;
};

const clientStub = ({ storage = {}, hasKey = true }: ClientOptions = {}) => {
  const store = vi.fn<(name: string, value: string) => Promise<void>>(async () => undefined);
  const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => ({}));
  const mx = {
    http: { authedRequest },
    secretStorage: {
      get: async (name: string) => storage[name] ?? null,
      hasKey: async () => hasKey,
      store,
    },
  } as unknown as MatrixClient;
  return { mx, authedRequest, store };
};

const requestsTo = (authedRequest: ReturnType<typeof clientStub>['authedRequest'], url: string) =>
  authedRequest.mock.calls.filter((call) => call[1] === url);

const invoked = (method: string) => mockInvoke.mock.calls.filter(([, name]) => name === method);

const engine = (overrides: (method: string, args?: Record<string, unknown>) => unknown) => {
  mockInvoke.mockImplementation(async (_identity, method, args) => {
    const result = overrides(method as string, args as Record<string, unknown>);
    return result === undefined ? null : result;
  });
};

const noKeys = { hasMaster: false, hasSelfSigning: false, hasUserSigning: false };
const allKeys = { hasMaster: true, hasSelfSigning: true, hasUserSigning: true };

describe('bootstrapCrossSigning', () => {
  beforeEach(() => mockInvoke.mockReset());

  it('imports the keys from secret storage instead of resetting', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return noKeys;
      if (method === 'importCrossSigningKeys') return allKeys;
      if (method === 'device.verify') return { id: null, type: 4, body: '{}' };
      return undefined;
    });
    const { mx, authedRequest } = clientStub({ storage: STORED_KEYS });

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({});

    expect(invoked('bootstrapCrossSigning')).toHaveLength(0);
    expect(invoked('importCrossSigningKeys')[0]?.[2]).toMatchObject({
      master_key: 'msk',
      self_signing_key: 'ssk',
      user_signing_key: 'usk',
    });
    expect(requestsTo(authedRequest, '/_matrix/client/v3/keys/signatures/upload')).toHaveLength(1);
  });

  it('refuses a secret storage import the engine did not actually apply', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return noKeys;
      if (method === 'importCrossSigningKeys') return { ...allKeys, hasUserSigning: false };
      return undefined;
    });
    const { mx } = clientStub({ storage: STORED_KEYS });

    await expect(
      new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({})
    ).rejects.toThrow('could not be imported');
  });

  it('creates and publishes an identity when there is none anywhere', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return noKeys;
      if (method === 'bootstrapCrossSigning') return BOOTSTRAP_REQUESTS;
      if (method === 'exportCrossSigningKeys') return { masterKey: 'msk' };
      return undefined;
    });
    const { mx, authedRequest } = clientStub();

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({});

    expect(invoked('bootstrapCrossSigning')[0]?.[2]).toMatchObject({ reset: true });
    expect(requestsTo(authedRequest, '/_matrix/client/v3/keys/upload')).toHaveLength(1);
    expect(requestsTo(authedRequest, '/keys/device_signing/upload')).toHaveLength(1);
    expect(requestsTo(authedRequest, '/_matrix/client/v3/keys/signatures/upload')).toHaveLength(1);
  });

  it('marks only the queued device-key upload as sent', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return noKeys;
      if (method === 'bootstrapCrossSigning') return BOOTSTRAP_REQUESTS;
      return undefined;
    });
    const { mx } = clientStub();

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({});

    const marked = invoked('markRequestAsSent');
    expect(marked).toHaveLength(1);
    expect(marked[0]?.[2]).toMatchObject({ requestId: 'u1', requestType: 0 });
  });

  it('routes the signing key upload through the interactive-auth callback', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return noKeys;
      if (method === 'bootstrapCrossSigning') return BOOTSTRAP_REQUESTS;
      return undefined;
    });
    const { mx, authedRequest } = clientStub();
    const authUploadDeviceSigningKeys = vi.fn<
      (makeRequest: (auth: Record<string, unknown> | null) => Promise<unknown>) => Promise<void>
    >(async (makeRequest) => {
      await makeRequest({ type: 'm.login.password' });
    });

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({
      setupNewCrossSigning: true,
      authUploadDeviceSigningKeys,
    });

    expect(authUploadDeviceSigningKeys).toHaveBeenCalledTimes(1);
    const call = requestsTo(authedRequest, '/keys/device_signing/upload')[0];
    expect(call?.[0]).toBe(Method.Post);
    expect(call?.[3]).toMatchObject({
      master_key: { keys: {} },
      auth: { type: 'm.login.password' },
    });
  });

  it('backs local keys up to secret storage rather than touching the identity', async () => {
    engine((method) => {
      if (method === 'crossSigningStatus') return allKeys;
      if (method === 'exportCrossSigningKeys') {
        return { masterKey: 'msk', self_signing_key: 'ssk', user_signing_key: 'usk' };
      }
      return undefined;
    });
    const { mx, store } = clientStub();

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({});

    expect(invoked('bootstrapCrossSigning')).toHaveLength(0);
    expect(store.mock.calls.map(([name]) => name)).toEqual([
      'm.cross_signing.master',
      'm.cross_signing.self_signing',
      'm.cross_signing.user_signing',
    ]);
  });

  it('does nothing when the keys are already local and already stored', async () => {
    engine((method) => (method === 'crossSigningStatus' ? allKeys : undefined));
    const { mx, store } = clientStub({ storage: STORED_KEYS });

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).bootstrapCrossSigning({});

    expect(invoked('bootstrapCrossSigning')).toHaveLength(0);
    expect(store).not.toHaveBeenCalled();
  });
});
