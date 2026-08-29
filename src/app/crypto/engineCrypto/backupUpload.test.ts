import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as RustSdkCryptoJs from '@matrix-org/matrix-sdk-crypto-wasm';
import { CryptoEvent } from 'matrix-js-sdk/lib/crypto-api';
import type { MatrixClient } from '$types/matrix-sdk';
import { engineInvoke } from '../olmMachine/engineInvoke';
import { EngineCrypto } from './EngineCrypto';

vi.mock('../olmMachine/engineInvoke', () => ({
  engineInvoke: vi.fn<(...args: never[]) => Promise<unknown>>(),
}));

const mockInvoke = vi.mocked(engineInvoke);

const BACKUP_INFO = {
  version: '7',
  algorithm: 'm.megolm_backup.v1.curve25519-aes-sha2',
  auth_data: { public_key: 'cHVibGlj' },
};

const clientStub = () => {
  const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => BACKUP_INFO);
  return { http: { authedRequest } } as unknown as MatrixClient;
};

const tick = () =>
  new Promise((resolve) => {
    setTimeout(resolve, 0);
  });

const settle = async () => {
  for (let i = 0; i < 10; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await tick();
  }
};

const invoked = (method: string) => mockInvoke.mock.calls.filter(([, name]) => name === method);

describe('key backup upload', () => {
  beforeEach(() => mockInvoke.mockReset());

  const backupRequest = { id: 'r1', type: 6, version: '7', body: '{"rooms":{}}' };

  it('uploads pending room keys once the backup is connected', async () => {
    let pending = 1;
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys') return { backupVersion: '7', decryptionKeyBase64: null };
      if (method === 'isBackupEnabled') return true;
      if (method === 'backupVersion') return '7';
      if (method === 'backupRoomKeys') {
        if (pending === 0) return null;
        pending -= 1;
        return backupRequest;
      }
      if (method === 'roomKeyCounts') return { total: 4, backedUp: 3 };
      return null;
    });

    const crypto = new EngineCrypto(clientStub(), { userId: '@me:e.org', deviceId: 'D' });
    const remaining = vi.fn<(count: number) => void>();
    crypto.on(CryptoEvent.KeyBackupSessionsRemaining, remaining);
    await settle();

    expect(invoked('backupRoomKeys').length).toBeGreaterThan(0);
    expect(invoked('markRequestAsSent')[0]?.[2]).toMatchObject({ requestId: 'r1', requestType: 6 });
    expect(remaining).toHaveBeenCalledWith(1);
    expect(remaining).toHaveBeenLastCalledWith(0);
  });

  it('does not upload when the engine has no backup enabled', async () => {
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: false };
      if (method === 'getBackupKeys') return { backupVersion: null, decryptionKeyBase64: null };
      if (method === 'isBackupEnabled') return false;
      if (method === 'backupVersion') return null;
      return null;
    });

    const crypto = new EngineCrypto(clientStub(), { userId: '@me:e.org', deviceId: 'D' });
    crypto.onKeysChanged();
    await settle();

    expect(invoked('backupRoomKeys')).toHaveLength(0);
  });

  it('uploads newly received room keys', async () => {
    let pending = 2;
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: false };
      if (method === 'getBackupKeys') return { backupVersion: '7', decryptionKeyBase64: null };
      if (method === 'isBackupEnabled') return true;
      if (method === 'backupVersion') return '7';
      if (method === 'backupRoomKeys') {
        if (pending === 0) return null;
        pending -= 1;
        return backupRequest;
      }
      if (method === 'roomKeyCounts') return { total: 2, backedUp: 2 };
      return null;
    });

    const crypto = new EngineCrypto(clientStub(), { userId: '@me:e.org', deviceId: 'D' });
    await settle();
    crypto.onKeysChanged();
    await settle();

    expect(invoked('backupRoomKeys').length).toBeGreaterThan(1);
  });
});

describe('resetKeyBackup', () => {
  beforeAll(() => RustSdkCryptoJs.initAsync());

  beforeEach(() => mockInvoke.mockReset());

  it('gossips the new backup key to our other verified devices', async () => {
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'isBackupEnabled') return false;
      if (method === 'backupVersion') return null;
      return null;
    });
    const store = vi.fn<(name: string, value: string) => Promise<void>>(async () => undefined);
    const mx = {
      http: {
        authedRequest: vi.fn<(...args: never[]) => Promise<unknown>>(async () => ({
          version: '8',
        })),
      },
      secretStorage: { store },
    } as unknown as MatrixClient;

    await new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).resetKeyBackup();

    const order = mockInvoke.mock.calls.map(([, method]) => method);
    expect(order.indexOf('saveBackupDecryptionKey')).toBeLessThan(
      order.indexOf('pushSecretToVerifiedDevices')
    );
    expect(invoked('pushSecretToVerifiedDevices')[0]?.[2]).toMatchObject({
      secretName: 'm.megolm_backup.v1',
    });
    expect(invoked('getMissingSessions')[0]?.[2]).toMatchObject({ users: ['@me:e.org'] });
    expect(store).toHaveBeenCalledWith('m.megolm_backup.v1', expect.any(String));
  });
});
