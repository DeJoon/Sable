import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import * as RustSdkCryptoJs from '@matrix-org/matrix-sdk-crypto-wasm';
import { CryptoEvent } from 'matrix-js-sdk/lib/crypto-api';
import { encodeBase64 } from 'matrix-js-sdk/lib/base64';
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

const clientSpy = () => {
  const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => BACKUP_INFO);
  return { mx: { http: { authedRequest } } as unknown as MatrixClient, authedRequest };
};

const settle = () =>
  new Promise((resolve) => {
    setTimeout(resolve, 0);
  });

/**
 * Nothing else calls checkKeyBackupAndEnable, so without this the engine never runs
 * enableBackupV1 and the backup reads as disconnected on a fully verified device.
 */
describe('key backup connection', () => {
  beforeEach(() => mockInvoke.mockReset());

  it('enables a trusted backup on construction', async () => {
    const { mx } = clientSpy();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys') return { backupVersion: null, decryptionKeyBase64: null };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    expect(crypto).toBeDefined();
    await settle();

    const enabled = mockInvoke.mock.calls.filter(([, method]) => method === 'enableBackupV1');
    expect(enabled).toHaveLength(1);
    expect(enabled[0]?.[2]).toMatchObject({ publicKeyBase64: 'cHVibGlj', version: '7' });
  });

  it('leaves an untrusted backup alone', async () => {
    const { mx } = clientSpy();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: false };
      if (method === 'getBackupKeys') return { backupVersion: null, decryptionKeyBase64: null };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    expect(crypto).toBeDefined();
    await settle();

    expect(mockInvoke.mock.calls.some(([, method]) => method === 'enableBackupV1')).toBe(false);
  });

  it('retries once our own identity becomes trusted', async () => {
    const { mx } = clientSpy();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys') return { backupVersion: null, decryptionKeyBase64: null };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await settle();
    crypto.onUserIdentityUpdated('@me:e.org');
    await settle();

    expect(mockInvoke.mock.calls.filter(([, method]) => method === 'enableBackupV1')).toHaveLength(
      2
    );
  });

  it('ignores another user becoming trusted', async () => {
    const { mx } = clientSpy();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys') return { backupVersion: null, decryptionKeyBase64: null };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await settle();
    crypto.onUserIdentityUpdated('@them:e.org');
    await settle();

    expect(mockInvoke.mock.calls.filter(([, method]) => method === 'enableBackupV1')).toHaveLength(
      1
    );
  });
});

describe('key backup status reporting', () => {
  const PRIVATE_KEY_BASE64 = encodeBase64(new Uint8Array(32).fill(9));
  let publicKey: string;

  beforeAll(async () => {
    await RustSdkCryptoJs.initAsync();
    const key = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(PRIVATE_KEY_BASE64);
    publicKey = key.megolmV1PublicKey.publicKeyBase64;
    key.free();
  });

  beforeEach(() => mockInvoke.mockReset());

  const watch = (crypto: EngineCrypto) => {
    const status = vi.fn<(enabled: boolean) => void>();
    crypto.on(CryptoEvent.KeyBackupStatus, status);
    return status;
  };

  const engineWith = (
    backupKeys: { backupVersion: string | null; decryptionKeyBase64: string | null },
    trusted: boolean
  ) => {
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'verifyBackup') return { trusted };
      if (method === 'getBackupKeys') return backupKeys;
      if (method === 'backupVersion') return backupKeys.backupVersion;
      return null;
    });
  };

  it('announces the backup once it enables it', async () => {
    const { mx } = clientSpy();
    engineWith({ backupVersion: null, decryptionKeyBase64: null }, true);

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    const status = watch(crypto);
    await crypto.checkKeyBackupAndEnable();

    expect(status).toHaveBeenCalledWith(true);
  });

  it('enables on a matching decryption key without a trusted signature', async () => {
    const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => ({
      version: '7',
      algorithm: 'm.megolm_backup.v1.curve25519-aes-sha2',
      auth_data: { public_key: publicKey },
    }));
    const mx = { http: { authedRequest } } as unknown as MatrixClient;
    engineWith({ backupVersion: null, decryptionKeyBase64: PRIVATE_KEY_BASE64 }, false);

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await crypto.checkKeyBackupAndEnable();

    const enabled = mockInvoke.mock.calls.filter(([, method]) => method === 'enableBackupV1');
    expect(enabled.length).toBeGreaterThan(0);
    expect(enabled[0]?.[2]).toMatchObject({ publicKeyBase64: publicKey, version: '7' });
  });

  it('switches away from a stale active version', async () => {
    const { mx } = clientSpy();
    engineWith({ backupVersion: '6', decryptionKeyBase64: PRIVATE_KEY_BASE64 }, true);

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    const status = watch(crypto);
    await crypto.checkKeyBackupAndEnable();

    const order = mockInvoke.mock.calls.map(([, method]) => method);
    expect(order.indexOf('disableBackup')).toBeLessThan(order.indexOf('enableBackupV1'));
    expect(status).toHaveBeenCalledWith(false);
    expect(status).toHaveBeenLastCalledWith(true);
  });

  it('turns the backup off when the server no longer has one', async () => {
    const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => {
      throw Object.assign(new Error('not found'), { errcode: 'M_NOT_FOUND' });
    });
    const mx = { http: { authedRequest } } as unknown as MatrixClient;
    engineWith({ backupVersion: '7', decryptionKeyBase64: PRIVATE_KEY_BASE64 }, true);

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    const status = watch(crypto);
    expect(await crypto.checkKeyBackupAndEnable()).toBeNull();

    expect(mockInvoke.mock.calls.some(([, method]) => method === 'disableBackup')).toBe(true);
    expect(status).toHaveBeenCalledWith(false);
  });

  it('leaves a still-current backup enabled', async () => {
    const { mx } = clientSpy();
    engineWith({ backupVersion: '7', decryptionKeyBase64: PRIVATE_KEY_BASE64 }, true);

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await crypto.checkKeyBackupAndEnable();

    expect(mockInvoke.mock.calls.some(([, method]) => method === 'disableBackup')).toBe(false);
    expect(mockInvoke.mock.calls.some(([, method]) => method === 'enableBackupV1')).toBe(false);
  });
});
