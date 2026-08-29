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

const PRIVATE_KEY_BASE64 = encodeBase64(new Uint8Array(32).fill(7));

let publicKey: string;

const clientFor = (backupInfo: unknown) =>
  ({
    http: { authedRequest: vi.fn<(...args: never[]) => Promise<unknown>>(async () => backupInfo) },
  }) as unknown as MatrixClient;

const invoked = (method: string) => mockInvoke.mock.calls.filter(([, name]) => name === method);

describe('secret inbox', () => {
  beforeAll(async () => {
    await RustSdkCryptoJs.initAsync();
    const key = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(PRIVATE_KEY_BASE64);
    publicKey = key.megolmV1PublicKey.publicKeyBase64;
    key.free();
  });

  beforeEach(() => mockInvoke.mockReset());

  const backupInfo = { version: '7', algorithm: 'm.megolm_backup.v1.curve25519-aes-sha2' };

  it('saves a gossiped backup key that matches the server backup', async () => {
    const mx = clientFor({ ...backupInfo, auth_data: { public_key: publicKey } });
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'getSecretsFromInbox') return [PRIVATE_KEY_BASE64];
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys')
        return { backupVersion: '7', decryptionKeyBase64: PRIVATE_KEY_BASE64 };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    const cached = vi.fn<(version: string) => void>();
    crypto.on(CryptoEvent.KeyBackupDecryptionKeyCached, cached);

    await crypto.checkSecrets('m.megolm_backup.v1');

    expect(invoked('saveBackupDecryptionKey')[0]?.[2]).toMatchObject({
      decryptionKey: PRIVATE_KEY_BASE64,
      version: '7',
    });
    expect(cached).toHaveBeenCalledWith('7');
    expect(invoked('deleteSecretsFromInbox')).toHaveLength(1);
  });

  it('drops a key for a backup other than the one on the server', async () => {
    const mx = clientFor({ ...backupInfo, auth_data: { public_key: 'c29tZW9uZS1lbHNl' } });
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'getSecretsFromInbox') return [PRIVATE_KEY_BASE64];
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await crypto.checkSecrets('m.megolm_backup.v1');

    expect(invoked('saveBackupDecryptionKey')).toHaveLength(0);
    expect(invoked('deleteSecretsFromInbox')).toHaveLength(1);
  });

  it('survives an unusable value and keeps reading the rest', async () => {
    const mx = clientFor({ ...backupInfo, auth_data: { public_key: publicKey } });
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'getSecretsFromInbox') return ['not-a-key', PRIVATE_KEY_BASE64];
      if (method === 'verifyBackup') return { trusted: true };
      if (method === 'getBackupKeys')
        return { backupVersion: '7', decryptionKeyBase64: PRIVATE_KEY_BASE64 };
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await crypto.checkSecrets('m.megolm_backup.v1');

    expect(invoked('saveBackupDecryptionKey')).toHaveLength(1);
  });

  it('ignores secrets the engine handles itself', async () => {
    const mx = clientFor({ ...backupInfo, auth_data: { public_key: publicKey } });
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'getSecretsFromInbox') return ['whatever'];
      return null;
    });

    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    await crypto.checkSecrets('m.cross_signing.master');

    expect(invoked('saveBackupDecryptionKey')).toHaveLength(0);
    expect(invoked('deleteSecretsFromInbox')[0]?.[2]).toMatchObject({
      secretName: 'm.cross_signing.master',
    });
  });
});
