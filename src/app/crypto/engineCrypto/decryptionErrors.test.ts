import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DecryptionFailureCode } from 'matrix-js-sdk/lib/crypto-api';
import { KnownMembership } from '$types/matrix-sdk';
import type { MatrixClient, MatrixEvent } from '$types/matrix-sdk';
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

type EngineState = {
  code: number;
  maybeWithheld?: string | null;
  deviceCreationTimeMs?: number;
  decryptionKeyBase64?: string | null;
};

const client = (backupInfo: unknown = BACKUP_INFO) =>
  ({
    http: {
      authedRequest: vi.fn<(...args: never[]) => Promise<unknown>>(async () => {
        if (backupInfo === null) throw Object.assign(new Error('nope'), { errcode: 'M_NOT_FOUND' });
        return backupInfo;
      }),
    },
  }) as unknown as MatrixClient;

const engine = ({
  code,
  maybeWithheld = null,
  deviceCreationTimeMs = 0,
  decryptionKeyBase64 = null,
}: EngineState) => {
  mockInvoke.mockImplementation(async (_identity, method) => {
    if (method === 'decryptRoomEvent') {
      return { className: 'DecryptionError', code, description: 'engine says no', maybeWithheld };
    }
    if (method === 'deviceCreationTimeMs') return deviceCreationTimeMs;
    if (method === 'getBackupKeys') return { backupVersion: '7', decryptionKeyBase64 };
    if (method === 'backupVersion') return null;
    return null;
  });
};

const eventAt = (ts: number, membership?: string) =>
  ({
    getRoomId: () => '!room:e.org',
    getId: () => '$e',
    getWireType: () => 'm.room.encrypted',
    getSender: () => '@them:e.org',
    getTs: () => ts,
    getMembershipAtEvent: () => membership,
    getWireContent: () => ({ session_id: 'session-1', sender_key: 'key' }),
  }) as unknown as MatrixEvent;

const decrypt = (event: MatrixEvent, mx = client()) =>
  new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' }).decryptEvent(event);

const codeOf = async (promise: Promise<unknown>) => {
  const error = await promise.then(
    () => undefined,
    (err: unknown) => err as { code?: string }
  );
  return error?.code;
};

describe('decryption failures', () => {
  beforeEach(() => mockInvoke.mockReset());

  it('reports a missing room key rather than a bare unknown error', async () => {
    engine({ code: 0 });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.MEGOLM_UNKNOWN_INBOUND_SESSION_ID
    );
  });

  it('reports a ratcheted session', async () => {
    engine({ code: 1 });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.OLM_UNKNOWN_MESSAGE_INDEX
    );
  });

  it('reports a withheld key', async () => {
    engine({ code: 0, maybeWithheld: 'm.unauthorised' });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(DecryptionFailureCode.MEGOLM_KEY_WITHHELD);
  });

  it('singles out a key withheld because we are unverified', async () => {
    engine({
      code: 0,
      maybeWithheld: 'The sender has disabled encrypting to unverified devices.',
    });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.MEGOLM_KEY_WITHHELD_FOR_UNVERIFIED_DEVICE
    );
  });

  it('reports a message sent while we were not in the room', async () => {
    engine({ code: 0 });

    expect(await codeOf(decrypt(eventAt(100, KnownMembership.Leave)))).toBe(
      DecryptionFailureCode.HISTORICAL_MESSAGE_USER_NOT_JOINED
    );
  });

  it('reports history with no backup on the server', async () => {
    engine({ code: 0, deviceCreationTimeMs: 5000 });

    expect(await codeOf(decrypt(eventAt(100), client(null)))).toBe(
      DecryptionFailureCode.HISTORICAL_MESSAGE_NO_KEY_BACKUP
    );
  });

  it('reports history this device cannot reach because backup is unconfigured', async () => {
    engine({ code: 0, deviceCreationTimeMs: 5000 });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.HISTORICAL_MESSAGE_BACKUP_UNCONFIGURED
    );
  });

  it('reports history a working backup should eventually supply', async () => {
    engine({ code: 0, deviceCreationTimeMs: 5000, decryptionKeyBase64: 'AAAA' });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.HISTORICAL_MESSAGE_WORKING_BACKUP
    );
  });

  it('reports an untrusted sender identity', async () => {
    engine({ code: 5 });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(
      DecryptionFailureCode.SENDER_IDENTITY_PREVIOUSLY_VERIFIED
    );
  });

  it('reports an unknown and an unsigned sender device', async () => {
    engine({ code: 3 });
    expect(await codeOf(decrypt(eventAt(100)))).toBe(DecryptionFailureCode.UNKNOWN_SENDER_DEVICE);

    engine({ code: 4 });
    expect(await codeOf(decrypt(eventAt(100)))).toBe(DecryptionFailureCode.UNSIGNED_SENDER_DEVICE);
  });

  it('falls back to unknown for anything else', async () => {
    engine({ code: 6 });

    expect(await codeOf(decrypt(eventAt(100)))).toBe(DecryptionFailureCode.UNKNOWN_ERROR);
  });
});
