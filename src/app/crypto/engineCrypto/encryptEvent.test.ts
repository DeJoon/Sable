import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HistoryVisibility } from 'matrix-js-sdk/lib/@types/partials';
import {
  AllDevicesIsolationMode,
  OnlySignedDevicesIsolationMode,
} from 'matrix-js-sdk/lib/crypto-api';
import type { MatrixClient, MatrixEvent, Room } from '$types/matrix-sdk';
import { engineInvoke } from '../olmMachine/engineInvoke';
import { EngineCrypto } from './EngineCrypto';

vi.mock('../olmMachine/engineInvoke', () => ({
  engineInvoke: vi.fn<(...args: never[]) => Promise<unknown>>(),
}));

const mockInvoke = vi.mocked(engineInvoke);

const authedRequest = vi.fn<(...args: never[]) => Promise<unknown>>(async () => null);
const mx = { http: { authedRequest } } as unknown as MatrixClient;

type RoomOptions = {
  encryption?: Record<string, unknown>;
  historyVisibility?: HistoryVisibility;
  blacklistUnverified?: boolean | null;
};

const roomStub = ({
  encryption,
  historyVisibility = HistoryVisibility.Shared,
  blacklistUnverified = false,
}: RoomOptions = {}) =>
  ({
    roomId: '!room:e.org',
    getEncryptionTargetMembers: async () => [{ userId: '@a:e.org' }],
    getHistoryVisibility: () => historyVisibility,
    getBlacklistUnverifiedDevices: () => blacklistUnverified,
    currentState: {
      getStateEvents: () => (encryption ? { getContent: () => encryption } : null),
    },
  }) as unknown as Room;

const event = {
  getType: () => 'm.room.message',
  getContent: () => ({ body: 'hi' }),
  makeEncrypted: vi.fn<(...args: never[]) => void>(),
} as unknown as MatrixEvent;

const shareArgs = () =>
  mockInvoke.mock.calls.find(([, method]) => method === 'shareRoomKey')?.[2] as
    | Record<string, unknown>
    | undefined;

const encrypt = async (room: Room, isolation?: AllDevicesIsolationMode) => {
  const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
  if (isolation) crypto.setDeviceIsolationMode(isolation);
  await crypto.encryptEvent(event, room);
};

describe('encryptEvent settings', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    authedRequest.mockClear();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'encryptRoomEvent') return '{}';
      if (method === 'identityKeys') return { ed25519: 'ed', curve25519: 'curve' };
      return null;
    });
  });

  it('sends the settings the engine requires', async () => {
    await encrypt(roomStub());

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      algorithm: 'm.megolm.v1.aes-sha2',
      historyVisibility: HistoryVisibility.Shared,
      sharingStrategy: 'allDevices',
    });
  });

  it('converts the room rotation period from milliseconds to microseconds', async () => {
    await encrypt(
      roomStub({ encryption: { rotation_period_ms: 604800000, rotation_period_msgs: 100 } })
    );

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      rotationPeriod: 604800000000,
      rotationPeriodMessages: 100,
    });
  });

  it('omits a rotation the room does not configure', async () => {
    await encrypt(roomStub());

    const settings = shareArgs()?.encryptionSettings as Record<string, unknown>;
    expect(settings.rotationPeriod).toBeUndefined();
    expect(settings.rotationPeriodMessages).toBeUndefined();
  });

  it('carries the room history visibility', async () => {
    await encrypt(roomStub({ historyVisibility: HistoryVisibility.Invited }));

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      historyVisibility: HistoryVisibility.Invited,
    });
  });

  it('restricts sharing when the room blacklists unverified devices', async () => {
    await encrypt(roomStub({ blacklistUnverified: true }));

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      sharingStrategy: 'onlyTrustedDevices',
    });
  });

  it('uses the identity strategy for signed-devices-only isolation', async () => {
    const crypto = new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });
    crypto.setDeviceIsolationMode(new OnlySignedDevicesIsolationMode());
    await crypto.encryptEvent(event, roomStub());

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      sharingStrategy: 'identityBasedStrategy',
    });
  });

  it('errors on verified-user problems when the isolation mode asks for it', async () => {
    await encrypt(roomStub(), new AllDevicesIsolationMode(true));

    expect(shareArgs()?.encryptionSettings).toMatchObject({
      sharingStrategy: 'errorOnVerifiedUserProblem',
    });
  });
});

describe('encryptEvent request delivery', () => {
  const claim = { id: 'c1', type: 2, body: '{}' };
  const share = [
    { id: 's1', type: 3, event_type: 'm.room.encrypted', txn_id: 's1', body: '{"messages":{}}' },
    { id: 's2', type: 3, event_type: 'm.room.encrypted', txn_id: 's2', body: '{"messages":{}}' },
  ];

  beforeEach(() => {
    mockInvoke.mockReset();
    authedRequest.mockClear();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'getMissingSessions') return claim;
      if (method === 'shareRoomKey') return share;
      if (method === 'encryptRoomEvent') return '{}';
      if (method === 'identityKeys') return { ed25519: 'ed', curve25519: 'curve' };
      return null;
    });
  });

  it('sends the key-claim request the engine hands back', async () => {
    await encrypt(roomStub());

    expect(
      authedRequest.mock.calls.some((call) => call[1] === '/_matrix/client/v3/keys/claim')
    ).toBe(true);
  });

  it('sends every room-key to-device message the engine hands back', async () => {
    await encrypt(roomStub());

    const sent = authedRequest.mock.calls.filter((call) =>
      String(call[1]).startsWith('/_matrix/client/v3/sendToDevice/')
    );
    expect(sent).toHaveLength(2);
  });

  it('acknowledges each one so the engine stops reissuing it', async () => {
    await encrypt(roomStub());

    const marked = mockInvoke.mock.calls
      .filter(([, method]) => method === 'markRequestAsSent')
      .map(([, , args]) => (args as { requestId: string }).requestId);
    expect(marked).toEqual(['c1', 's1', 's2']);
  });

  it('shares the key before it encrypts the event', async () => {
    await encrypt(roomStub());

    const order = mockInvoke.mock.calls.map(([, method]) => method);
    expect(order.indexOf('shareRoomKey')).toBeLessThan(order.indexOf('encryptRoomEvent'));
    expect(order.indexOf('getMissingSessions')).toBeLessThan(order.indexOf('shareRoomKey'));
  });
});
