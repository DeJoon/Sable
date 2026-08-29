import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { MatrixClient, MatrixEvent } from '$types/matrix-sdk';
import { engineInvoke } from '../olmMachine/engineInvoke';
import { EngineCrypto } from './EngineCrypto';

vi.mock('../olmMachine/engineInvoke', () => ({
  engineInvoke: vi.fn<(...args: never[]) => Promise<unknown>>(),
}));

const mockInvoke = vi.mocked(engineInvoke);

const mx = {
  http: { authedRequest: vi.fn<(...args: never[]) => Promise<unknown>>(async () => null) },
} as unknown as MatrixClient;

const utdEvent = (sessionId: string, roomId = '!room:e.org') => {
  const attemptDecryption = vi.fn<(...args: never[]) => Promise<void>>(async () => undefined);
  const event = {
    getRoomId: () => roomId,
    getId: () => '$e',
    getWireType: () => 'm.room.encrypted',
    getSender: () => '@them:e.org',
    getTs: () => 0,
    getWireContent: () => ({ session_id: sessionId }),
    attemptDecryption,
  } as unknown as MatrixEvent;
  return { event, attemptDecryption };
};

const crypto = () => new EngineCrypto(mx, { userId: '@me:e.org', deviceId: 'D' });

describe('events pending a room key', () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation(async (_identity, method) => {
      if (method === 'decryptRoomEvent') throw new Error('decryptRoomEvent failed: MissingRoomKey');
      return null;
    });
  });

  it('retries an undecryptable event once its key arrives', async () => {
    const { event, attemptDecryption } = utdEvent('session-1');
    const engine = crypto();

    await expect(engine.decryptEvent(event)).rejects.toThrow('MissingRoomKey');
    engine.onRoomKeysUpdated([{ roomId: '!room:e.org', sessionId: 'session-1' }]);

    expect(attemptDecryption).toHaveBeenCalledWith(engine, { isRetry: true });
  });

  it('retries when the key is reported withheld', async () => {
    const { event, attemptDecryption } = utdEvent('session-1');
    const engine = crypto();

    await expect(engine.decryptEvent(event)).rejects.toThrow('MissingRoomKey');
    engine.onRoomKeysWithheld([{ roomId: '!room:e.org', sessionId: 'session-1' }]);

    expect(attemptDecryption).toHaveBeenCalledTimes(1);
  });

  it('leaves events waiting on another session alone', async () => {
    const { event, attemptDecryption } = utdEvent('session-1');
    const engine = crypto();

    await expect(engine.decryptEvent(event)).rejects.toThrow('MissingRoomKey');
    engine.onRoomKeysUpdated([{ roomId: '!room:e.org', sessionId: 'session-2' }]);
    engine.onRoomKeysUpdated([{ roomId: '!other:e.org', sessionId: 'session-1' }]);

    expect(attemptDecryption).not.toHaveBeenCalled();
  });

  it('retries every event stuck on the same session', async () => {
    const first = utdEvent('session-1');
    const second = utdEvent('session-1');
    const engine = crypto();

    await expect(engine.decryptEvent(first.event)).rejects.toThrow('MissingRoomKey');
    await expect(engine.decryptEvent(second.event)).rejects.toThrow('MissingRoomKey');
    engine.onRoomKeysUpdated([{ roomId: '!room:e.org', sessionId: 'session-1' }]);

    expect(first.attemptDecryption).toHaveBeenCalledTimes(1);
    expect(second.attemptDecryption).toHaveBeenCalledTimes(1);
  });

  it('drops the events it has retried', async () => {
    const { event, attemptDecryption } = utdEvent('session-1');
    const engine = crypto();

    await expect(engine.decryptEvent(event)).rejects.toThrow('MissingRoomKey');
    engine.onRoomKeysUpdated([{ roomId: '!room:e.org', sessionId: 'session-1' }]);
    engine.onRoomKeysUpdated([{ roomId: '!room:e.org', sessionId: 'session-1' }]);

    expect(attemptDecryption).toHaveBeenCalledTimes(1);
  });
});
