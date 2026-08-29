import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { EngineIdentity } from '../olmMachine/engineInvoke';
import type { EngineCrypto } from './EngineCrypto';

const ROOM_KEYS_RECEIVED = 'matrix-crypto://room-keys-received';
const ROOM_KEYS_WITHHELD = 'matrix-crypto://room-keys-withheld';
const IDENTITIES_UPDATED = 'matrix-crypto://identities-updated';
const SECRET_RECEIVED = 'matrix-crypto://secret-received';

type Envelope<T> = { account: string; payload: T };

type RoomKeyInfo = { roomId: string; sessionId: string };

/** Must be torn down with the client, or a re-login leaks a listener. */
export const startCryptoEventBridge = async (
  crypto: EngineCrypto,
  identity: EngineIdentity
): Promise<UnlistenFn> => {
  const account = `${identity.userId}|${identity.deviceId}`;
  const forAccount =
    <T>(handle: (payload: T) => void) =>
    ({ payload: envelope }: { payload: Envelope<T> }) => {
      if (envelope.account !== account) return;
      handle(envelope.payload);
    };

  const unlisten = await Promise.all([
    listen<Envelope<RoomKeyInfo[]>>(
      ROOM_KEYS_RECEIVED,
      forAccount<RoomKeyInfo[]>((keys) => crypto.onRoomKeysUpdated(keys))
    ),
    listen<Envelope<RoomKeyInfo[]>>(
      ROOM_KEYS_WITHHELD,
      forAccount<RoomKeyInfo[]>((sessions) => crypto.onRoomKeysWithheld(sessions))
    ),
    listen<Envelope<{ identities: string[]; devices: string[] }>>(
      IDENTITIES_UPDATED,
      forAccount<{ identities: string[]; devices: string[] }>(({ identities, devices }) => {
        identities.forEach((userId) => crypto.onUserIdentityUpdated(userId));
        if (devices.length > 0) crypto.onDevicesUpdated(devices);
      })
    ),
    listen<Envelope<{ name: string }>>(
      SECRET_RECEIVED,
      forAccount<{ name: string }>(({ name }) => {
        crypto.checkSecrets(name).catch(() => undefined);
      })
    ),
  ]);

  return () => unlisten.forEach((stop) => stop());
};
