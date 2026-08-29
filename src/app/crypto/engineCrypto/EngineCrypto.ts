import {
  CrossSigningKey,
  DeviceVerificationStatus,
  deriveRecoveryKeyFromPassphrase,
  EventShieldColour,
  EventShieldReason,
  encodeRecoveryKey,
  EventType,
  ImportRoomKeyStage,
  KnownMembership,
  MatrixEventEvent,
  MsgType,
  UserVerificationStatus,
} from '$types/matrix-sdk';
import { isVerificationEvent } from 'matrix-js-sdk/lib/rust-crypto/verification';
import { Device, DeviceVerification } from 'matrix-js-sdk/lib/models/device';
import { getHttpUriForMxc } from 'matrix-js-sdk/lib/content-repo';
import * as RustSdkCryptoJs from '@matrix-org/matrix-sdk-crypto-wasm';
import { decodeBase64, encodeBase64 } from 'matrix-js-sdk/lib/base64';
import { secureRandomString } from 'matrix-js-sdk/lib/randomstring';
import type { KeyBackupSession } from 'matrix-js-sdk/lib/crypto-api/keybackup';
import {
  SECRET_STORAGE_ALGORITHM_V1_AES,
  type SecretStorageKey,
} from 'matrix-js-sdk/lib/secret-storage';
import { ClientPrefix, Method } from 'matrix-js-sdk/lib/http-api';
import type { RoomMessageEventContent } from 'matrix-js-sdk/lib/types';
import { encodeUri } from 'matrix-js-sdk/lib/utils';
import { TypedEventEmitter } from 'matrix-js-sdk/lib/models/typed-event-emitter';
import { CryptoEvent, DeviceIsolationModeKind } from 'matrix-js-sdk/lib/crypto-api';
import { DecryptionFailureCode } from 'matrix-js-sdk/lib/crypto-api';
import { DecryptionError } from 'matrix-js-sdk/lib/common-crypto/CryptoBackend';
import type { CryptoEventHandlerMap } from 'matrix-js-sdk/lib/crypto-api/CryptoEventHandlerMap';
import { createDebugLogger } from '$utils/debugLogger';
import { EngineVerificationRequest } from '../verification/request';
import {
  SUPPORTED_VERIFICATION_METHOD_CODES,
  type EngineVerificationState,
} from '../verification/state';
import { engineInvoke, type EngineIdentity } from '../olmMachine/engineInvoke';
import { sendOutgoingRequest, type OutgoingRequest } from './outgoing';
import type {
  BackupDecryptor,
  CryptoBackend,
  EventDecryptionResult,
  OnSyncCompletedData,
} from 'matrix-js-sdk/lib/common-crypto/CryptoBackend';
import type { DeviceMap } from 'matrix-js-sdk/lib/models/device';
import type {
  IDeviceLists,
  IToDeviceEvent,
  ReceivedToDeviceMessage,
} from 'matrix-js-sdk/lib/sync-accumulator';
import type { IMegolmSessionData } from 'matrix-js-sdk/lib/@types/crypto';
import type { ToDeviceBatch, ToDevicePayload } from 'matrix-js-sdk/lib/models/ToDeviceMessage';
import type { AuthDict, UIAuthCallback } from 'matrix-js-sdk/lib/interactive-auth';
import type {
  BackupTrustInfo,
  BootstrapCrossSigningOpts,
  CreateSecretStorageOpts,
  CrossSigningKeys,
  CrossSigningKeyInfo,
  CrossSigningStatus,
  DeviceIsolationMode,
  EventEncryptionInfo,
  GeneratedSecretStorageKey,
  ImportRoomKeysOpts,
  KeyBackupCheck,
  KeyBackupInfo,
  KeyBackupRestoreOpts,
  KeyBackupRestoreResult,
  MatrixClient,
  MatrixEvent,
  OwnDeviceKeys,
  Room,
  RoomMember,
  SecretStorageStatus,
  StartDehydrationOpts,
  VerificationRequest,
} from '$types/matrix-sdk';

const engineCryptoLog = createDebugLogger('engine-crypto');

const DECRYPTION_WAIT_MS = 5 * 60 * 1000;

const MAX_OUTGOING_DRAIN_PASSES = 5;

const RESTORE_CHUNK_SIZE = 200;

const MAX_BACKUP_UPLOAD_FAILURES = 5;
const MAX_BACKUP_VERSIONS_TO_DELETE = 50;
const BACKUP_RETRY_DELAY_MS = 5000;
const MAX_BACKUP_RETRY_DELAY_MS = 60000;

const DecryptionErrorCode = {
  MissingRoomKey: 0,
  UnknownMessageIndex: 1,
  UnknownSenderDevice: 3,
  UnsignedSenderDevice: 4,
  SenderIdentityVerificationViolation: 5,
} as const;

const WITHHELD_FOR_UNVERIFIED_DEVICE = 'The sender has disabled encrypting to unverified devices.';

type EngineDecryptionError = {
  className: 'DecryptionError';
  code: number;
  description: string;
  maybeWithheld?: string | null;
};

const isDecryptionError = (value: unknown): value is EngineDecryptionError =>
  typeof value === 'object' &&
  value !== null &&
  'className' in value &&
  (value as { className?: string }).className === 'DecryptionError';

const ROOM_KEY_BUNDLE_TYPES = new Set(['io.element.msc4268.room_key_bundle', 'm.room_key_bundle']);

const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
};

/** js-sdk keeps this union private to its own rust-crypto module; derived the same way. */
type CryptoEvents = (typeof CryptoEvent)[keyof typeof CryptoEvent];

/** Matches matrix-js-sdk's own derivation cost so keys stay interchangeable. */
const RECOVERY_KEY_DERIVATION_ITERATIONS = 500000;

const SECRETS_IN_STORAGE = [
  'm.cross_signing.master',
  'm.cross_signing.self_signing',
  'm.cross_signing.user_signing',
] as const satisfies readonly SecretStorageKey[];

type EngineDevice = {
  userId: string;
  deviceId: string;
  displayName?: string | null;
  algorithms: number[];
  keys: Record<string, string>;
  isCrossSigningTrusted: boolean;
  isCrossSignedByOwner: boolean;
  isLocallyTrusted: boolean;
  isVerified: boolean;
  isBlacklisted: boolean;
  isDehydrated: boolean;
};

const TrustRequirement = {
  Untrusted: 0,
  CrossSignedOrLegacy: 1,
  CrossSigned: 2,
} as const;

/** wasm's ProcessedToDeviceEventType, which the engine emits as bare numbers. */
const ProcessedToDeviceEventType = {
  Decrypted: 0,
  UnableToDecrypt: 1,
  PlainText: 2,
  Invalid: 3,
} as const;

type EngineProcessedToDeviceEvent = {
  type: number;
  rawEvent: string;
  encryptionInfo?: {
    sender: string;
    senderDevice?: string;
    senderCurve25519Key: string;
    isSenderVerified: boolean;
  };
};

type EngineShieldState = { color: number; code?: number | null };

type EngineEncryptionInfo = {
  shieldStateLax?: EngineShieldState;
  shieldStateStrict?: EngineShieldState;
};

// Engine colour codes, per shield_state_json in matrix_crypto/rooms.rs.
const SHIELD_COLOUR: Record<number, EventShieldColour> = {
  0: EventShieldColour.RED,
  1: EventShieldColour.GREY,
  2: EventShieldColour.NONE,
};

// Engine ShieldStateCode ordinals, per shield_state_json in matrix_crypto/rooms.rs.
const SHIELD_REASON: Record<number, EventShieldReason> = {
  0: EventShieldReason.AUTHENTICITY_NOT_GUARANTEED,
  1: EventShieldReason.UNKNOWN_DEVICE,
  2: EventShieldReason.UNSIGNED_DEVICE,
  3: EventShieldReason.UNVERIFIED_IDENTITY,
  4: EventShieldReason.VERIFICATION_VIOLATION,
  5: EventShieldReason.MISMATCHED_SENDER,
};

export const toEventEncryptionInfo = (
  info: EngineEncryptionInfo | null
): EventEncryptionInfo | null => {
  if (!info) return null;

  // js-sdk reads the lax state; strict is only used behind its own setting.
  const state = info.shieldStateLax;
  if (!state) return null;

  const code = state.code;
  return {
    shieldColour: SHIELD_COLOUR[state.color] ?? EventShieldColour.RED,
    shieldReason:
      code === undefined || code === null
        ? null
        : (SHIELD_REASON[code] ?? EventShieldReason.UNKNOWN),
  };
};

type EngineDecryptedEvent = {
  event: string;
  senderCurve25519Key?: string | null;
  senderClaimedEd25519Key?: string | null;
  forwardingCurve25519KeyChain?: string[];
  forwarder?: string | null;
  forwarderDevice?: string | null;
};

const isOutgoingRequest = (value: unknown): value is OutgoingRequest => {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<OutgoingRequest>;
  return typeof candidate.type === 'number' && typeof candidate.body === 'string';
};

type EngineRoomKeyInfo = {
  roomId: string;
  sessionId: string;
};

type EngineRoomKeyBundle = {
  encryptedData: string;
  mediaEncryptionInfo: string;
};

type EngineBootstrapRequests = {
  uploadKeysRequest?: OutgoingRequest | null;
  uploadSigningKeysRequest?: { body: string } | null;
  uploadSignaturesRequest?: OutgoingRequest | null;
};

type EngineBackupKeys = {
  backupVersion?: string | null;
  /** Base64 text, not raw bytes; the engine never hands the key over as an object. */
  decryptionKeyBase64?: string | null;
};

/** The engine serialises each cross-signing key as JSON text. */
const parseCrossSigningKey = (raw: unknown): CrossSigningKeyInfo | undefined => {
  if (typeof raw !== 'string') return undefined;
  try {
    return JSON.parse(raw) as CrossSigningKeyInfo;
  } catch {
    return undefined;
  }
};

type EngineIdentityInfo = {
  userId: string;
  isVerified: boolean;
  wasPreviouslyVerified: boolean;
  identityNeedsUserApproval?: boolean;
  masterKey?: unknown;
  selfSigningKey?: unknown;
  userSigningKey?: unknown;
};

const deviceVerification = (device: EngineDevice): DeviceVerification => {
  if (device.isBlacklisted) return DeviceVerification.Blocked;
  return device.isVerified ? DeviceVerification.Verified : DeviceVerification.Unverified;
};

const ENCRYPTION_ALGORITHMS = ['m.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'];

const toSdkDevice = (device: EngineDevice): Device =>
  new Device({
    userId: device.userId,
    deviceId: device.deviceId,
    displayName: device.displayName ?? undefined,
    algorithms: ENCRYPTION_ALGORITHMS.filter((_, index) =>
      device.algorithms?.includes(index)
    ) as string[],
    keys: new Map(Object.entries(device.keys)),
    verified: deviceVerification(device),
    signatures: new Map(),
    dehydrated: device.isDehydrated,
  });

export class EngineCrypto
  extends TypedEventEmitter<CryptoEvents, CryptoEventHandlerMap>
  implements CryptoBackend
{
  globalBlacklistUnverifiedDevices = false;

  globalErrorOnUnknownDevices = false;

  readonly #mx: MatrixClient;

  readonly #identity: EngineIdentity;

  #trustCrossSignedDevices = true;

  #stopped = false;

  #deviceIsolationMode: DeviceIsolationMode | undefined;

  /** Live requests, keyed by flow id, so the synchronous CryptoApi getters can answer. */
  readonly #verificationRequests = new Map<string, EngineVerificationRequest>();

  #flushing: Promise<void> = Promise.resolve();

  readonly #roomsWithTrackedMembers = new Set<string>();

  #backingUp: Promise<void> = Promise.resolve();

  #checkingKeyBackup: Promise<KeyBackupCheck | null> = Promise.resolve(null);

  readonly #eventsPendingKey = new Map<string, Set<MatrixEvent>>();

  constructor(mx: MatrixClient, identity: EngineIdentity) {
    super();
    this.#mx = mx;
    this.#identity = identity;
    // Nothing else drives the backup connection.
    void this.#connectKeyBackup();
  }

  /** The engine reports a backup version only once `enableBackupV1` has run. */
  async #connectKeyBackup(): Promise<void> {
    try {
      await this.checkKeyBackupAndEnable();
    } catch (error) {
      engineCryptoLog.warn('general', 'Could not connect the key backup', error);
    }
  }

  #scheduleKeyBackup(): void {
    this.#backingUp = this.#backingUp.then(() =>
      this.#uploadRoomKeysToBackup().catch((error: unknown) => {
        engineCryptoLog.error('general', 'Uploading room keys to backup failed', error);
      })
    );
  }

  async #uploadRoomKeysToBackup(): Promise<void> {
    if (this.#stopped) return;
    if (!(await this.#call('isBackupEnabled'))) return;

    for (let failures = 0; failures < MAX_BACKUP_UPLOAD_FAILURES;) {
      if (this.#stopped) return;
      // eslint-disable-next-line no-await-in-loop
      const request = (await this.#call('backupRoomKeys')) as OutgoingRequest | null;
      if (!request) break;

      try {
        // eslint-disable-next-line no-await-in-loop
        const response = await sendOutgoingRequest(this.#mx, request);
        // eslint-disable-next-line no-await-in-loop
        await this.#call('markRequestAsSent', {
          requestId: request.id,
          requestType: request.type,
          response,
        });
        failures = 0;
      } catch (error) {
        failures += 1;
        // eslint-disable-next-line no-await-in-loop
        if (!(await this.#recoverFromBackupUploadError(error))) return;
        // eslint-disable-next-line no-await-in-loop
        continue;
      }

      // eslint-disable-next-line no-await-in-loop
      const counts = (await this.#call('roomKeyCounts')) as { total: number; backedUp: number };
      this.emit(CryptoEvent.KeyBackupSessionsRemaining, counts.total - counts.backedUp);
    }

    this.emit(CryptoEvent.KeyBackupSessionsRemaining, 0);
  }

  async #recoverFromBackupUploadError(error: unknown): Promise<boolean> {
    const failure = error as { data?: { errcode?: string; retry_after_ms?: number } };
    const errcode = failure.data?.errcode;

    if (errcode === 'M_WRONG_ROOM_KEYS_VERSION' || errcode === 'M_NOT_FOUND') {
      this.emit(CryptoEvent.KeyBackupFailed, errcode);
      await this.#disableKeyBackup();
      await this.#connectKeyBackup();
      return false;
    }

    if (errcode === 'M_LIMIT_EXCEEDED') {
      const wait = failure.data?.retry_after_ms ?? BACKUP_RETRY_DELAY_MS;
      await new Promise((resolve) => {
        setTimeout(resolve, Math.min(wait, MAX_BACKUP_RETRY_DELAY_MS));
      });
      return true;
    }

    if (errcode) this.emit(CryptoEvent.KeyBackupFailed, errcode);
    return false;
  }

  onUserIdentityUpdated(userId: string): void {
    void this.getUserVerificationStatus(userId)
      .then((status) => this.emit(CryptoEvent.UserTrustStatusChanged, userId, status))
      .catch(() => undefined);
    // Our own identity becoming trusted can make a backup we rejected trustworthy.
    if (userId === this.#identity.userId) void this.#connectKeyBackup();
  }

  onDevicesUpdated(userIds: string[]): void {
    this.emit(CryptoEvent.WillUpdateDevices, userIds, false);
    this.emit(CryptoEvent.DevicesUpdated, userIds, false);
  }

  onKeysChanged(): void {
    this.emit(CryptoEvent.KeysChanged, {});
    this.#scheduleKeyBackup();
  }

  onRoomKeysUpdated(keys: EngineRoomKeyInfo[]): void {
    this.onKeysChanged();
    keys.forEach((key) => this.#retryEventsPendingKey(key));
  }

  onRoomKeysWithheld(sessions: EngineRoomKeyInfo[]): void {
    sessions.forEach((session) => this.#retryEventsPendingKey(session));
  }

  #retryEventsPendingKey({ roomId, sessionId }: EngineRoomKeyInfo): void {
    if (this.#stopped) return;
    const pending = this.#eventsPendingKey.get(`${roomId}|${sessionId}`);
    if (!pending) return;
    this.#eventsPendingKey.delete(`${roomId}|${sessionId}`);

    pending.forEach((event) => {
      event.attemptDecryption(this, { isRetry: true }).catch(() => undefined);
    });
  }

  #dropEventPendingKey(event: MatrixEvent): void {
    const key = this.#pendingKeyFor(event);
    if (!key) return;
    const pending = this.#eventsPendingKey.get(key);
    if (!pending) return;
    pending.delete(event);
    if (pending.size === 0) this.#eventsPendingKey.delete(key);
  }

  #pendingKeyFor(event: MatrixEvent): string | undefined {
    const roomId = event.getRoomId();
    const sessionId = (event.getWireContent() as { session_id?: string }).session_id;
    return roomId && sessionId ? `${roomId}|${sessionId}` : undefined;
  }

  #holdEventPendingKey(event: MatrixEvent): void {
    const roomId = event.getRoomId();
    const sessionId = (event.getWireContent() as { session_id?: string }).session_id;
    if (!roomId || !sessionId) return;

    const key = `${roomId}|${sessionId}`;
    const pending = this.#eventsPendingKey.get(key) ?? new Set<MatrixEvent>();
    pending.add(event);
    this.#eventsPendingKey.set(key, pending);
  }

  async #receiveSyncChanges(input: {
    toDeviceEvents?: IToDeviceEvent[];
    deviceLists?: IDeviceLists;
    oneTimeKeysCounts?: Record<string, number>;
    unusedFallbackKeys?: string[];
  }): Promise<EngineProcessedToDeviceEvent[]> {
    const processed = (await this.#call('receiveSyncChanges', {
      toDeviceEvents: JSON.stringify(input.toDeviceEvents ?? []),
      changedDevices: input.deviceLists?.changed ?? [],
      leftDevices: input.deviceLists?.left ?? [],
      oneTimeKeysCounts: input.oneTimeKeysCounts ?? {},
      ...(input.unusedFallbackKeys ? { unusedFallbackKeys: input.unusedFallbackKeys } : {}),
    })) as EngineProcessedToDeviceEvent[] | null;

    void this.#flushOutgoingRequests();
    return processed ?? [];
  }

  #call(method: string, args: Record<string, unknown> = {}): Promise<unknown> {
    return engineInvoke(this.#identity, method, args);
  }

  /**
   * Verification actions return their outgoing request instead of queueing it, so the
   * generic drain never sees it. Unsent, the flow stalls with no error.
   */
  readonly #engineCall = async (
    method: string,
    args: Record<string, unknown> = {}
  ): Promise<unknown> => {
    const result = await this.#call(method, args);

    // `sas.confirm` answers with several requests (the MAC plus a signature upload), and
    // `startSas` answers with [state, request]. Sending only a lone object drops both.
    if (Array.isArray(result)) {
      for (const item of result) {
        if (!isOutgoingRequest(item)) continue;
        // Ordered: the peer rejects a MAC that arrives before the accept.
        // eslint-disable-next-line no-await-in-loop
        await sendOutgoingRequest(this.#mx, item);
      }
      return result;
    }

    if (isOutgoingRequest(result)) {
      await sendOutgoingRequest(this.#mx, result);
      return null;
    }
    return result;
  };

  async #startVerification(
    method: string,
    args: Record<string, unknown>
  ): Promise<VerificationRequest> {
    const started = (await this.#call(method, args)) as {
      request: EngineVerificationState;
      outgoingRequest?: unknown;
    };
    if (isOutgoingRequest(started.outgoingRequest)) {
      await sendOutgoingRequest(this.#mx, started.outgoingRequest);
    }
    await this.#flushOutgoingRequests();

    const request = new EngineVerificationRequest(this.#engineCall, started.request);
    this.#verificationRequests.set(started.request.flowId, request);
    return request;
  }

  async onLiveEventFromSync(event: MatrixEvent): Promise<void> {
    if (event.isState() || event.getUnsigned().transaction_id) return;

    const handle = async (candidate: MatrixEvent): Promise<void> => {
      if (isVerificationEvent(candidate)) await this.onKeyVerificationEvent(candidate);
    };

    if (event.isDecryptionFailure() || event.isEncrypted()) {
      let timeoutId: ReturnType<typeof setTimeout>;
      const onDecrypted = (decrypted: MatrixEvent, error?: Error) => {
        if (error) return;
        clearTimeout(timeoutId);
        event.off(MatrixEventEvent.Decrypted, onDecrypted);
        void handle(decrypted);
      };
      timeoutId = setTimeout(() => {
        event.off(MatrixEventEvent.Decrypted, onDecrypted);
      }, DECRYPTION_WAIT_MS);
      event.on(MatrixEventEvent.Decrypted, onDecrypted);
      return;
    }

    await handle(event);
  }

  async onKeyVerificationEvent(event: MatrixEvent): Promise<void> {
    const roomId = event.getRoomId();
    const senderId = event.getSender();
    const eventId = event.getId();
    if (!roomId || !senderId || !eventId) return;

    const content = event.getContent();
    const isRequest =
      event.getType() === EventType.RoomMessage &&
      content.msgtype === MsgType.KeyVerificationRequest;

    if (isRequest) {
      await this.#sendTracked(await this.#call('queryKeysForUsers', { users: [senderId] }));
    }

    await this.#call('receiveVerificationEvent', {
      roomId,
      event: JSON.stringify({
        event_id: eventId,
        type: event.getType(),
        sender: senderId,
        state_key: event.getStateKey(),
        content,
        origin_server_ts: event.getTs(),
      }),
    });

    if (isRequest) {
      await this.onIncomingKeyVerificationRequest(senderId, eventId);
    } else {
      const flowId = (content['m.relates_to'] as { event_id?: string } | undefined)?.event_id;
      if (flowId) await this.#verificationRequests.get(flowId)?.refresh();
    }

    await this.#flushOutgoingRequests();
  }

  onRoomStateEvent(event: MatrixEvent): void {
    if (event.getType() !== EventType.RoomMember) return;
    if (
      event.getStateKey() !== this.#identity.userId &&
      event.getContent().membership !== KnownMembership.Join
    ) {
      void this.forceDiscardSession(event.getRoomId() ?? '');
    }
  }

  onRoomMembership(event: MatrixEvent, member: RoomMember, oldMembership?: string): void {
    const roomId = event.getRoomId();
    if (!roomId) return;

    if (
      member.membership === KnownMembership.Join ||
      member.membership === KnownMembership.Invite
    ) {
      void this.#trackUsers([member.userId]);
    }

    if (
      oldMembership === KnownMembership.Join &&
      member.membership !== KnownMembership.Join &&
      member.userId === this.#identity.userId
    ) {
      void this.#call('clearRoomPendingKeyBundle', { roomId });
    }
  }

  async #trackUsers(users: string[]): Promise<void> {
    if (users.length === 0) return;
    try {
      await this.#call('updateTrackedUsers', { users });
    } catch (error) {
      engineCryptoLog.warn('general', 'Could not track device lists for users', error);
    }
  }

  async #sendTracked(request: unknown): Promise<void> {
    if (!isOutgoingRequest(request)) return;
    const response = await sendOutgoingRequest(this.#mx, request);
    if (typeof request.id !== 'string') return;
    await this.#call('markRequestAsSent', {
      requestId: request.id,
      requestType: request.type,
      response,
    });
  }

  async onIncomingKeyVerificationRequest(sender: string, transactionId: string): Promise<void> {
    const state = (await this.#call('getVerificationRequest', {
      userId: sender,
      flowId: transactionId,
    })) as EngineVerificationState | null;
    if (!state) return;

    const existing = this.#verificationRequests.get(transactionId);
    if (existing) {
      existing.apply(state);
      return;
    }
    const request = new EngineVerificationRequest(this.#engineCall, state);
    this.#verificationRequests.set(transactionId, request);
    this.emit(CryptoEvent.VerificationRequestReceived, request);
  }

  #flushOutgoingRequests(): Promise<void> {
    this.#flushing = this.#flushing.then(() =>
      this.#drainOutgoingRequests().catch((error: unknown) => {
        engineCryptoLog.error('general', 'Draining outgoing crypto requests failed', error);
      })
    );
    return this.#flushing;
  }

  /** matrix-sdk-crypto only clears a request once told it was sent, so a failure here
   * leaves it queued for the next drain rather than losing it. */
  async #drainOutgoingRequests(): Promise<void> {
    for (let pass = 0; pass < MAX_OUTGOING_DRAIN_PASSES; pass += 1) {
      // eslint-disable-next-line no-await-in-loop
      if (!(await this.#drainOutgoingRequestsOnce())) return;
    }
  }

  async #drainOutgoingRequestsOnce(): Promise<boolean> {
    if (this.#stopped) return false;
    const requests = ((await this.#call('outgoingRequests')) ?? []) as OutgoingRequest[];

    let sent = 0;
    for (const request of requests) {
      if (this.#stopped) return false;
      try {
        // Sequential: the engine's queue is ordered and later requests can depend on
        // earlier ones having landed.
        // eslint-disable-next-line no-await-in-loop
        const response = await sendOutgoingRequest(this.#mx, request);
        // eslint-disable-next-line no-await-in-loop
        await this.#call('markRequestAsSent', {
          requestId: request.id,
          requestType: request.type,
          response,
        });
        sent += 1;
      } catch (error) {
        // Loud: a request the engine never marks sent is retried on every sync forever.
        engineCryptoLog.error('general', `Outgoing crypto request ${request.id} failed`, error);
      }
    }

    return sent > 0;
  }

  async preprocessToDeviceMessages(events: IToDeviceEvent[]): Promise<ReceivedToDeviceMessage[]> {
    const processed = await this.#receiveSyncChanges({ toDeviceEvents: events });
    const received: ReceivedToDeviceMessage[] = [];

    const messages = processed.map(
      (event) => [event, JSON.parse(event.rawEvent) as IToDeviceEvent] as const
    );

    if (
      messages.some(
        ([, message]) =>
          typeof message.type === 'string' && message.type.startsWith('m.key.verification.')
      )
    ) {
      await this.#flushOutgoingRequests();
    }

    for (const [event, message] of messages) {
      if (typeof message.type === 'string' && message.type.startsWith('m.key.verification.')) {
        const transactionId = (message.content as { transaction_id?: string })?.transaction_id;
        if (transactionId && message.sender) {
          if (message.type === EventType.KeyVerificationRequest) {
            // eslint-disable-next-line no-await-in-loop
            await this.onIncomingKeyVerificationRequest(message.sender, transactionId);
          } else if (message.type === EventType.KeyVerificationDone) {
            // Rust removes completed requests while consuming the event, so no state snapshot
            // exists to refresh. Keep the JS request alive long enough to expose Done.
            this.#verificationRequests.get(transactionId)?.markDone();
          } else {
            // Without this the verifier never learns the SAS digits arrived.
            // eslint-disable-next-line no-await-in-loop
            await this.#verificationRequests.get(transactionId)?.refresh();
          }
        }
      }

      if (ROOM_KEY_BUNDLE_TYPES.has(message.type) && message.sender) {
        void this.#acceptArrivedKeyBundle(message.sender);
      }

      if (event.type === ProcessedToDeviceEventType.Decrypted && event.encryptionInfo) {
        received.push({
          message,
          encryptionInfo: {
            sender: event.encryptionInfo.sender,
            senderDevice: event.encryptionInfo.senderDevice,
            senderCurve25519KeyBase64: event.encryptionInfo.senderCurve25519Key,
            senderVerified: event.encryptionInfo.isSenderVerified,
          },
        });
      } else if (event.type === ProcessedToDeviceEventType.PlainText) {
        received.push({ message, encryptionInfo: null });
      }
      // Undecryptable and invalid events are dropped, as js-sdk's own backend does.
    }

    return received;
  }

  async processKeyCounts(
    oneTimeKeysCounts?: Record<string, number>,
    unusedFallbackKeys?: string[]
  ): Promise<void> {
    await this.#receiveSyncChanges({ oneTimeKeysCounts, unusedFallbackKeys });
  }

  async processDeviceLists(deviceLists: IDeviceLists): Promise<void> {
    await this.#receiveSyncChanges({ deviceLists });
  }

  async onCryptoEvent(room: Room, event: MatrixEvent): Promise<void> {
    const config = event.getContent();
    if (config.algorithm !== 'm.megolm.v1.aes-sha2') {
      engineCryptoLog.warn('general', 'Ignoring encryption event with invalid algorithm', {
        roomId: room.roomId,
        algorithm: config.algorithm,
      });
      return;
    }

    try {
      await this.#call('setRoomSettings', {
        roomId: room.roomId,
        settings: {
          algorithm: config.algorithm,
          sessionRotationPeriodMs: config.rotation_period_ms,
          sessionRotationPeriodMessages: config.rotation_period_msgs,
        },
      });
    } catch (error) {
      engineCryptoLog.warn('general', 'Could not update room encryption settings', {
        roomId: room.roomId,
        error,
      });
    }
  }

  onSyncCompleted(syncState: OnSyncCompletedData): void {
    // Working through a backlog: the next sync follows immediately, so batch the drain.
    if (syncState.catchingUp) return;
    void this.#flushOutgoingRequests();
  }

  async markAllTrackedUsersAsDirty(): Promise<void> {
    await this.#call('markAllTrackedUsersAsDirty');
  }

  stop(): void {
    this.#stopped = true;
    this.#eventsPendingKey.clear();
    this.#roomsWithTrackedMembers.clear();
  }

  #trustRequirement(): number {
    return this.#deviceIsolationMode?.kind ===
      DeviceIsolationModeKind.OnlySignedDevicesIsolationMode
      ? TrustRequirement.CrossSignedOrLegacy
      : TrustRequirement.Untrusted;
  }

  #sharingStrategy(room: Room): string {
    if (
      this.#deviceIsolationMode?.kind === DeviceIsolationModeKind.OnlySignedDevicesIsolationMode
    ) {
      return 'identityBasedStrategy';
    }
    if (room.getBlacklistUnverifiedDevices() ?? this.globalBlacklistUnverifiedDevices) {
      return 'onlyTrustedDevices';
    }
    if (this.#deviceIsolationMode?.errorOnVerifiedUserProblems) {
      return 'errorOnVerifiedUserProblem';
    }
    return 'allDevices';
  }

  #encryptionSettings(room: Room): Record<string, unknown> {
    const config =
      room.currentState.getStateEvents(EventType.RoomEncryption, '')?.getContent() ?? {};

    const settings: Record<string, unknown> = {
      algorithm: 'm.megolm.v1.aes-sha2',
      historyVisibility: room.getHistoryVisibility(),
      sharingStrategy: this.#sharingStrategy(room),
    };
    if (typeof config.rotation_period_ms === 'number') {
      settings.rotationPeriod = config.rotation_period_ms * 1000;
    }
    if (typeof config.rotation_period_msgs === 'number') {
      settings.rotationPeriodMessages = config.rotation_period_msgs;
    }
    return settings;
  }

  async encryptEvent(event: MatrixEvent, room: Room): Promise<void> {
    // The megolm session has to reach every device in the room before the event does.
    const members = await room.getEncryptionTargetMembers();
    const users = members.map((member) => member.userId);

    if (!this.#roomsWithTrackedMembers.has(room.roomId)) {
      await this.#trackUsers(users);
      await this.#flushOutgoingRequests();
      this.#roomsWithTrackedMembers.add(room.roomId);
    }

    const claim = (await this.#call('getMissingSessions', { users })) as OutgoingRequest | null;
    await this.#sendTracked(claim);
    await this.#flushOutgoingRequests();

    const shared = ((await this.#call('shareRoomKey', {
      roomId: room.roomId,
      users,
      encryptionSettings: this.#encryptionSettings(room),
    })) ?? []) as OutgoingRequest[];
    for (const request of shared) {
      // eslint-disable-next-line no-await-in-loop
      await this.#sendTracked(request);
    }
    await this.#flushOutgoingRequests();

    const encrypted = (await this.#call('encryptRoomEvent', {
      roomId: room.roomId,
      eventType: event.getType(),
      content: JSON.stringify(event.getContent()),
    })) as string;

    const own = await this.getOwnDeviceKeys();
    event.makeEncrypted(
      'm.room.encrypted',
      JSON.parse(encrypted) as Record<string, unknown>,
      own.curve25519,
      own.ed25519
    );
  }

  async decryptEvent(event: MatrixEvent): Promise<EventDecryptionResult> {
    const roomId = event.getRoomId();
    if (!roomId) throw new Error('Cannot decrypt an event with no room id');

    this.#holdEventPendingKey(event);

    const result = (await this.#call('decryptRoomEvent', {
      event: JSON.stringify({
        event_id: event.getId(),
        type: event.getWireType(),
        sender: event.getSender(),
        room_id: roomId,
        origin_server_ts: event.getTs(),
        content: event.getWireContent(),
      }),
      roomId,
      decryptionSettings: { senderDeviceTrustRequirement: this.#trustRequirement() },
    })) as unknown;

    if (isDecryptionError(result)) await this.#throwDecryptionError(event, result);
    const decrypted = result as EngineDecryptedEvent;

    this.#dropEventPendingKey(event);

    return {
      clearEvent: JSON.parse(decrypted.event) as EventDecryptionResult['clearEvent'],
      senderCurve25519Key: decrypted.senderCurve25519Key ?? undefined,
      claimedEd25519Key: decrypted.senderClaimedEd25519Key ?? undefined,
      forwardingCurve25519KeyChain: decrypted.forwardingCurve25519KeyChain ?? [],
      ...(decrypted.forwarder ? { keyForwardedBy: decrypted.forwarder } : {}),
    };
  }

  async #throwDecryptionError(event: MatrixEvent, error: EngineDecryptionError): Promise<never> {
    const content = event.getWireContent() as { sender_key?: string; session_id?: string };
    const details: Record<string, string> = {};
    if (content.sender_key) details.sender_key = content.sender_key;
    if (content.session_id) details.session_id = content.session_id;

    const recoverable =
      error.code === DecryptionErrorCode.MissingRoomKey ||
      error.code === DecryptionErrorCode.UnknownMessageIndex;

    if (recoverable) {
      const membership = event.getMembershipAtEvent();
      if (
        membership &&
        membership !== KnownMembership.Join &&
        membership !== KnownMembership.Invite
      ) {
        throw new DecryptionError(
          DecryptionFailureCode.HISTORICAL_MESSAGE_USER_NOT_JOINED,
          'This message was sent when we were not a member of the room.',
          details
        );
      }
      await this.#throwIfHistorical(event, details);
    }

    if (error.maybeWithheld) {
      throw new DecryptionError(
        error.maybeWithheld === WITHHELD_FOR_UNVERIFIED_DEVICE
          ? DecryptionFailureCode.MEGOLM_KEY_WITHHELD_FOR_UNVERIFIED_DEVICE
          : DecryptionFailureCode.MEGOLM_KEY_WITHHELD,
        error.maybeWithheld,
        details
      );
    }

    switch (error.code) {
      case DecryptionErrorCode.MissingRoomKey:
        throw new DecryptionError(
          DecryptionFailureCode.MEGOLM_UNKNOWN_INBOUND_SESSION_ID,
          "The sender's device has not sent us the keys for this message.",
          details
        );
      case DecryptionErrorCode.UnknownMessageIndex:
        throw new DecryptionError(
          DecryptionFailureCode.OLM_UNKNOWN_MESSAGE_INDEX,
          "The sender's device has not sent us the keys for this message at this index.",
          details
        );
      case DecryptionErrorCode.SenderIdentityVerificationViolation:
        this.#dropEventPendingKey(event);
        throw new DecryptionError(
          DecryptionFailureCode.SENDER_IDENTITY_PREVIOUSLY_VERIFIED,
          'The sender identity is unverified, but was previously verified.'
        );
      case DecryptionErrorCode.UnknownSenderDevice:
        this.#dropEventPendingKey(event);
        throw new DecryptionError(
          DecryptionFailureCode.UNKNOWN_SENDER_DEVICE,
          'The sender device is not known.'
        );
      case DecryptionErrorCode.UnsignedSenderDevice:
        this.#dropEventPendingKey(event);
        throw new DecryptionError(
          DecryptionFailureCode.UNSIGNED_SENDER_DEVICE,
          'The sender identity is not cross-signed.'
        );
      default:
        throw new DecryptionError(DecryptionFailureCode.UNKNOWN_ERROR, error.description, details);
    }
  }

  async #throwIfHistorical(event: MatrixEvent, details: Record<string, string>): Promise<void> {
    const createdAt = (await this.#call('deviceCreationTimeMs')) as number | null;
    if (createdAt === null || event.getTs() > createdAt) return;

    const backupInfo = await this.getKeyBackupInfo().catch(() => null);
    if (!backupInfo) {
      throw new DecryptionError(
        DecryptionFailureCode.HISTORICAL_MESSAGE_NO_KEY_BACKUP,
        'This message was sent before this device logged in, and there is no key backup on the server.',
        details
      );
    }

    const usable = (await this.getSessionBackupPrivateKey()) !== null;
    throw new DecryptionError(
      usable
        ? DecryptionFailureCode.HISTORICAL_MESSAGE_WORKING_BACKUP
        : DecryptionFailureCode.HISTORICAL_MESSAGE_BACKUP_UNCONFIGURED,
      'This message was sent before this device logged in.',
      details
    );
  }

  /** Stateless: needs the backup key, not the crypto store, so it stays in-process. */
  async getBackupDecryptor(
    backupInfo: KeyBackupInfo,
    privKey: Uint8Array
  ): Promise<BackupDecryptor> {
    if (backupInfo.algorithm !== 'm.megolm_backup.v1.curve25519-aes-sha2') {
      throw new Error(`Unsupported key backup algorithm ${backupInfo.algorithm}`);
    }

    const key = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(encodeBase64(privKey));
    const authData = backupInfo.auth_data as { public_key?: string } | undefined;
    if (authData?.public_key !== key.megolmV1PublicKey.publicKeyBase64) {
      throw new Error('The backup key does not match this backup version');
    }

    return {
      sourceTrusted: false,
      async decryptSessions(ciphertexts) {
        const decrypted: IMegolmSessionData[] = [];
        for (const [sessionId, session] of Object.entries(ciphertexts)) {
          try {
            const data = JSON.parse(
              key.decryptV1(
                session.session_data.ephemeral,
                session.session_data.mac,
                session.session_data.ciphertext
              )
            ) as IMegolmSessionData;
            data.session_id = sessionId;
            decrypted.push(data);
          } catch (error) {
            engineCryptoLog.warn(
              'general',
              `Could not decrypt backed up session ${sessionId}`,
              error
            );
          }
        }
        return decrypted;
      },
      free() {
        key.free();
      },
    };
  }

  async importBackedUpRoomKeys(
    keys: IMegolmSessionData[],
    backupVersion: string,
    opts?: ImportRoomKeysOpts
  ): Promise<void> {
    await this.#importBackedUpRoomKeys(keys, backupVersion, opts);
  }

  async #importBackedUpRoomKeys(
    keys: IMegolmSessionData[],
    backupVersion: string,
    opts?: ImportRoomKeysOpts,
    already = 0,
    grandTotal = keys.length
  ): Promise<number> {
    const result = (await this.#call('importBackedUpRoomKeys', {
      keys: JSON.stringify(keys),
      backupVersion,
    })) as { importedCount?: number; totalCount?: number } | null;

    const successes = already + (result?.importedCount ?? 0);
    opts?.progressCallback?.({
      stage: ImportRoomKeyStage.LoadKeys,
      successes,
      failures: grandTotal - successes,
      total: grandTotal,
    });
    return result?.importedCount ?? 0;
  }

  /** MSC4268. The engine encrypts; we upload; only the mxc URL goes back. */
  async #downloadAllRoomKeys(roomId: string): Promise<void> {
    if ((await this.#call('hasDownloadedAllRoomKeys', { roomId })) === true) return;
    try {
      await this.restoreKeyBackup();
      await this.#call('setHasDownloadedAllRoomKeys', { roomId });
    } catch (error) {
      engineCryptoLog.warn('general', 'Could not download room keys before sharing', error);
    }
  }

  async shareRoomHistoryWithUser(roomId: string, userId: string): Promise<void> {
    await this.#downloadAllRoomKeys(roomId);
    const own = await this.getUserVerificationStatus(this.#identity.userId);
    if (!own.isCrossSigningVerified()) {
      engineCryptoLog.warn(
        'general',
        'Not sharing message history: this device is not verified by our own identity'
      );
      return;
    }

    const bundle = (await this.#call('buildRoomKeyBundle', {
      roomId,
    })) as EngineRoomKeyBundle | null;
    if (!bundle) return;

    const { content_uri: url } = await this.#mx.uploadContent(
      new Blob([decodeBase64(bundle.encryptedData) as BlobPart]),
      { includeFilename: false }
    );

    await this.#sendTracked(await this.#call('queryKeysForUsers', { users: [userId] }));
    await this.#flushOutgoingRequests();
    await this.#sendTracked(await this.#call('getMissingSessions', { users: [userId] }));
    await this.#flushOutgoingRequests();

    const requests = ((await this.#call('shareRoomKeyBundleData', {
      userId,
      roomId,
      url,
      mediaEncryptionInfo: bundle.mediaEncryptionInfo,
      sharingStrategy: 'identityBasedStrategy',
    })) ?? []) as OutgoingRequest[];
    for (const request of requests) {
      // eslint-disable-next-line no-await-in-loop
      await this.#sendTracked(request);
    }
    await this.#flushOutgoingRequests();
  }

  /** MSC4268. The engine stores the bundle metadata; we fetch the media it points at. */
  async maybeAcceptKeyBundle(roomId: string, inviter: string): Promise<boolean> {
    await this.#trackUsers([inviter]);
    await this.#sendTracked(await this.#call('queryKeysForUsers', { users: [inviter] }));
    await this.#flushOutgoingRequests();

    const data = (await this.#call('getReceivedRoomKeyBundleData', {
      roomId,
      inviterId: inviter,
    })) as { url?: string } | null;
    if (!data?.url) return false;

    const httpUrl = new URL(
      getHttpUriForMxc(
        this.#mx.baseUrl,
        data.url,
        undefined,
        undefined,
        undefined,
        false,
        true,
        true
      )
    );
    const blob = await this.#mx.http.authedRequest<Blob>(
      Method.Get,
      httpUrl.pathname + httpUrl.search,
      {},
      undefined,
      { rawResponseBody: true, prefix: '' }
    );

    await this.#call('receiveRoomKeyBundle', {
      roomId,
      inviterId: inviter,
      bundle: encodeBase64(new Uint8Array(await blob.arrayBuffer())),
    });
    await this.#call('clearRoomPendingKeyBundle', { roomId });
    return true;
  }

  async #acceptArrivedKeyBundle(inviter: string): Promise<void> {
    try {
      const pending = ((await this.#call('getAllRoomsPendingKeyBundles')) ?? []) as {
        roomId: string;
        inviterId: string;
      }[];

      for (const room of pending.filter((entry) => entry.inviterId === inviter)) {
        // eslint-disable-next-line no-await-in-loop
        await this.maybeAcceptKeyBundle(room.roomId, inviter);
      }
    } catch (error) {
      engineCryptoLog.warn('general', 'Could not accept an arrived room key bundle', error);
    }
  }

  async markRoomAsPendingKeyBundle(roomId: string, inviterId: string): Promise<void> {
    await this.#call('storeRoomPendingKeyBundle', { roomId, inviterId });
  }

  setDeviceIsolationMode(isolationMode: DeviceIsolationMode): void {
    this.#deviceIsolationMode = isolationMode;
  }

  getVersion(): string {
    return 'Rust SDK (Sable engine over IPC)';
  }

  async getOwnDeviceKeys(): Promise<OwnDeviceKeys> {
    const keys = (await this.#call('identityKeys')) as { ed25519: string; curve25519: string };
    return { ed25519: keys.ed25519, curve25519: keys.curve25519 };
  }

  async isEncryptionEnabledInRoom(roomId: string): Promise<boolean> {
    return this.#mx.getRoom(roomId)?.hasEncryptionStateEvent() ?? false;
  }

  async isStateEncryptionEnabledInRoom(roomId: string): Promise<boolean> {
    const settings = (await this.#call('getRoomSettings', { roomId })) as {
      encryptStateEvents?: boolean;
    } | null;
    return settings?.encryptStateEvents ?? false;
  }

  prepareToEncrypt(room: Room): void {
    void room
      .getEncryptionTargetMembers()
      .then(async (members) => {
        const users = members.map((member) => member.userId);
        await this.#trackUsers(users);
        await this.#sendTracked(await this.#call('getMissingSessions', { users }));
        await this.#flushOutgoingRequests();
      })
      .catch((error: unknown) => engineCryptoLog.warn('general', 'prepareToEncrypt failed', error));
  }

  async forceDiscardSession(roomId: string): Promise<void> {
    await this.#call('invalidateGroupSession', { roomId });
  }

  async getEncryptionInfoForEvent(event: MatrixEvent): Promise<EventEncryptionInfo | null> {
    if (!event.getClearContent() || event.isDecryptionFailure()) return null;
    if (event.status !== null) {
      return { shieldColour: EventShieldColour.NONE, shieldReason: null };
    }

    const roomId = event.getRoomId();
    if (!roomId) return null;

    const info = (await this.#call('getRoomEventEncryptionInfo', {
      event: JSON.stringify({
        event_id: event.getId(),
        type: event.getWireType(),
        sender: event.getSender(),
        room_id: roomId,
        origin_server_ts: event.getTs(),
        content: event.getWireContent(),
      }),
      roomId,
    })) as EngineEncryptionInfo | null;

    return toEventEncryptionInfo(info);
  }

  async encryptToDeviceMessages(
    eventType: string,
    devices: { userId: string; deviceId: string }[],
    payload: ToDevicePayload
  ): Promise<ToDeviceBatch> {
    const users = [...new Set(devices.map(({ userId }) => userId))];
    await this.#sendTracked(await this.#call('getMissingSessions', { users }));
    await this.#flushOutgoingRequests();

    const encrypted = await Promise.all(
      devices.map(async ({ userId, deviceId }) => {
        const content = (await this.#call('device.encryptToDeviceEvent', {
          userId,
          deviceId,
          eventType,
          content: payload,
        })) as string | null;
        if (!content) return null;
        return { userId, deviceId, payload: JSON.parse(content) as ToDevicePayload };
      })
    );

    return {
      eventType: EventType.RoomMessageEncrypted,
      batch: encrypted.filter((entry) => entry !== null),
    };
  }

  async resetEncryption(authUploadDeviceSigningKeys: UIAuthCallback<void>): Promise<void> {
    await this.disableKeyStorage();
    await this.#resetCrossSigning(authUploadDeviceSigningKeys);
    await this.resetKeyBackup();
  }

  async exportRoomKeys(): Promise<IMegolmSessionData[]> {
    return JSON.parse(await this.exportRoomKeysAsJson()) as IMegolmSessionData[];
  }

  async exportRoomKeysAsJson(): Promise<string> {
    // Already JSON text; stringifying again would double-encode the export.
    return (await this.#call('exportRoomKeys')) as string;
  }

  async importRoomKeys(keys: IMegolmSessionData[], opts?: ImportRoomKeysOpts): Promise<void> {
    await this.#call('importExportedRoomKeys', { keys: JSON.stringify(keys) });
    opts?.progressCallback?.({
      stage: ImportRoomKeyStage.LoadKeys,
      successes: keys.length,
      failures: 0,
      total: keys.length,
    });
  }

  async importRoomKeysAsJson(keys: string, opts?: ImportRoomKeysOpts): Promise<void> {
    await this.importRoomKeys(JSON.parse(keys) as IMegolmSessionData[], opts);
  }

  async userHasCrossSigningKeys(
    userId: string = this.#identity.userId,
    downloadUncached = false
  ): Promise<boolean> {
    if (downloadUncached) {
      await this.#sendTracked(await this.#call('queryKeysForUsers', { users: [userId] }));
    }
    const identity = (await this.#call('getIdentity', { userId })) as EngineIdentityInfo | null;
    return identity !== null;
  }

  async getUserDeviceInfo(userIds: string[], downloadUncached = false): Promise<DeviceMap> {
    if (downloadUncached) {
      await this.#sendTracked(await this.#call('queryKeysForUsers', { users: userIds }));
    }

    const map: DeviceMap = new Map();
    await Promise.all(
      userIds.map(async (userId) => {
        const answer = (await this.#call('getUserDevices', {
          userId,
          timeoutSecs: null,
        })) as { devices?: EngineDevice[] } | null;
        const devices = answer?.devices ?? [];

        map.set(userId, new Map(devices.map((device) => [device.deviceId, toSdkDevice(device)])));
      })
    );
    return map;
  }

  setTrustCrossSignedDevices(val: boolean): void {
    this.#trustCrossSignedDevices = val;
  }

  getTrustCrossSignedDevices(): boolean {
    return this.#trustCrossSignedDevices;
  }

  async getUserVerificationStatus(userId: string): Promise<UserVerificationStatus> {
    const identity = (await this.#call('getIdentity', { userId })) as EngineIdentityInfo | null;
    if (!identity) return new UserVerificationStatus(false, false, false);

    return new UserVerificationStatus(
      identity.isVerified,
      identity.wasPreviouslyVerified,
      true,
      identity.identityNeedsUserApproval ?? false
    );
  }

  async pinCurrentUserIdentity(userId: string): Promise<void> {
    await this.#call('userIdentity.pin', { userId });
  }

  async withdrawVerificationRequirement(userId: string): Promise<void> {
    await this.#call('userIdentity.withdrawVerification', { userId });
  }

  async getUserCrossSigningKeys(userId: string): Promise<Partial<CrossSigningKeys> | null> {
    const identity = (await this.#call('getIdentity', { userId })) as EngineIdentityInfo | null;
    if (!identity) return null;

    return {
      [CrossSigningKey.Master]: parseCrossSigningKey(identity.masterKey),
      [CrossSigningKey.SelfSigning]: parseCrossSigningKey(identity.selfSigningKey),
      [CrossSigningKey.UserSigning]: parseCrossSigningKey(identity.userSigningKey),
    };
  }

  async getDeviceVerificationStatus(
    userId: string,
    deviceId: string
  ): Promise<DeviceVerificationStatus | null> {
    const device = (await this.#call('getDevice', {
      userId,
      deviceId,
      timeoutSecs: null,
    })) as EngineDevice | null;
    if (!device) return null;

    return new DeviceVerificationStatus({
      signedByOwner: device.isCrossSignedByOwner,
      crossSigningVerified: device.isCrossSigningTrusted,
      localVerified: device.isLocallyTrusted,
      trustCrossSignedDevices: this.#trustCrossSignedDevices,
    });
  }

  async setDeviceVerified(userId: string, deviceId: string, verified = true): Promise<void> {
    await this.#call('device.setLocalTrust', {
      userId,
      deviceId,
      trustState: verified ? RustSdkCryptoJs.LocalTrust.Verified : RustSdkCryptoJs.LocalTrust.Unset,
    });
  }

  async crossSignDevice(deviceId: string): Promise<void> {
    await this.#sendTracked(
      await this.#call('device.verify', { userId: this.#identity.userId, deviceId })
    );
    await this.#flushOutgoingRequests();
  }

  async isCrossSigningReady(): Promise<boolean> {
    const status = await this.getCrossSigningStatus();
    const cached = status.privateKeysCachedLocally;
    return (
      status.publicKeysOnDevice &&
      cached.masterKey &&
      cached.selfSigningKey &&
      cached.userSigningKey
    );
  }

  async getCrossSigningKeyId(
    type: CrossSigningKey = CrossSigningKey.Master
  ): Promise<string | null> {
    const keys = await this.getUserCrossSigningKeys(this.#identity.userId);
    const first = Object.values(keys?.[type]?.keys ?? {})[0];
    return first ?? null;
  }

  async bootstrapCrossSigning(opts: BootstrapCrossSigningOpts): Promise<void> {
    if (opts.setupNewCrossSigning) {
      await this.#resetCrossSigning(opts.authUploadDeviceSigningKeys);
      return;
    }

    const status = (await this.#call('crossSigningStatus')) as {
      hasMaster: boolean;
      hasSelfSigning: boolean;
      hasUserSigning: boolean;
    };
    const stored = await this.#crossSigningKeysInStorage();

    if (status.hasMaster && status.hasSelfSigning && status.hasUserSigning) {
      if (!stored && (await this.#mx.secretStorage.hasKey())) {
        await this.#exportCrossSigningKeysToStorage();
      }
      return;
    }

    if (!stored) {
      await this.#resetCrossSigning(opts.authUploadDeviceSigningKeys);
      return;
    }

    await this.#importCrossSigningKeys(stored);
  }

  async #crossSigningKeysInStorage(): Promise<Record<string, string> | null> {
    const [masterKey, selfSigningKey, userSigningKey] = await Promise.all([
      this.#mx.secretStorage.get('m.cross_signing.master'),
      this.#mx.secretStorage.get('m.cross_signing.self_signing'),
      this.#mx.secretStorage.get('m.cross_signing.user_signing'),
    ]);

    if (!masterKey || !selfSigningKey || !userSigningKey) return null;
    return {
      master_key: masterKey,
      self_signing_key: selfSigningKey,
      user_signing_key: userSigningKey,
    };
  }

  async #importCrossSigningKeys(keys: Record<string, string>): Promise<void> {
    const status = (await this.#call('importCrossSigningKeys', keys)) as {
      hasMaster: boolean;
      hasSelfSigning: boolean;
      hasUserSigning: boolean;
    };
    if (!status.hasMaster || !status.hasSelfSigning || !status.hasUserSigning) {
      throw new Error('The cross-signing keys in secret storage could not be imported');
    }

    const request = (await this.#call('device.verify', {
      userId: this.#identity.userId,
      deviceId: this.#identity.deviceId,
    })) as OutgoingRequest | null;
    if (request) await sendOutgoingRequest(this.#mx, request);
  }

  async #exportCrossSigningKeysToStorage(): Promise<void> {
    const exported = (await this.#call('exportCrossSigningKeys')) as Record<
      string,
      string | undefined
    > | null;
    if (!exported) return;

    const entries: [SecretStorageKey, string | undefined][] = [
      ['m.cross_signing.master', exported.masterKey],
      ['m.cross_signing.self_signing', exported.self_signing_key ?? exported.selfSigningKey],
      ['m.cross_signing.user_signing', exported.user_signing_key ?? exported.userSigningKey],
    ];
    await Promise.all(
      entries
        .filter(([, value]) => Boolean(value))
        .map(([name, value]) => this.#mx.secretStorage.store(name, value as string))
    );
  }

  async #resetCrossSigning(uiaCallback?: UIAuthCallback<void>): Promise<void> {
    const requests = (await this.#call('bootstrapCrossSigning', {
      reset: true,
    })) as EngineBootstrapRequests | null;

    if (await this.#mx.secretStorage.hasKey()) await this.#exportCrossSigningKeysToStorage();

    const uploadKeys = requests?.uploadKeysRequest;
    if (uploadKeys) {
      const response = await sendOutgoingRequest(this.#mx, uploadKeys);
      await this.#call('markRequestAsSent', {
        requestId: uploadKeys.id,
        requestType: uploadKeys.type,
        response,
      });
    }

    await this.#uploadDeviceSigningKeys(requests?.uploadSigningKeysRequest, uiaCallback);

    const signatures = requests?.uploadSignaturesRequest;
    if (signatures) await sendOutgoingRequest(this.#mx, signatures);

    await this.#flushOutgoingRequests();
  }

  async #uploadDeviceSigningKeys(
    request: { body: string } | null | undefined,
    uiaCallback?: UIAuthCallback<void>
  ): Promise<void> {
    if (!request) return;

    const body = JSON.parse(request.body) as Record<string, unknown>;
    const send = (auth: AuthDict | null) =>
      this.#mx.http.authedRequest<void>(
        Method.Post,
        '/keys/device_signing/upload',
        undefined,
        auth ? { ...body, auth } : body,
        { prefix: ClientPrefix.V3 }
      );

    if (uiaCallback) await uiaCallback(send);
    else await send(null);
  }

  async isSecretStorageReady(): Promise<boolean> {
    return (await this.getSecretStorageStatus()).ready;
  }

  async getSecretStorageStatus(): Promise<SecretStorageStatus> {
    const defaultKeyId = await this.#mx.secretStorage.getDefaultKeyId();
    if (!defaultKeyId) {
      return { ready: false, defaultKeyId: null, secretStorageKeyValidityMap: {} };
    }

    const names: SecretStorageKey[] = [...SECRETS_IN_STORAGE];
    if (await this.getActiveSessionBackupVersion()) names.push('m.megolm_backup.v1');

    const entries = await Promise.all(
      names.map(
        async (name) => [name, Boolean(await this.#mx.secretStorage.isStored(name))] as const
      )
    );
    const secretStorageKeyValidityMap = Object.fromEntries(entries);

    return {
      ready: entries.every(([, stored]) => stored),
      defaultKeyId,
      secretStorageKeyValidityMap,
    };
  }

  async bootstrapSecretStorage(opts: CreateSecretStorageOpts): Promise<void> {
    const existingKeyId = await this.#mx.secretStorage.getDefaultKeyId();
    const needsKey = opts.setupNewSecretStorage || !existingKeyId;

    if (needsKey) {
      if (!opts.createSecretStorageKey) {
        throw new Error('bootstrapSecretStorage needs createSecretStorageKey to make a new key');
      }
      const key = await opts.createSecretStorageKey();
      const { keyId, keyInfo } = await this.#mx.secretStorage.addKey(
        SECRET_STORAGE_ALGORITHM_V1_AES,
        { ...key.keyInfo, key: key.privateKey }
      );
      await this.#mx.secretStorage.setDefaultKeyId(keyId);
      engineCryptoLog.info('general', 'Created a new secret storage key', {
        keyId,
        algorithm: keyInfo.algorithm,
      });
    }

    await this.#exportCrossSigningKeysToStorage();

    if (opts.setupNewKeyBackup) await this.resetKeyBackup();
  }

  async getCrossSigningStatus(): Promise<CrossSigningStatus> {
    const status = (await this.#call('crossSigningStatus')) as {
      hasMaster: boolean;
      hasSelfSigning: boolean;
      hasUserSigning: boolean;
    };

    return {
      publicKeysOnDevice: status.hasMaster && status.hasSelfSigning && status.hasUserSigning,
      privateKeysInSecretStorage: false,
      privateKeysCachedLocally: {
        masterKey: status.hasMaster,
        selfSigningKey: status.hasSelfSigning,
        userSigningKey: status.hasUserSigning,
      },
    };
  }

  async createRecoveryKeyFromPassphrase(password?: string): Promise<GeneratedSecretStorageKey> {
    if (!password) {
      const key = new Uint8Array(32);
      globalThis.crypto.getRandomValues(key);
      return { privateKey: key, encodedPrivateKey: encodeRecoveryKey(key) };
    }

    const salt = secureRandomString(32);
    const privateKey = await deriveRecoveryKeyFromPassphrase(
      password,
      salt,
      RECOVERY_KEY_DERIVATION_ITERATIONS
    );

    return {
      keyInfo: {
        passphrase: {
          algorithm: 'm.pbkdf2',
          iterations: RECOVERY_KEY_DERIVATION_ITERATIONS,
          salt,
        },
      },
      privateKey,
      encodedPrivateKey: encodeRecoveryKey(privateKey),
    };
  }

  getVerificationRequestsToDeviceInProgress(userId: string): VerificationRequest[] {
    return [...this.#verificationRequests.values()].filter(
      (request) => request.otherUserId === userId && request.roomId === undefined && request.pending
    );
  }

  findVerificationRequestDMInProgress(
    roomId: string,
    userId?: string
  ): VerificationRequest | undefined {
    return [...this.#verificationRequests.values()].find(
      (request) =>
        request.roomId === roomId &&
        request.pending &&
        (userId === undefined || request.otherUserId === userId)
    );
  }

  /** The engine needs the event id of the request we send, so build, send, then register. */
  async requestVerificationDM(userId: string, roomId: string): Promise<VerificationRequest> {
    const requestContent = (await this.#call('userIdentity.verificationRequestContent', {
      userId,
      roomId,
      methods: SUPPORTED_VERIFICATION_METHOD_CODES,
    })) as { outgoingRequest?: { body?: string } } | null;

    const content = requestContent?.outgoingRequest?.body;
    if (!content) throw new Error('The engine produced no verification request content');

    const { event_id: eventId } = await this.#mx.sendEvent(
      roomId,
      EventType.RoomMessage,
      JSON.parse(content) as RoomMessageEventContent
    );

    const started = (await this.#call('userIdentity.requestVerificationDm', {
      userId,
      roomId,
      requestEventId: eventId,
      methods: SUPPORTED_VERIFICATION_METHOD_CODES,
    })) as { request: EngineVerificationState; outgoingRequest?: unknown };

    if (isOutgoingRequest(started.outgoingRequest)) {
      await sendOutgoingRequest(this.#mx, started.outgoingRequest);
    }
    await this.#flushOutgoingRequests();

    const request = new EngineVerificationRequest(this.#engineCall, started.request);
    this.#verificationRequests.set(started.request.flowId, request);
    return request;
  }

  async requestOwnUserVerification(): Promise<VerificationRequest> {
    return this.#startVerification('userIdentity.requestVerification', {
      userId: this.#identity.userId,
      methods: SUPPORTED_VERIFICATION_METHOD_CODES,
    });
  }

  async requestDeviceVerification(userId: string, deviceId: string): Promise<VerificationRequest> {
    return this.#startVerification('device.requestVerification', {
      userId,
      deviceId,
      methods: SUPPORTED_VERIFICATION_METHOD_CODES,
    });
  }

  async getSessionBackupPrivateKey(): Promise<Uint8Array | null> {
    const keys = (await this.#call('getBackupKeys')) as EngineBackupKeys | null;
    if (!keys?.decryptionKeyBase64) return null;
    return decodeBase64(keys.decryptionKeyBase64);
  }

  async storeSessionBackupPrivateKey(key: Uint8Array, version: string): Promise<void> {
    await this.#call('saveBackupDecryptionKey', { decryptionKey: encodeBase64(key), version });
    this.emit(CryptoEvent.KeyBackupDecryptionKeyCached, version);
  }

  async checkSecrets(name: string): Promise<void> {
    const values = ((await this.#call('getSecretsFromInbox', { secretName: name })) ??
      []) as string[];

    for (const value of values) {
      // eslint-disable-next-line no-await-in-loop
      if (await this.#handleSecretReceived(name, value)) break;
    }

    await this.#call('deleteSecretsFromInbox', { secretName: name });
  }

  async #handleSecretReceived(name: string, value: string): Promise<boolean> {
    if (name !== 'm.megolm_backup.v1') return false;

    const backupInfo = await this.getKeyBackupInfo();
    if (!backupInfo?.version) {
      engineCryptoLog.warn('general', 'Received a backup key with no server-side backup');
      return false;
    }

    const publicKey = (backupInfo.auth_data as { public_key?: string } | undefined)?.public_key;
    let matches = false;
    try {
      const key = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(value);
      try {
        matches = key.megolmV1PublicKey.publicKeyBase64 === publicKey;
      } finally {
        key.free();
      }
    } catch (error) {
      engineCryptoLog.warn('general', 'Received an invalid backup decryption key', error);
      return false;
    }

    if (!matches) {
      engineCryptoLog.warn(
        'general',
        `Received a backup key for another backup than version ${backupInfo.version}`
      );
      return false;
    }

    await this.storeSessionBackupPrivateKey(decodeBase64(value), backupInfo.version);
    await this.#connectKeyBackup();
    return true;
  }

  async loadSessionBackupPrivateKeyFromSecretStorage(): Promise<void> {
    const encoded = await this.#mx.secretStorage.get('m.megolm_backup.v1');
    if (!encoded) throw new Error('No session backup key in secret storage');

    const backupInfo = await this.getKeyBackupInfo();
    if (!backupInfo?.version) throw new Error('No key backup version to attach the key to');

    await this.storeSessionBackupPrivateKey(decodeBase64(encoded), backupInfo.version);
  }

  async getActiveSessionBackupVersion(): Promise<string | null> {
    return (await this.#call('backupVersion')) as string | null;
  }

  /** The engine reports signature trust only; whether our key opens it is separate. */
  async isKeyBackupTrusted(info: KeyBackupInfo): Promise<BackupTrustInfo> {
    const verification = (await this.#call('verifyBackup', {
      backupInfo: JSON.stringify(info),
    })) as { trusted?: boolean } | null;

    const stored = await this.getSessionBackupPrivateKey();
    const publicKey = (info.auth_data as { public_key?: string } | undefined)?.public_key;
    let matchesDecryptionKey = false;
    if (stored && publicKey) {
      const key = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(encodeBase64(stored));
      try {
        matchesDecryptionKey = key.megolmV1PublicKey.publicKeyBase64 === publicKey;
      } finally {
        key.free();
      }
    }

    return { trusted: verification?.trusted ?? false, matchesDecryptionKey };
  }

  async getKeyBackupInfo(): Promise<KeyBackupInfo | null> {
    try {
      return await this.#mx.http.authedRequest<KeyBackupInfo>(
        Method.Get,
        '/room_keys/version',
        undefined,
        undefined,
        { prefix: ClientPrefix.V3 }
      );
    } catch (error) {
      if ((error as { errcode?: string }).errcode === 'M_NOT_FOUND') return null;
      throw error;
    }
  }

  async #getKeyBackupInfoForVersion(version: string): Promise<KeyBackupInfo | null> {
    try {
      return await this.#mx.http.authedRequest<KeyBackupInfo>(
        Method.Get,
        encodeUri('/room_keys/version/$version', { $version: version }),
        undefined,
        undefined,
        { prefix: ClientPrefix.V3 }
      );
    } catch (error) {
      if ((error as { errcode?: string }).errcode === 'M_NOT_FOUND') return null;
      throw error;
    }
  }

  async checkKeyBackupAndEnable(): Promise<KeyBackupCheck | null> {
    this.#checkingKeyBackup = this.#checkingKeyBackup
      .catch(() => null)
      .then(() => this.#checkKeyBackupAndEnable());
    return this.#checkingKeyBackup;
  }

  async #checkKeyBackupAndEnable(): Promise<KeyBackupCheck | null> {
    const backupInfo = await this.getKeyBackupInfo();
    const activeVersion = await this.getActiveSessionBackupVersion();

    if (!backupInfo?.version) {
      if (activeVersion !== null) await this.#disableKeyBackup();
      return null;
    }

    const trustInfo = await this.isKeyBackupTrusted(backupInfo);
    const publicKey = (backupInfo.auth_data as { public_key?: string } | undefined)?.public_key;

    if (!publicKey || (!trustInfo.trusted && !trustInfo.matchesDecryptionKey)) {
      if (activeVersion !== null) await this.#disableKeyBackup();
      return { backupInfo, trustInfo };
    }

    if (activeVersion !== backupInfo.version) {
      if (activeVersion !== null) await this.#disableKeyBackup();
      await this.#enableKeyBackup(backupInfo.version, publicKey);
    } else {
      this.#scheduleKeyBackup();
    }
    return { backupInfo, trustInfo };
  }

  async #enableKeyBackup(version: string, publicKeyBase64: string): Promise<void> {
    await this.#call('enableBackupV1', { publicKeyBase64, version });
    this.emit(CryptoEvent.KeyBackupStatus, true);
    this.#scheduleKeyBackup();
  }

  async #disableKeyBackup(): Promise<void> {
    await this.#call('disableBackup');
    this.emit(CryptoEvent.KeyBackupStatus, false);
  }

  async resetKeyBackup(): Promise<void> {
    await this.#deleteAllKeyBackupVersions();

    const key = await this.createRecoveryKeyFromPassphrase();
    const decryptionKey = RustSdkCryptoJs.BackupDecryptionKey.fromBase64(
      encodeBase64(key.privateKey)
    );
    let publicKey: string;
    try {
      publicKey = decryptionKey.megolmV1PublicKey.publicKeyBase64;
    } finally {
      decryptionKey.free();
    }

    const authData: Record<string, unknown> = { public_key: publicKey };
    const signatures = await this.#signatureFor(authData);
    if (signatures) authData.signatures = signatures;

    const created = await this.#mx.http.authedRequest<{ version: string }>(
      Method.Post,
      '/room_keys/version',
      undefined,
      {
        algorithm: 'm.megolm_backup.v1.curve25519-aes-sha2',
        auth_data: authData,
      },
      { prefix: ClientPrefix.V3 }
    );

    await this.#call('enableBackupV1', { publicKeyBase64: publicKey, version: created.version });
    await this.storeSessionBackupPrivateKey(key.privateKey, created.version);
    await this.#pushSecretToVerifiedDevices('m.megolm_backup.v1');
    await this.#mx.secretStorage.store('m.megolm_backup.v1', encodeBase64(key.privateKey));
  }

  async #signatureFor(value: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    const signed = (await this.#call('sign', { message: canonicalJson(value) })) as {
      json?: string;
    } | null;
    if (!signed?.json) return null;
    return JSON.parse(signed.json) as Record<string, unknown>;
  }

  async #pushSecretToVerifiedDevices(secretName: string): Promise<void> {
    await this.#sendTracked(
      await this.#call('getMissingSessions', { users: [this.#identity.userId] })
    );
    await this.#flushOutgoingRequests();
    await this.#call('pushSecretToVerifiedDevices', { secretName });
    await this.#flushOutgoingRequests();
  }

  async disableKeyStorage(): Promise<void> {
    await this.#deleteAllKeyBackupVersions();
    await this.#disableKeyBackup();
    await this.#deleteSecretStorage();
  }

  async #deleteAllKeyBackupVersions(): Promise<void> {
    const seen = new Set<string>();

    for (let attempt = 0; attempt < MAX_BACKUP_VERSIONS_TO_DELETE; attempt += 1) {
      // eslint-disable-next-line no-await-in-loop
      const info = await this.getKeyBackupInfo();
      if (!info?.version || seen.has(info.version)) return;
      seen.add(info.version);
      // eslint-disable-next-line no-await-in-loop
      await this.deleteKeyBackupVersion(info.version);
    }
  }

  async #deleteSecretStorage(): Promise<void> {
    const secrets: SecretStorageKey[] = [...SECRETS_IN_STORAGE, 'm.megolm_backup.v1'];
    await Promise.all(secrets.map((name) => this.#mx.secretStorage.store(name, null)));

    const defaultKeyId = await this.#mx.secretStorage.getDefaultKeyId();
    if (defaultKeyId) {
      await this.#mx.secretStorage.store(
        `m.secret_storage.key.${defaultKeyId}` as SecretStorageKey,
        null
      );
    }
    await this.#mx.secretStorage.setDefaultKeyId(null);
  }

  async deleteKeyBackupVersion(version: string): Promise<void> {
    const active = await this.getActiveSessionBackupVersion();
    await this.#mx.http.authedRequest(
      Method.Delete,
      encodeUri('/room_keys/version/$version', { $version: version }),
      undefined,
      undefined,
      { prefix: ClientPrefix.V3 }
    );
    if (active === version) await this.#disableKeyBackup();
  }

  async restoreKeyBackup(opts?: KeyBackupRestoreOpts): Promise<KeyBackupRestoreResult> {
    const keys = (await this.#call('getBackupKeys')) as EngineBackupKeys | null;
    if (!keys?.decryptionKeyBase64 || !keys.backupVersion) {
      throw new Error('No decryption key found in crypto store');
    }

    const backupInfo = await this.#getKeyBackupInfoForVersion(keys.backupVersion);
    if (!backupInfo) {
      throw new Error(`Backup version ${keys.backupVersion} is not on the server`);
    }

    opts?.progressCallback?.({ stage: ImportRoomKeyStage.Fetch });

    const decryptor = await this.getBackupDecryptor(
      backupInfo,
      decodeBase64(keys.decryptionKeyBase64)
    );
    try {
      const response = await this.#mx.http.authedRequest<{
        rooms: Record<string, { sessions: Record<string, KeyBackupSession> }>;
      }>(Method.Get, '/room_keys/keys', { version: keys.backupVersion }, undefined, {
        prefix: ClientPrefix.V3,
      });

      const rooms = Object.entries(response.rooms ?? {});
      const total = rooms.reduce(
        (count, [, room]) => count + Object.keys(room.sessions ?? {}).length,
        0
      );

      let imported = 0;
      for (const [roomId, room] of rooms) {
        // eslint-disable-next-line no-await-in-loop
        const decrypted = await decryptor.decryptSessions(room.sessions ?? {});
        const withRoom = decrypted.map((session) => ({ ...session, room_id: roomId }));

        for (let start = 0; start < withRoom.length; start += RESTORE_CHUNK_SIZE) {
          // eslint-disable-next-line no-await-in-loop
          imported += await this.#importBackedUpRoomKeys(
            withRoom.slice(start, start + RESTORE_CHUNK_SIZE),
            keys.backupVersion,
            opts,
            imported,
            total
          );
        }
      }

      return { total, imported };
    } finally {
      decryptor.free();
    }
  }

  async restoreKeyBackupWithPassphrase(
    passphrase: string,
    opts?: KeyBackupRestoreOpts
  ): Promise<KeyBackupRestoreResult> {
    const backupInfo = await this.getKeyBackupInfo();
    const passphraseInfo = backupInfo?.auth_data?.private_key_salt
      ? backupInfo.auth_data
      : undefined;
    if (!passphraseInfo?.private_key_salt || !passphraseInfo.private_key_iterations) {
      throw new Error('This backup was not created from a passphrase');
    }

    const privateKey = await deriveRecoveryKeyFromPassphrase(
      passphrase,
      passphraseInfo.private_key_salt,
      passphraseInfo.private_key_iterations
    );
    if (backupInfo?.version)
      await this.storeSessionBackupPrivateKey(privateKey, backupInfo.version);
    return this.restoreKeyBackup(opts);
  }

  async isDehydrationSupported(): Promise<boolean> {
    return false;
  }

  async startDehydration(opts?: StartDehydrationOpts | boolean): Promise<void> {
    // A dehydrated device is a second server-side device; Sable keeps one per session.
    throw new Error(
      `Device dehydration is not supported by the Sable crypto engine (opts: ${JSON.stringify(opts) ?? 'none'})`
    );
  }
}
