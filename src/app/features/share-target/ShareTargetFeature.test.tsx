import { createElement } from 'react';
import { render, waitFor } from '@testing-library/react';
import { Provider, createStore } from 'jotai';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShareTargetFeature } from './ShareTargetFeature';
import type { ShareBatch } from '$generated/tauri/types';

const { mockDrain, mockMatrixClient } = vi.hoisted(() => ({
  mockDrain: vi.fn<() => Promise<ShareBatch[]>>(),
  mockMatrixClient: {
    getSyncState: vi.fn<() => string>(),
    getRoom: vi.fn<() => undefined>(),
  },
}));

vi.mock('@tauri-apps/api/core', () => ({
  isTauri: () => true,
}));

vi.mock('@tauri-apps/plugin-os', () => ({
  type: () => 'android',
}));

vi.mock('$generated/tauri/commands', () => ({
  shareInboxDrain: mockDrain,
  shareInboxClear: vi.fn<() => Promise<void>>(),
  shareInboxRead: vi.fn<() => Promise<unknown>>(),
}));

vi.mock('$hooks/useMatrixClient', () => ({
  useMatrixClient: () => mockMatrixClient,
}));

vi.mock('$hooks/useRoomNavigate', () => ({
  useRoomNavigate: () => ({ navigateRoom: vi.fn<() => void>() }),
}));

vi.mock('$hooks/useMessageTargetRooms', () => ({
  useMessageTargetRooms: () => ['!room:example.org'],
}));

vi.mock('$features/navigate', () => ({
  SearchWrapper: ({ pickRoom }: { pickRoom: { title: string } }) =>
    createElement('div', { 'data-testid': 'share-picker' }, pickRoom.title),
}));

vi.mock('$utils/debug', () => ({
  createLogger: () => ({ warn: vi.fn<(...args: unknown[]) => void>() }),
}));

vi.mock('$utils/matrix', () => ({ encryptFile: vi.fn<(...args: unknown[]) => Promise<never>>() }));
vi.mock('$utils/mimeTypes', () => ({
  safeUploadFile: vi.fn<(...args: unknown[]) => Promise<never>>(),
}));
vi.mock('$components/editor/input', () => ({
  plainToEditorInput: vi.fn<(...args: unknown[]) => never>(),
}));
vi.mock('$state/room/roomInputDrafts', () => ({
  roomIdToMsgDraftAtomFamily: vi.fn<(...args: unknown[]) => never>(),
  roomIdToUploadItemsAtomFamily: vi.fn<(...args: unknown[]) => never>(),
}));

describe('ShareTargetFeature', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMatrixClient.getSyncState.mockReturnValue('PREPARED');
    mockDrain.mockResolvedValue([
      { batchId: 'batch-1', items: [{ kind: 'text', text: 'https://example.com' }] },
    ]);
  });

  it('shows a pending share when the client is already prepared', async () => {
    const { getByTestId } = render(
      <Provider store={createStore()}>
        <ShareTargetFeature />
      </Provider>
    );

    await waitFor(() => expect(getByTestId('share-picker')).toHaveTextContent('Share to'));
  });
});
