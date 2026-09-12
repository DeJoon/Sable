import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecretStorageKeyContent } from '$types/matrix/accountData';
import { VerifyCurrentDeviceTile } from './Verification';

const requestOwnUserVerification = vi.hoisted(() => vi.fn<() => Promise<unknown>>());

vi.mock('$hooks/useMatrixClient', () => ({
  useMatrixClient: () => ({
    getSafeUserId: () => '@me:example.org',
    getCrypto: () => ({ requestOwnUserVerification }),
  }),
}));

vi.mock('$components/DeviceVerification', () => ({
  DeviceVerification: () => <div>device verification dialog</div>,
}));

const KEY_ID = 'key-id';
const KEY_CONTENT = { algorithm: 'm.secret_storage.v1.aes-hmac-sha2' } as SecretStorageKeyContent;

const renderTile = (props: Record<string, unknown> = {}) =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <VerifyCurrentDeviceTile
        secretStorageKeyId={KEY_ID}
        secretStorageKeyContent={KEY_CONTENT}
        hasVerifiedOtherDevice
        {...props}
      />
    </QueryClientProvider>
  );

describe('VerifyCurrentDeviceTile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    requestOwnUserVerification.mockResolvedValue({});
  });

  it('starts a self verification so an unverified device is not stuck with the recovery key', async () => {
    renderTile();

    fireEvent.click(screen.getByRole('button', { name: /Verify with Device/i }));

    await waitFor(() => expect(requestOwnUserVerification).toHaveBeenCalledOnce());
    expect(await screen.findByText('device verification dialog')).toBeInTheDocument();
  });

  it('offers the device flow when there is no recovery key to fall back on', async () => {
    renderTile({ secretStorageKeyId: undefined, secretStorageKeyContent: undefined });

    expect(screen.getByRole('button', { name: /Verify with Device/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Verify Manually/i })).toBeNull();
    expect(screen.getByText(/Verify with another device\./)).toBeInTheDocument();
  });

  it('does not offer a request nobody can answer when no other device is verified', async () => {
    renderTile({ hasVerifiedOtherDevice: false });

    expect(screen.queryByRole('button', { name: /Verify with Device/i })).toBeNull();
    expect(screen.getByRole('button', { name: /Verify Manually/i })).toBeInTheDocument();
    expect(screen.getByText(/recovery key/i)).toBeInTheDocument();
  });

  it('says to reset when there is neither a verified device nor a recovery key', async () => {
    renderTile({
      hasVerifiedOtherDevice: false,
      secretStorageKeyId: undefined,
      secretStorageKeyContent: undefined,
    });

    expect(screen.queryByRole('button', { name: /Verify with Device/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Verify Manually/i })).toBeNull();
    expect(screen.getByText(/reset device verification/i)).toBeInTheDocument();
  });

  it('reports why the request failed instead of silently doing nothing', async () => {
    requestOwnUserVerification.mockRejectedValue(new Error('no cross-signing identity'));
    renderTile();

    fireEvent.click(screen.getByRole('button', { name: /Verify with Device/i }));

    expect(await screen.findByText('no cross-signing identity')).toBeInTheDocument();
  });
});
