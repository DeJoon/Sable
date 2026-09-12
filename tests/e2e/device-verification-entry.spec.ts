import type { Page } from '@playwright/test';
import { test, expect } from './fixtures/test';
import { homeserverBaseUrl, PASSWORD, type InjectedSession } from './fixtures/session';
import {
  loginUser,
  registerUser,
  setAccountData,
  type RegisteredUser,
} from './fixtures/continuwuity';

const injectSession = async (page: Page, baseUrl: string, user: RegisteredUser): Promise<void> => {
  const session: InjectedSession = {
    baseUrl,
    userId: user.userId,
    deviceId: user.deviceId,
    accessToken: user.accessToken,
    slidingSyncOptIn: false,
  };
  await page.addInitScript((injected: InjectedSession) => {
    localStorage.setItem('matrixSessions', JSON.stringify([injected]));
    localStorage.setItem('matrixActiveSession', JSON.stringify(injected.userId));
    localStorage.setItem('dismissNotice', 'true');
  }, session);
};

test.describe('device verification entry points', () => {
  test('an unverified session can still start verification with another session', async ({
    browser,
  }, testInfo) => {
    test.setTimeout(300_000);
    const storageStatePath = testInfo.project.use.storageState as string;
    const hsBaseUrl = await homeserverBaseUrl(storageStatePath);
    const username = `two-device-${testInfo.project.name}-${process.pid}`;

    const first = await registerUser(hsBaseUrl, username, PASSWORD);
    await setAccountData(hsBaseUrl, first, 'm.cross_signing.master', { encrypted: {} });
    const second = await loginUser(hsBaseUrl, username, PASSWORD);

    const firstContext = await browser.newContext({ storageState: undefined });
    const firstPage = await firstContext.newPage();
    await injectSession(firstPage, hsBaseUrl, first);
    await firstPage.goto('/settings/devices');
    await expect(firstPage.getByText(first.deviceId).first()).toBeVisible({ timeout: 120_000 });
    await expect
      .poll(
        async () => {
          const response = await fetch(`${hsBaseUrl}/_matrix/client/v3/keys/query`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${first.accessToken}` },
            body: JSON.stringify({ device_keys: { [first.userId]: [] } }),
          });
          const body = (await response.json()) as {
            device_keys?: Record<string, Record<string, unknown>>;
          };
          return Object.keys(body.device_keys?.[first.userId] ?? {}).length;
        },
        { timeout: 120_000, intervals: [2_000] }
      )
      .toBeGreaterThanOrEqual(1);

    const context = await browser.newContext({ storageState: undefined });
    const page = await context.newPage();
    await injectSession(page, hsBaseUrl, second);

    await page.goto('/settings/devices');
    await expect(page.getByText('Others')).toBeVisible({ timeout: 120_000 });
    await expect(page.getByText(first.deviceId).first()).toBeVisible({ timeout: 120_000 });

    const otherDeviceTile = page.getByText(
      'Verify device identity and grant access to encrypted messages.',
      { exact: true }
    );
    await expect(otherDeviceTile).toBeVisible({ timeout: 120_000 });

    await page
      .getByRole('button', { name: 'Verify', exact: true })
      .last()
      .click({ timeout: 60_000 });

    await expect(
      firstPage.getByText('Click accept to start the verification process.')
    ).toBeVisible({ timeout: 120_000 });

    await context.close();
    await firstContext.close();
  });
});
