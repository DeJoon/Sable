import { describe, expect, it } from 'vitest';
import { type SyncActivity, nextSyncAction } from './syncActivity';

const activity = (overrides: Partial<SyncActivity> = {}): SyncActivity => ({
  visible: false,
  callActive: false,
  drainingPush: false,
  ...overrides,
});

describe('nextSyncAction', () => {
  it('stops a running transport once nothing needs it', () => {
    expect(nextSyncAction(false, activity())).toBe('stop');
  });

  it.each([
    ['visible', { visible: true }],
    ['a call is active', { callActive: true }],
    ['a push is draining', { drainingPush: true }],
  ])('starts a parked transport when %s', (_label, overrides) => {
    expect(nextSyncAction(true, activity(overrides))).toBe('start');
  });

  it.each([
    ['visible', { visible: true }],
    ['a call is active', { callActive: true }],
    ['a push is draining', { drainingPush: true }],
  ])('keeps a running transport while %s', (_label, overrides) => {
    expect(nextSyncAction(false, activity(overrides))).toBe('none');
  });

  it('starts a parked transport without consulting connectivity', () => {
    expect(nextSyncAction(true, activity({ visible: true }))).toBe('start');
  });

  it('reaches the same answer whichever input changed', () => {
    expect(nextSyncAction(true, activity({ visible: true }))).toBe(
      nextSyncAction(true, activity({ drainingPush: true }))
    );
  });
});
