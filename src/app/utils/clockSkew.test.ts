import { describe, expect, it, vi } from 'vitest';
import { clockSkewMessage, homeserverClockSkewSeconds } from './clockSkew';

describe('clockSkewMessage', () => {
  it('stays quiet inside the window the spec allows', () => {
    expect(clockSkewMessage(0)).toBeUndefined();
    expect(clockSkewMessage(120)).toBeUndefined();
    expect(clockSkewMessage(-540)).toBeUndefined();
  });

  it('warns when we are far enough ahead that the peer ignores the request', () => {
    expect(clockSkewMessage(6 * 60)).toMatch(/ahead/);
  });

  it('warns when we are far enough behind that the peer ignores the request', () => {
    expect(clockSkewMessage(-11 * 60)).toMatch(/behind/);
  });
});

describe('homeserverClockSkewSeconds', () => {
  it('reads the skew from the server date header', async () => {
    const serverTime = new Date('2026-09-01T12:00:00Z');
    vi.stubGlobal(
      'fetch',
      vi.fn<() => Promise<Response>>(
        async () =>
          ({
            headers: new Headers({ date: serverTime.toUTCString() }),
          }) as Response
      )
    );

    const skew = await homeserverClockSkewSeconds(
      'https://hs.example.org',
      serverTime.getTime() + 8 * 60 * 1000
    );

    expect(skew).toBe(480);
    vi.unstubAllGlobals();
  });

  it('says nothing when the server cannot be reached', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<() => Promise<Response>>(async () => {
        throw new Error('offline');
      })
    );

    expect(await homeserverClockSkewSeconds('https://hs.example.org')).toBeUndefined();
    vi.unstubAllGlobals();
  });
});
