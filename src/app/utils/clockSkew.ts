const MAX_FUTURE_SECONDS = 5 * 60;
const MAX_PAST_SECONDS = 10 * 60;
const MARGIN_SECONDS = 30;

export const clockSkewMessage = (skewSeconds: number): string | undefined => {
  const minutes = Math.round(Math.abs(skewSeconds) / 60);
  if (skewSeconds > MAX_FUTURE_SECONDS - MARGIN_SECONDS) {
    return `This device's clock is about ${minutes} minutes ahead of the server. The other device would ignore the verification request. Fix the clock, then try again.`;
  }
  if (-skewSeconds > MAX_PAST_SECONDS - MARGIN_SECONDS) {
    return `This device's clock is about ${minutes} minutes behind the server. The other device would ignore the verification request. Fix the clock, then try again.`;
  }
  return undefined;
};

export const homeserverClockSkewSeconds = async (
  baseUrl: string,
  now: number = Date.now()
): Promise<number | undefined> => {
  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, '')}/_matrix/client/versions`, {
      method: 'GET',
      cache: 'no-store',
    });
    const date = response.headers.get('date');
    if (!date) return undefined;
    const serverTime = Date.parse(date);
    if (Number.isNaN(serverTime)) return undefined;
    return Math.round((now - serverTime) / 1000);
  } catch {
    return undefined;
  }
};

export const verificationClockWarning = async (
  baseUrl: string | undefined
): Promise<string | undefined> => {
  if (!baseUrl) return undefined;
  const skew = await homeserverClockSkewSeconds(baseUrl);
  if (skew === undefined) return undefined;
  return clockSkewMessage(skew);
};
