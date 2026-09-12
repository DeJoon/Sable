import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installConsolePasteScamWarning } from './consolePasteScamWarning';

const isMobileTauri = vi.hoisted(() => vi.fn<() => boolean>());

vi.mock('./platform', () => ({ isMobileTauri }));

describe('installConsolePasteScamWarning', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    window.innerWidth = 800;
    window.outerWidth = 800;
    window.innerHeight = 400;
    // A soft keyboard shrinks the viewport by far more than the 160px threshold.
    window.outerHeight = 900;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('stays silent on a phone, where the keyboard looks like docked devtools', () => {
    isMobileTauri.mockReturnValue(true);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    installConsolePasteScamWarning();
    vi.advanceTimersByTime(2000);

    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('still warns on desktop when devtools look docked', () => {
    isMobileTauri.mockReturnValue(false);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    installConsolePasteScamWarning();
    vi.advanceTimersByTime(2000);

    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});
