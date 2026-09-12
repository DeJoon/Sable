import { useSyncExternalStore } from 'react';

export type ToastStatus = 'success' | 'error';

export type ToastMessage = { id: number; text: string; status: ToastStatus };

let current: ToastMessage | null = null;
let counter = 0;
let timer: ReturnType<typeof setTimeout> | undefined;
const listeners = new Set<() => void>();

const notify = (): void => {
  listeners.forEach((listener) => listener());
};

const show = (text: string, status: ToastStatus, durationMs: number): void => {
  counter += 1;
  current = { id: counter, text, status };
  notify();

  if (timer) clearTimeout(timer);
  timer = setTimeout(() => {
    current = null;
    timer = undefined;
    notify();
  }, durationMs);
};

export const showToast = (text: string, durationMs = 3000): void =>
  show(text, 'success', durationMs);

export const showErrorToast = (text: string, durationMs = 3000): void =>
  show(text, 'error', durationMs);

const subscribe = (listener: () => void): (() => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

const getSnapshot = (): ToastMessage | null => current;

export const useToastMessage = (): ToastMessage | null =>
  useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
