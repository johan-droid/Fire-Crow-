// Toast notifications: accessible, dismissible, no secrets, no crashes.
//
// Deliberately hand-rolled (~80 lines) rather than adding a dependency: the
// project already ships React 19 + a token-based CSS system, and the required
// behaviour is one live region plus a list. A library would add a build weight
// and dependency surface for no capability we do not already have.
//
// Accessibility contract:
// - One polite live region per toast; role="status" for info/success,
//   role="alert" for warnings/errors so screen readers interrupt.
// - Dismiss control is a real <button> with an accessible name.
// - Toasts never trap focus and never render user data beyond a short message.
import { useEffect, useRef, useState } from 'react';

export type ToastTone = 'success' | 'info' | 'warning' | 'error';

export interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
}

/** Auto-dismissal per tone; warnings/errors stay longer. 0 = never auto-hide. */
const DURATIONS: Record<ToastTone, number> = {
  success: 5000,
  info: 5000,
  warning: 12000,
  error: 0,
};

export function useToasts() {  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const dismiss = (id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const push = (tone: ToastTone, message: string): number => {
    // Toast failures must never break the app: guard against empty/non-string.
    const text = typeof message === 'string' && message.trim() ? message.slice(0, 300) : 'Notification';
    const id = nextId.current++;
    setToasts((prev) => [...prev.slice(-3), { id, tone, message: text }]);
    const ms = DURATIONS[tone];
    if (ms > 0) {
      const t = setTimeout(() => dismiss(id), ms);
      timers.current.push(t);
    }
    return id;
  };

  useEffect(() => {
    return () => {
      for (const t of timers.current) clearTimeout(t);
      timers.current = [];
    };
  }, []);

  return { toasts, push, dismiss };
}
