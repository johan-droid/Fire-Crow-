// Toast view layer. The state hook lives in ./toast.ts (pure, unit-testable).
import type { Toast } from './toast';

export function ToastHost({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: number) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    <div className="toast-host" aria-label="Notifications">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`toast toast-${t.tone}`}
          role={t.tone === 'warning' || t.tone === 'error' ? 'alert' : 'status'}
          aria-live={t.tone === 'warning' || t.tone === 'error' ? 'assertive' : 'polite'}
        >
          <span className="toast-dot" aria-hidden="true" />
          <span className="toast-message">{t.message}</span>
          <button
            type="button"
            className="toast-close"
            onClick={() => onDismiss(t.id)}
            aria-label={`Dismiss notification: ${t.message}`}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
