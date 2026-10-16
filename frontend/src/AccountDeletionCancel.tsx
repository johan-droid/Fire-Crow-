import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertCircle, CheckCircle2 } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { api } from './api/client';

interface AccountDeletionCancelProps {
  onNavigateLanding: () => void;
}

/**
 * Account deletion cancellation page (Phase 3B).
 *
 * Reached via the single-purpose cancellation token in the confirmation
 * email. Authenticated users can cancel a pending deletion request before
 * the grace-period deadline passes.
 */
export default function AccountDeletionCancel({
  onNavigateLanding,
}: AccountDeletionCancelProps) {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [status, setStatus] = useState<'idle' | 'checking' | 'cancelled' | 'error'>(
    'idle',
  );
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setError('No cancellation token provided.');
      return;
    }
    setStatus('checking');
    api.deletionCancel(token)
      .then((body) => {
        if (body.status === 'cancelled') {
          setStatus('cancelled');
        } else {
          setStatus('error');
          setError('Cancellation could not be completed.');
        }
      })
      .catch((err: unknown) => {
        setStatus('error');
        setError(
          err instanceof Error ? err.message : 'Could not cancel deletion request.',
        );
      });
  }, [token]);

  return (
    <div
      className="ad-page"
      style={{ maxWidth: 520, margin: '0 auto', padding: 40, fontFamily: 'var(--lp-body)' }}
    >
      <header style={{ marginBottom: 32 }}>
        <BrandMark size={32} />
        <h1
          style={{
            fontFamily: 'var(--lp-display-serif)',
            fontSize: 26,
            marginTop: 12,
          }}
        >
          Cancel account deletion
        </h1>
      </header>

      {status === 'checking' && (
        <p style={{ color: '#6b7280' }}>Processing your cancellation request…</p>
      )}

      {status === 'cancelled' && (
        <section
          style={{
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
            borderRadius: 12,
            padding: 24,
            color: '#166534',
          }}
        >
          <CheckCircle2 size={28} style={{ marginBottom: 12 }} />
          <strong style={{ color: '#1a1a18' }}>Deletion cancelled.</strong>
          <p style={{ marginTop: 8 }}>
            Your account deletion request has been cancelled. Your account is
            safe and no further action is needed.
          </p>
          <button
            type="button"
            onClick={onNavigateLanding}
            style={{
              marginTop: 16,
              background: '#1a1a18',
              color: '#fff',
              border: 'none',
              borderRadius: 10,
              padding: '12px 24px',
              font: '600 1rem var(--lp-body)',
              cursor: 'pointer',
            }}
          >
            Back to landing
          </button>
        </section>
      )}

      {status === 'error' && (
        <section
          style={{
            background: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: 12,
            padding: 24,
            color: '#991b1b',
          }}
        >
          <AlertCircle size={28} style={{ marginBottom: 12 }} />
          <strong style={{ color: '#1a1a18' }}>Cancellation failed.</strong>
          <p style={{ marginTop: 8 }}>{error}</p>
          <button
            type="button"
            onClick={onNavigateLanding}
            style={{
              marginTop: 16,
              background: '#ea580c',
              color: '#14100d',
              border: 'none',
              borderRadius: 10,
              padding: '12px 24px',
              font: '600 1rem var(--lp-body)',
              cursor: 'pointer',
            }}
          >
            Back to landing
          </button>
        </section>
      )}
    </div>
  );
}
