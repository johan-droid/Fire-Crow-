import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertCircle, ShieldAlert, Trash2 } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { api } from './api/client';

import type { UserProfile } from './LandingPage';

interface AccountDeletionRequestProps {
  user: UserProfile | null;
  onNavigateLogin: () => void;
  onNavigateLanding: () => void;
}

/**
 * Account deletion request page (Phase 3B).
 *
 * Authenticated users can request deletion of their account. A grace-period
 * deadline is recorded and a single-purpose cancellation token is issued.
 * The confirmation email is sent server-side; this page only initiates the
 * request and displays the result honestly — it never claims delivery.
 */
export default function AccountDeletionRequest({
  user,
  onNavigateLogin,
  onNavigateLanding,
}: AccountDeletionRequestProps) {
  const navigate = useNavigate();
  const [isRequesting, setIsRequesting] = useState(false);
  const [deadline, setDeadline] = useState<string | null>(null);
  const [cancelUrl, setCancelUrl] = useState<string | null>(null);
  const [error, setError] = useState('');

  const requestDeletion = useCallback(async () => {
    setIsRequesting(true);
    setError('');
    try {
      const body = await api.deletionRequest();
      setDeadline(body.deadline);
      setCancelUrl(body.cancel_url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not submit deletion request.');
    } finally {
      setIsRequesting(false);
    }
  }, []);

  const handleCancel = useCallback(() => {
    if (cancelUrl) navigate(cancelUrl);
  }, [cancelUrl, navigate]);

  if (!user) {
    onNavigateLogin();
    return null;
  }

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
          Account deletion
        </h1>
        <p style={{ color: '#6b7280', marginTop: 8 }}>
          Request deletion of your Fire Crow account. You will have a grace
          period to cancel before the deletion completes.
        </p>
      </header>

      {!deadline && (
        <section style={{ marginBottom: 24 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 12,
              marginBottom: 16,
            }}
          >
            <ShieldAlert size={20} color="#ea580c" />
            <div>
              <strong style={{ color: '#1a1a18' }}>
                This cannot be undone.
              </strong>
              <p style={{ margin: 4, color: '#4a4540', fontSize: 14 }}>
                After the deadline passes, your account record, credentials,
                and sessions are removed. Scan results tied to your account
                are anonymized or retained where the law or our retention
                policy requires. Some information may remain in backups or
                external processors subject to separate policies.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={requestDeletion}
            disabled={isRequesting}
            style={{
              background: '#ea580c',
              color: '#14100d',
              border: 'none',
              borderRadius: 10,
              padding: '12px 24px',
              font: '600 1rem var(--lp-body)',
              cursor: isRequesting ? 'not-allowed' : 'pointer',
              opacity: isRequesting ? 0.6 : 1,
            }}
          >
            {isRequesting ? 'Requesting…' : 'Request account deletion'}
          </button>
          <button
            type="button"
            onClick={onNavigateLanding}
            style={{
              marginLeft: 12,
              background: 'transparent',
              color: '#6b7280',
              border: '1px solid #d1d5db',
              borderRadius: 10,
              padding: '12px 24px',
              font: '600 1rem var(--lp-body)',
              cursor: 'pointer',
            }}
          >
            Keep my account
          </button>
        </section>
      )}

      {deadline && cancelUrl && (
        <section
          style={{
            background: '#f7f5f0',
            border: '1px solid #e7dfd2',
            borderRadius: 12,
            padding: 24,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 12,
              marginBottom: 16,
            }}
          >
            <Trash2 size={20} color="#ea580c" />
            <div>
              <strong style={{ color: '#1a1a18' }}>Deletion requested.</strong>
              <p style={{ margin: 4, color: '#4a4540', fontSize: 14 }}>
                Your account is scheduled for deletion on{' '}
                <strong style={{ color: '#1a1a18' }}>{deadline}</strong>. You can cancel
                at any time before the deadline.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleCancel}
            style={{
              background: '#1a1a18',
              color: '#fff',
              border: 'none',
              borderRadius: 10,
              padding: '12px 24px',
              font: '600 1rem var(--lp-body)',
              cursor: 'pointer',
              marginBottom: 12,
            }}
          >
            Cancel deletion
          </button>
          <p style={{ color: '#6b7280', fontSize: 14, marginTop: 12 }}>
            A confirmation email was sent to {user.email || 'the address on file'}.{' '}
            <em style={{ color: '#4a4540' }}>
              Email acceptance is not proof of inbox delivery.
            </em>
          </p>
        </section>
      )}

      {error && !deadline && (
        <section
          style={{
            background: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: 12,
            padding: 24,
            color: '#991b1b',
          }}
        >
          <AlertCircle size={20} style={{ marginRight: 8 }} />
          <strong>Request failed.</strong>{' '}
          {error && <span style={{ marginLeft: 4 }}>{error}</span>}
          <button
            type="button"
            onClick={() => setError('')}
            style={{
              marginTop: 12,
              background: 'transparent',
              color: '#ea580c',
              border: '1px solid #fca5a5',
              borderRadius: 8,
              padding: '8px 16px',
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </section>
      )}

      <footer
        style={{
          marginTop: 32,
          borderTop: '1px solid #e7dfd2',
          paddingTop: 24,
        }}
      >
        <button
          type="button"
          onClick={onNavigateLanding}
          style={{
            background: 'none',
            border: 'none',
            color: '#6b7280',
            fontSize: 14,
            cursor: 'pointer',
            textDecoration: 'underline',
          }}
        >
          ← Back to landing
        </button>
      </footer>
    </div>
  );
}
