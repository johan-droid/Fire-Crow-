// Live-stream helpers, extracted from App.tsx so they are unit-testable.
// The SSE contract lives in backend/src/api/routes_sse.rs:
// events `update`/`done` carry {job, phases}, `error` carries {error}.
import type { JobResponse, PhaseLedgerEntry, SseJobPayload } from './types.js';

/**
 * Guarded SSE payload parser: stream data is untrusted, never blind-cast.
 * Returns the validated subset (job + phases + error); malformed frames are
 * dropped. A stream error never means completion — only a `done` event does.
 */
export function parseSsePayload(data: unknown): SseJobPayload | null {
  if (typeof data !== 'string' || !data.trim()) return null;
  let p: unknown;
  try {
    p = JSON.parse(data);
  } catch {
    return null;
  }
  if (!p || typeof p !== 'object' || Array.isArray(p)) return null;
  const out: SseJobPayload = {};
  const rec = p as Record<string, unknown>;
  if (Array.isArray(rec.phases)) out.phases = rec.phases as PhaseLedgerEntry[];
  const job = rec.job;
  if (job && typeof job === 'object' && typeof (job as JobResponse).id === 'string') {
    out.job = job as JobResponse;
  }
  if (typeof rec.error === 'string') out.error = rec.error;
  return out;
}

// Severity rank for explorer sorting: worst first, unknown last (never first).
export function severityRank(s: string): number {
  switch ((s || '').toLowerCase()) {
    case 'critical': return 0;
    case 'high': return 1;
    case 'medium': return 2;
    case 'low': return 3;
    case 'info': return 4;
    default: return 5;
  }
}
