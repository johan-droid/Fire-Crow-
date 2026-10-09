// Findings-explorer data layer: normalize the two finding shapes (deterministic
// report rows vs job-detail rows) into one filterable row, then filter + sort.
// Everything displayed is backend-provided; nothing is recalculated.
import { severityRank } from './sse.js';
import type { CanonicalReference, ReportFinding } from './types.js';

export interface ExplorerFinding {
  key: string;
  severity: string;
  title: string;
  description: string;
  file: string | null;
  line: number | null;
  cvss: number | null;
  cwe: string | null;
  remediation: string | null;
  evidence: string | null;
  evidenceTruncated: boolean;
  references: CanonicalReference[];
}

/** Canonical report rows carry evidence + references but no CVSS. */
export function fromReportFindings(findings: ReportFinding[]): ExplorerFinding[] {
  return findings.map((f) => ({
    key: f.id,
    severity: f.severity,
    title: f.title,
    description: f.description,
    file: f.location?.file ?? null,
    line: f.location?.line ?? null,
    cvss: null,
    cwe: f.cwe_id ?? null,
    remediation: f.remediation ?? null,
    evidence: f.evidence ?? null,
    evidenceTruncated: f.evidence_truncated ?? false,
    references: f.references ?? [],
  }));
}

/** Job-detail rows carry CVSS but no curated evidence/references. */
export function fromDetailFindings(
  findings: {
    id: string;
    title: string;
    description: string;
    severity: string;
    file_path?: string | null;
    line_number?: number | null;
    cvss_score?: number | null;
    cwe_id?: string | null;
    remediation?: string | null;
    evidence?: string | null;
  }[],
): ExplorerFinding[] {
  return findings.map((f) => ({
    key: f.id,
    severity: f.severity,
    title: f.title,
    description: f.description,
    file: f.file_path ?? null,
    line: f.line_number ?? null,
    cvss: f.cvss_score ?? null,
    cwe: f.cwe_id ?? null,
    remediation: f.remediation ?? null,
    evidence: f.evidence ?? null,
    evidenceTruncated: false,
    references: [],
  }));
}

export function filterFindings(
  rows: ExplorerFinding[],
  query: string,
  sev: string,
): ExplorerFinding[] {
  const q = query.trim().toLowerCase();
  return rows
    .filter((r) => (sev === 'all' ? true : r.severity.toLowerCase() === sev))
    .filter(
      (r) =>
        !q ||
        `${r.title} ${r.description} ${r.file ?? ''} ${r.cwe ?? ''}`.toLowerCase().includes(q),
    )
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title),
    );
}

/**
 * Clickable only for absolute http(s) URLs. URL-parsed, never
 * substring-sniffed: `javascript:`, `data:`, relative, and malformed inputs
 * all fail closed and must be rendered as plain text by callers.
 */
export function isSafeExternalUrl(value: string): boolean {
  const trimmed = (value ?? '').trim();
  if (!trimmed) return false;
  try {
    const protocol = new URL(trimmed).protocol.toLowerCase();
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}
