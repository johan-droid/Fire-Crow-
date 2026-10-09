import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  filterFindings,
  fromDetailFindings,
  fromReportFindings,
  isSafeExternalUrl,
} from '../src/api/explorer.js';
import type { ReportFinding } from '../src/api/types.js';

const reportRow: ReportFinding = {
  id: 'f-1',
  agent_source: 'gitleaks',
  title: 'Exposed secret',
  description: 'A token in config',
  severity: 'high',
  cwe_id: 'CWE-798',
  remediation: 'Rotate it',
  evidence: 'token = "abc"',
  evidence_truncated: true,
  location: { file: 'config.env', line: 3 },
  references: [{ reference_type: 'WEB', url: 'https://example.com/x' }],
};

describe('fromReportFindings', () => {
  it('normalizes evidence, truncation flag, location, references; cvss stays null', () => {
    const [row] = fromReportFindings([reportRow]);
    assert.equal(row.file, 'config.env');
    assert.equal(row.line, 3);
    assert.equal(row.evidence, 'token = "abc"');
    assert.equal(row.evidenceTruncated, true);
    assert.equal(row.references.length, 1);
    assert.equal(row.cvss, null);
  });
});

describe('fromDetailFindings', () => {
  it('carries cvss and path; evidence unflagged', () => {
    const [row] = fromDetailFindings([
      {
        id: 'd-1', title: 'T', description: 'D', severity: 'low',
        file_path: 'a.ts', line_number: 9, cvss_score: 3.5, evidence: 'x',
      },
    ]);
    assert.equal(row.cvss, 3.5);
    assert.equal(row.evidenceTruncated, false);
  });
});

describe('isSafeExternalUrl (URL-parsed, fail-closed)', () => {
  it('permits absolute http/https links', () => {
    assert.equal(isSafeExternalUrl('http://example.com/x'), true);
    assert.equal(isSafeExternalUrl('https://example.com/x?a=1#y'), true);
    assert.equal(isSafeExternalUrl('  HTTPS://EXAMPLE.COM/  '), true);
  });
  it('rejects javascript:, data:, other protocols, relative, malformed', () => {
    assert.equal(isSafeExternalUrl('javascript:alert(1)'), false);
    assert.equal(isSafeExternalUrl('JaVaScRiPt:alert(1)'), false);
    assert.equal(isSafeExternalUrl('data:text/html,<h1>x</h1>'), false);
    assert.equal(isSafeExternalUrl('ftp://example.com/f'), false);
    assert.equal(isSafeExternalUrl('file:///etc/passwd'), false);
    assert.equal(isSafeExternalUrl('/relative/path'), false);
    assert.equal(isSafeExternalUrl('example.com/no-scheme'), false);
    assert.equal(isSafeExternalUrl('http://'), false);
    assert.equal(isSafeExternalUrl(''), false);
    assert.equal(isSafeExternalUrl('   '), false);
  });
});

describe('filterFindings', () => {
  const rows = fromReportFindings([
    reportRow,
    { ...reportRow, id: 'f-2', severity: 'unknown', title: 'Mystery dep', description: 'dep', cwe_id: null },
  ]);
  it('sorts worst-first with unknown last', () => {
    assert.deepEqual(filterFindings(rows, '', 'all').map((r) => r.key), ['f-1', 'f-2']);
  });
  it('filters by severity and query (title/desc/path/cwe)', () => {
    assert.equal(filterFindings(rows, '', 'unknown').length, 1);
    assert.equal(filterFindings(rows, 'config.env', 'all').length, 2);
    assert.equal(filterFindings(rows, 'cwe-798', 'all').length, 1);
    assert.equal(filterFindings(rows, 'nope', 'all').length, 0);
  });
});
