import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSsePayload, severityRank } from '../src/api/sse.js';

describe('parseSsePayload (contract: routes_sse.rs {job, phases} / {error})', () => {
  it('accepts a full update frame', () => {
    const p = parseSsePayload(JSON.stringify({ job: { id: 'j1' }, phases: [{ id: 'p1' }] }));
    assert.equal(p?.job?.id, 'j1');
    assert.equal(p?.phases?.length, 1);
  });
  it('drops malformed, empty, and non-string frames', () => {
    assert.equal(parseSsePayload('not json'), null);
    assert.equal(parseSsePayload(''), null);
    assert.equal(parseSsePayload('   '), null);
    assert.equal(parseSsePayload(null), null);
    assert.equal(parseSsePayload(42), null);
    assert.equal(parseSsePayload('[1,2]'), null);
  });
  it('parses duplicate frames identically (idempotent apply)', () => {
    const frame = JSON.stringify({ job: { id: 'j1', status: 'running' }, phases: [] });
    assert.deepEqual(parseSsePayload(frame), parseSsePayload(frame));
  });
  it('keeps phases from error frames carrying partial payloads', () => {
    const p = parseSsePayload(JSON.stringify({ error: 'x', phases: [{ id: 'p1' }] }));
    assert.equal(p?.error, 'x');
    assert.equal(p?.phases?.length, 1);
    assert.equal(p?.job, undefined);
  });
  it('drops a job without an id but keeps error frames', () => {
    assert.equal(parseSsePayload(JSON.stringify({ job: { noid: 1 } }))?.job, undefined);
    const err = parseSsePayload(JSON.stringify({ error: 'job not found or access denied' }));
    assert.equal(err?.error, 'job not found or access denied');
  });
  it('drops non-array phases', () => {
    assert.equal(parseSsePayload(JSON.stringify({ phases: 'x' }))?.phases, undefined);
  });
});

describe('severityRank', () => {
  it('orders worst-first with unknown last', () => {
    const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown', 'bogus'];
    const ranks = order.map(severityRank);
    assert.deepEqual(ranks, [0, 1, 2, 3, 4, 5, 5]);
  });
});
