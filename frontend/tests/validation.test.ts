import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildSubmitRequest, isValidCommitSha } from '../src/api/validation.js';

describe('isValidCommitSha (mirrors backend is_valid_commit_sha)', () => {
  it('accepts 40 lowercase hex chars', () => {
    assert.equal(isValidCommitSha('a'.repeat(40)), true);
    assert.equal(isValidCommitSha('0123456789abcdef'.repeat(2) + '01234567'), true);
  });
  it('rejects uppercase, wrong length, non-hex, empty', () => {
    assert.equal(isValidCommitSha('A'.repeat(40)), false);
    assert.equal(isValidCommitSha('a'.repeat(39)), false);
    assert.equal(isValidCommitSha('a'.repeat(41)), false);
    assert.equal(isValidCommitSha('g'.repeat(40)), false);
    assert.equal(isValidCommitSha(''), false);
    assert.equal(isValidCommitSha('  ' + 'a'.repeat(40) + '  '), false);
  });
});

describe('buildSubmitRequest', () => {
  it('trims, defaults branch to main, nulls empty sha', () => {
    const req = buildSubmitRequest({ repoUrl: '  https://github.com/o/r  ', repoBranch: '', commitSha: '' });
    assert.equal(req.repo_url, 'https://github.com/o/r');
    assert.equal(req.repo_branch, 'main');
    assert.equal(req.commit_sha, null);
  });
  it('passes a valid sha through', () => {
    const sha = 'b'.repeat(40);
    const req = buildSubmitRequest({ repoUrl: 'https://github.com/o/r', commitSha: ` ${sha} ` });
    assert.equal(req.commit_sha, sha);
  });
  it('always includes custom_email:null (stable wire shape; backend Option defaults absent to None)', () => {
    const req = buildSubmitRequest({ repoUrl: 'https://github.com/o/r' });
    assert.ok('custom_email' in req);
    assert.equal(req.custom_email, null);
    const wire = JSON.parse(JSON.stringify(req)) as Record<string, unknown>;
    assert.ok('custom_email' in wire, 'key must survive JSON serialization');
    assert.equal(wire['custom_email'], null);
  });
});
