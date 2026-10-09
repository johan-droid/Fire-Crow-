import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static a11y guards for the inspector modal (the newest interactive surface).
// They assert the markers exist in source, not that a screen reader was run:
// assistive-tech verification still needs a manual pass (see Phase 15 notes).
const app = readFileSync(join(process.cwd(), 'src', 'App.tsx'), 'utf8');

describe('inspector modal keyboard support', () => {
  it('exposes a dialog with an Escape handler and an autofocused close', () => {
    assert.ok(app.includes('role="dialog"'), 'dialog role missing');
    assert.ok(app.includes("e.key === 'Escape'"), 'Escape handler missing');
    assert.ok(
      /<button onClick=\{\(\) => closeInspector\(\)\} className="btn btn-primary" autoFocus>/.test(app),
      'autofocused Close missing',
    );
  });
  it('announces async errors as alerts', () => {
    const alerts = (app.match(/className="error-box" role="alert"/g) ?? []).length;
    assert.ok(alerts >= 3, `expected modal/report/narrative alerts, found ${alerts}`);
  });
  it('labels the explorer controls', () => {
    assert.ok(app.includes('aria-label="Search findings"'), 'search label missing');
    assert.ok(app.includes('aria-label="Filter by severity"'), 'filter label missing');
  });
});
