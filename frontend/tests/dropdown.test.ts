import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static guards for the console dropdown primitive and its wiring. They assert
// the accessible contract exists in source (the repo has no DOM test runner);
// a screen-reader pass still needs a manual check.
const cwd = process.cwd();
const dropdown = readFileSync(join(cwd, 'src', 'dashboard', 'Dropdown.tsx'), 'utf8');
const dropdownCss = readFileSync(join(cwd, 'src', 'dashboard', 'dropdown.css'), 'utf8');
const app = readFileSync(join(cwd, 'src', 'App.tsx'), 'utf8');
const auditTable = readFileSync(join(cwd, 'src', 'dashboard', 'AuditTable.tsx'), 'utf8');

describe('dropdown primitive exposes the menu-button contract', () => {
  it('wires trigger and popup with ARIA and ids', () => {
    assert.ok(dropdown.includes('aria-haspopup="menu"'), 'aria-haspopup missing');
    assert.ok(dropdown.includes('aria-expanded={open}'), 'aria-expanded missing');
    assert.ok(dropdown.includes('aria-controls={open ? menuId : undefined}'), 'aria-controls missing');
    assert.ok(dropdown.includes('role="menu"'), 'menu role missing');
    assert.ok(dropdown.includes('role="menuitem"'), 'menuitem role missing');
    assert.ok(dropdown.includes('role="menuitemradio"'), 'menuitemradio role missing');
    assert.ok(dropdown.includes('aria-checked={selected}'), 'option checked state missing');
  });

  it('handles keyboard and dismissal', () => {
    assert.ok(dropdown.includes("e.key === 'Escape'"), 'Escape handling missing');
    assert.ok(dropdown.includes("e.key === 'ArrowDown'"), 'arrow navigation missing');
    assert.ok(dropdown.includes("e.key === 'Home'"), 'Home/End navigation missing');
    assert.ok(dropdown.includes("e.key === 'Tab'"), 'Tab dismissal missing');
    assert.ok(dropdown.includes("addEventListener('pointerdown'"), 'click-outside dismissal missing');
  });

  it('returns focus to the trigger on close', () => {
    assert.ok(dropdown.includes('triggerRef.current?.focus()'), 'focus restore missing');
  });

  it('styles the popup and honors reduced motion', () => {
    assert.ok(dropdownCss.includes('.fc-dropdown-menu'), 'popup styles missing');
    assert.ok(dropdownCss.includes('.fc-dropdown-item'), 'item styles missing');
    assert.ok(dropdownCss.includes('prefers-reduced-motion'), 'reduced-motion guard missing');
  });
});

describe('the console uses the shared dropdown, not ad-hoc popups', () => {
  it('mounts the account menu in the workspace rail', () => {
    assert.ok(app.includes('label="Account"'), 'account menu missing');
    assert.ok(app.includes('<DropdownItem icon={<LogOut'), 'sign-out menu item missing');
    assert.ok(app.includes("onSelect={() => navigate('/console/settings')}"), 'settings menu item missing');
    assert.ok(!app.includes('dyn-logout'), 'the bare logout button must be replaced by the menu');
  });

  it('drives the findings severity filter through the dropdown', () => {
    assert.ok(app.includes('triggerLabel="Filter by severity"'), 'severity trigger label missing');
    assert.ok(
      !app.includes('aria-label="Filter by severity"'),
      'the bare severity <select> must be replaced by the dropdown',
    );
    assert.ok(app.includes('SEVERITY_FILTERS.map'), 'severity options must come from one definition');
  });

  it('offers audit sorting through the dropdown', () => {
    assert.ok(auditTable.includes('label="Sort audits"'), 'audit sort control missing');
    assert.ok(auditTable.includes('AUDIT_SORTS'), 'sort options must come from console state');
  });
});
