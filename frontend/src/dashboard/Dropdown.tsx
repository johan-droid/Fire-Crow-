import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { Check } from 'lucide-react';
import './dropdown.css';

/**
 * One accessible dropdown primitive for the console: a trigger button and a
 * popup menu. Deliberately small and dependency-free — it backs the account
 * menu, the audit sort control, and the findings severity filter, so those
 * never grow their own hand-rolled popup with its own keyboard bugs.
 *
 * Keyboard contract (APG menu-button pattern):
 *   ArrowDown / ArrowUp  open (or move focus through the items, wrapping)
 *   Home / End           first / last item
 *   Escape               close and return focus to the trigger
 *   Tab                  close and let focus move on naturally
 *   Enter / Space        activate the focused item
 *
 * The popup is rendered in a portal with fixed positioning and flips upward
 * when there is no room below. That is not decoration: both real containers —
 * the scrollable workspace rail and the scrollable inspector dialog — would
 * otherwise clip a menu that opened near their bottom edge.
 */
export interface DropdownProps {
  /** Trigger button content. */
  trigger: ReactNode;
  /** Accessible name for the popup menu. */
  label: string;
  align?: 'start' | 'end';
  /** Extra class on the trigger button (e.g. `fc-select`). */
  triggerClassName?: string;
  /** Accessible name for the trigger button when its content is not text. */
  triggerLabel?: string;
  className?: string;
  children: ReactNode;
}

const ITEM_SELECTOR = '[role="menuitem"],[role="menuitemradio"]';
const MENU_MIN_WIDTH = 180;
const VIEWPORT_GAP = 8;
const CloseContext = createContext<(() => void) | null>(null);

export function Dropdown({
  trigger,
  label,
  align = 'start',
  triggerClassName = '',
  triggerLabel,
  className = '',
  children,
}: DropdownProps) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState<CSSProperties | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const menuId = useId();

  const items = useCallback(
    (): HTMLElement[] =>
      menuRef.current ? Array.from(menuRef.current.querySelectorAll<HTMLElement>(ITEM_SELECTOR)) : [],
    [],
  );

  const close = useCallback((restoreFocus = true) => {
    setOpen(false);
    if (restoreFocus) triggerRef.current?.focus();
  }, []);

  const openMenu = useCallback(
    (focusLast = false) => {
      setOpen(true);
      // Items mount on the next frame; focus the checked one when there is one.
      requestAnimationFrame(() => {
        const list = items();
        if (list.length === 0) return;
        const checked = list.findIndex((el) => el.getAttribute('aria-checked') === 'true');
        const idx = focusLast ? list.length - 1 : checked >= 0 ? checked : 0;
        list[idx]?.focus();
      });
    },
    [items],
  );

  // Position after the menu mounts (before paint), and keep it anchored while
  // any ancestor scrolls or the window resizes.
  useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return;
    }
    const place = () => {
      const t = triggerRef.current;
      if (!t) return;
      const r = t.getBoundingClientRect();
      const height = menuRef.current?.offsetHeight ?? 220;
      const spaceBelow = window.innerHeight - r.bottom;
      const openUp = spaceBelow < height + 12 && r.top > spaceBelow;
      const style: CSSProperties = {
        position: 'fixed',
        top: openUp ? Math.max(VIEWPORT_GAP, r.top - height - 6) : r.bottom + 6,
        minWidth: Math.max(r.width, MENU_MIN_WIDTH),
      };
      if (align === 'end') {
        style.right = Math.max(VIEWPORT_GAP, window.innerWidth - r.right);
      } else {
        style.left = Math.min(
          Math.max(VIEWPORT_GAP, r.left),
          Math.max(VIEWPORT_GAP, window.innerWidth - MENU_MIN_WIDTH - VIEWPORT_GAP),
        );
      }
      setMenuStyle(style);
    };
    place();
    window.addEventListener('resize', place);
    document.addEventListener('scroll', place, true);
    return () => {
      window.removeEventListener('resize', place);
      document.removeEventListener('scroll', place, true);
    };
  }, [open, align]);

  // Dismiss on a pointer press outside both the trigger and the portaled menu.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (rootRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open]);

  // Closed: the trigger owns ArrowDown/ArrowUp to open the menu.
  const onTriggerKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      openMenu(e.key === 'ArrowUp');
    }
  };

  // Open: the menu owns navigation. Focus lives here, so these events never
  // reach the trigger.
  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      close();
      return;
    }
    if (e.key === 'Tab') {
      setOpen(false);
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const list = items();
      if (list.length === 0) return;
      const current = list.indexOf(document.activeElement as HTMLElement);
      const next =
        e.key === 'ArrowDown'
          ? (current + 1) % list.length
          : (current - 1 + list.length) % list.length;
      list[next]?.focus();
      return;
    }
    if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      const list = items();
      if (list.length > 0) list[e.key === 'Home' ? 0 : list.length - 1]?.focus();
    }
  };

  const menu = open
    ? createPortal(
        <div
          className={`fc-dropdown-menu fc-dropdown-menu-${align}`}
          role="menu"
          aria-label={label}
          id={menuId}
          ref={menuRef}
          style={{ ...(menuStyle ?? {}), visibility: menuStyle ? 'visible' : 'hidden' }}
          onKeyDown={onMenuKeyDown}
        >
          {children}
        </div>,
        document.body,
      )
    : null;

  return (
    <CloseContext.Provider value={close}>
      <div className={`fc-dropdown ${className}`} ref={rootRef}>
        <button
          type="button"
          ref={triggerRef}
          className={`fc-dropdown-trigger ${triggerClassName}`}
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          aria-label={triggerLabel}
          onClick={() => (open ? close(false) : openMenu())}
          onKeyDown={onTriggerKeyDown}
        >
          {trigger}
        </button>
        {menu}
      </div>
    </CloseContext.Provider>
  );
}

export interface DropdownItemProps {
  onSelect?: () => void;
  icon?: ReactNode;
  disabled?: boolean;
  /** Renders a non-interactive heading row (e.g. the account identity). */
  asHeader?: boolean;
  children: ReactNode;
}

/** A plain action row (menu item). */
export function DropdownItem({ onSelect, icon, disabled, asHeader, children }: DropdownItemProps) {
  const close = useContext(CloseContext);
  if (asHeader) {
    return <div className="fc-dropdown-header">{children}</div>;
  }
  return (
    <button
      type="button"
      role="menuitem"
      className="fc-dropdown-item"
      disabled={disabled}
      onClick={() => {
        onSelect?.();
        close?.();
      }}
    >
      {icon && (
        <span className="fc-dropdown-icon" aria-hidden="true">
          {icon}
        </span>
      )}
      <span className="fc-dropdown-label">{children}</span>
    </button>
  );
}

export interface DropdownOptionProps {
  /** Whether this option is the current value. */
  selected: boolean;
  onSelect: () => void;
  disabled?: boolean;
  children: ReactNode;
}

/** A single-choice option row (menuitemradio) — the "select box" case. */
export function DropdownOption({ selected, onSelect, disabled, children }: DropdownOptionProps) {
  const close = useContext(CloseContext);
  return (
    <button
      type="button"
      role="menuitemradio"
      aria-checked={selected}
      className={`fc-dropdown-item${selected ? ' is-selected' : ''}`}
      disabled={disabled}
      onClick={() => {
        onSelect();
        close?.();
      }}
    >
      <span className="fc-dropdown-label">{children}</span>
      {selected && <Check size={14} className="fc-dropdown-check" aria-hidden="true" />}
    </button>
  );
}
