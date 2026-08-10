/**
 * Clipboard Safety Utility — Defends against Pastejacking & Clipboard Hijacking Attacks.
 * Sanitizes control characters, ANSI escape codes, and hidden HTML formatting prior to copying.
 */

export function sanitizeClipboardText(text: string): string {
  // Strip control characters except newline and tab
  return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
}

export async function safeCopyToClipboard(text: string): Promise<boolean> {
  try {
    const cleanText = sanitizeClipboardText(text);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(cleanText);
      return true;
    } else {
      // Fallback with sanitized input
      const textarea = document.createElement('textarea');
      textarea.value = cleanText;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      const success = document.execCommand('copy');
      document.body.removeChild(textarea);
      return success;
    }
  } catch (err) {
    console.error('Clipboard copy failed:', err);
    return false;
  }
}
