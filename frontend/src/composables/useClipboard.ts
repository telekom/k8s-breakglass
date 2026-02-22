// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { ref } from "vue";

/**
 * Composable for copying text to the clipboard.
 *
 * Uses the Clipboard API when available, with a textarea-based
 * fallback for older browsers / insecure contexts.
 *
 * @param resetDelay - ms after which `copied` resets to false (default 2000)
 */
export function useClipboard(resetDelay = 2000) {
  const copied = ref(false);
  const error = ref<string | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy(text: string): Promise<boolean> {
    error.value = null;
    try {
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          // writeText can reject in insecure contexts or due to permission denial;
          // fall back to textarea-based copy.
          fallbackCopy(text);
        }
      } else {
        fallbackCopy(text);
      }
      copied.value = true;
      clearTimeout(timer);
      timer = setTimeout(() => {
        copied.value = false;
      }, resetDelay);
      return true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      copied.value = false;
      return false;
    }
  }

  /** Textarea-based fallback for environments without Clipboard API */
  function fallbackCopy(text: string): void {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    try {
      textarea.select();
      // document.execCommand is deprecated but needed as fallback for older browsers
      const success = document.execCommand("copy");
      if (!success) {
        throw new Error("execCommand copy failed");
      }
    } finally {
      document.body.removeChild(textarea);
    }
  }

  /** Cancel any pending reset timer. Call this on component unmount if needed. */
  function cleanup() {
    clearTimeout(timer);
  }

  return { copied, error, copy, cleanup };
}
