// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { nextTick, onBeforeUnmount, watch, type Ref } from "vue";

type ModalBehaviorOptions = {
  lockScroll?: boolean;
};

const MODAL_FOCUS_ATTEMPTS = 60;

type ScaleModalElement = HTMLElement & { opened?: boolean; componentOnReady?: () => Promise<unknown> };

const scrollLockTokens = new Set<symbol>();
const modalStack: Array<{ token: symbol; close: () => void }> = [];
let previousBodyOverflow = "";
let previousDocumentOverflow = "";

function handleDocumentKeydown(event: KeyboardEvent) {
  if (event.key !== "Escape" || modalStack.length === 0) return;
  if (event.defaultPrevented) return;

  const activeModal = modalStack[modalStack.length - 1];
  if (!activeModal) return;

  event.preventDefault();
  event.stopPropagation();
  activeModal.close();
}

function activateModal(token: symbol, onClose: () => void) {
  if (typeof document === "undefined") return;

  deactivateModal(token);
  modalStack.push({ token, close: onClose });
  if (modalStack.length === 1) {
    document.addEventListener("keydown", handleDocumentKeydown);
  }
}

function deactivateModal(token: symbol) {
  if (typeof document === "undefined") return;

  const index = modalStack.findIndex((entry) => entry.token === token);
  if (index >= 0) {
    modalStack.splice(index, 1);
  }
  if (modalStack.length === 0) {
    document.removeEventListener("keydown", handleDocumentKeydown);
  }
}

function lockDocumentScroll(token: symbol) {
  if (typeof document === "undefined") return;

  if (scrollLockTokens.size === 0) {
    previousBodyOverflow = document.body.style.overflow;
    previousDocumentOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
  }
  scrollLockTokens.add(token);
}

function unlockDocumentScroll(token: symbol) {
  if (typeof document === "undefined" || !scrollLockTokens.has(token)) return;

  scrollLockTokens.delete(token);
  if (scrollLockTokens.size === 0) {
    document.body.style.overflow = previousBodyOverflow;
    document.documentElement.style.overflow = previousDocumentOverflow;
  }
}

/** Returns the focused element, descending into open shadow roots (e.g. scale-button > button). */
function deepActiveElement(): HTMLElement | null {
  let el = document.activeElement as HTMLElement | null;
  while (el?.shadowRoot?.activeElement) {
    el = el.shadowRoot.activeElement as HTMLElement;
  }
  return el && el !== document.body ? el : null;
}

/**
 * Scale's modal only moves focus into the dialog when its `opened` prop changes
 * after the first render. Our dialogs are usually mounted with `opened=true`
 * (v-if), so keyboard and screen reader users would stay on the trigger behind
 * the backdrop. Move focus to the dialog's close button unless focus is already
 * inside the dialog.
 */
async function focusOpenModal(isStillOpen: () => boolean) {
  await nextTick();
  // The dialog may be inserted a few frames later (async components, lazy Scale
  // loading) and is not focusable until its open transition makes it visible.
  for (let attempt = 0; attempt < MODAL_FOCUS_ATTEMPTS && isStillOpen(); attempt++) {
    const modals = Array.from(document.querySelectorAll<ScaleModalElement>("scale-modal")).filter((m) => m.opened);
    const modal = modals[modals.length - 1];
    if (modal) {
      await modal.componentOnReady?.();
      if (!modal.isConnected || !modal.opened || !isStillOpen()) return;
      if (document.activeElement && modal.contains(document.activeElement)) return;
      const closeButton = modal.shadowRoot?.querySelector<HTMLElement>(".modal__close-button");
      closeButton?.focus();
      if (closeButton && modal.shadowRoot?.activeElement === closeButton) return;
    }
    await new Promise((resolve) => requestAnimationFrame(resolve));
  }
}

export function useModalBehavior(opened: Ref<boolean>, onClose: () => void, options: ModalBehaviorOptions = {}) {
  const lockScroll = options.lockScroll ?? true;
  const scrollLockToken = Symbol("modal-scroll-lock");
  const modalToken = Symbol("modal");
  let isActive = false;
  let returnFocusTo: HTMLElement | null = null;

  function setActive(active: boolean) {
    if (typeof document === "undefined") return;

    if (active) {
      if (!isActive) {
        returnFocusTo = deepActiveElement();
        void focusOpenModal(() => isActive);
      }
      isActive = true;
      activateModal(modalToken, onClose);
      if (lockScroll) lockDocumentScroll(scrollLockToken);
      return;
    }

    deactivateModal(modalToken);
    if (lockScroll) unlockDocumentScroll(scrollLockToken);
    if (isActive) {
      isActive = false;
      // Return focus to the control that opened the dialog (WCAG 2.4.3).
      const target = returnFocusTo;
      returnFocusTo = null;
      if (target?.isConnected) {
        target.focus();
      }
    }
  }

  watch(opened, setActive, { immediate: true, flush: "sync" });

  onBeforeUnmount(() => {
    setActive(false);
  });
}
