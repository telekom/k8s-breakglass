// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { nextTick, onBeforeUnmount, watch, type Ref } from "vue";

type ModalBehaviorOptions = {
  lockScroll?: boolean;
};

const MODAL_FOCUS_ATTEMPTS = 60;
const FOCUS_RESTORE_WINDOW_MS = 5000;
const FOCUS_RESTORE_POLL_MS = 100;

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

function isTopModal(token: symbol) {
  return modalStack[modalStack.length - 1]?.token === token;
}

function openScaleModals(): ScaleModalElement[] {
  return Array.from(document.querySelectorAll<ScaleModalElement>("scale-modal")).filter((m) => m.opened);
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
 *
 * The dialog belonging to this activation is the one that opens after it, so
 * dialogs that were already open (e.g. the one underneath) are ignored
 * regardless of their DOM order.
 */
async function focusOpenModal(isStillOpen: () => boolean, alreadyOpen: Set<Element>) {
  await nextTick();
  // The dialog may be inserted a few frames later (async components, lazy Scale
  // loading) and is not focusable until its open transition makes it visible.
  for (let attempt = 0; attempt < MODAL_FOCUS_ATTEMPTS && isStillOpen(); attempt++) {
    const modals = openScaleModals().filter((m) => !alreadyOpen.has(m));
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

/** Focuses the page heading (or main region) like route changes do. */
function focusMainHeading() {
  const target =
    document.querySelector<HTMLElement>("#main h1, #main h2") ?? document.getElementById("main") ?? undefined;
  if (!target) return;
  if (!target.hasAttribute("tabindex")) {
    target.setAttribute("tabindex", "-1");
    target.addEventListener("blur", () => target.removeAttribute("tabindex"), { once: true });
  }
  target.focus({ preventScroll: true });
}

/**
 * Returns focus to the control that opened the dialog (WCAG 2.4.3). A
 * successful action often refreshes the view and replaces that control, which
 * drops focus to <body>; in that case keyboard users are anchored on the page
 * heading instead. Watching stops once focus moves anywhere else.
 */
function restoreFocus(trigger: HTMLElement | null) {
  if (trigger?.isConnected) trigger.focus();
  const startedAt = Date.now();
  const timer = setInterval(() => {
    const active = deepActiveElement();
    if (!active && !trigger?.isConnected) {
      clearInterval(timer);
      focusMainHeading();
    } else if ((active && active !== trigger) || Date.now() - startedAt > FOCUS_RESTORE_WINDOW_MS) {
      clearInterval(timer);
    }
  }, FOCUS_RESTORE_POLL_MS);
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
        // Only the top-most dialog may take focus (it also receives Escape).
        void focusOpenModal(() => isActive && isTopModal(modalToken), new Set(openScaleModals()));
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
      const target = returnFocusTo;
      returnFocusTo = null;
      restoreFocus(target);
    }
  }

  watch(opened, setActive, { immediate: true, flush: "sync" });

  onBeforeUnmount(() => {
    setActive(false);
  });
}
