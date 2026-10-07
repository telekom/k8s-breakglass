// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { nextTick, onBeforeUnmount, watch, type Ref } from "vue";
import { PAGE_HEADING_SELECTOR } from "@/utils/pageHeading";

type ModalBehaviorOptions = {
  lockScroll?: boolean;
};

const MODAL_FOCUS_ATTEMPTS = 60;

type ScaleModalElement = HTMLElement & { opened?: boolean; componentOnReady?: () => Promise<unknown> };

const scrollLockTokens = new Set<symbol>();
const modalStack: Array<{ token: symbol; close: () => void; element?: ScaleModalElement }> = [];
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

  const element = modalElementFor(token);
  deactivateModal(token);
  modalStack.push({ token, close: onClose, element });
  if (modalStack.length === 1) {
    document.addEventListener("keydown", handleDocumentKeydown);
  }
}

function isTopModal(token: symbol) {
  return modalStack[modalStack.length - 1]?.token === token;
}

function setModalElement(token: symbol, element: ScaleModalElement) {
  const entry = modalStack.find((candidate) => candidate.token === token);
  if (entry) entry.element = element;
}

function modalElementFor(token: symbol): ScaleModalElement | undefined {
  return modalStack.find((candidate) => candidate.token === token)?.element;
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
function focusModal(modal: ScaleModalElement): boolean {
  if (document.activeElement && modal.contains(document.activeElement)) return true;
  // `close-button` is the part name Scale documents for styling the dialog's close button.
  const closeButton = modal.shadowRoot?.querySelector<HTMLElement>('[part~="close-button"]');
  closeButton?.focus();
  return !!closeButton && modal.shadowRoot?.activeElement === closeButton;
}

async function focusOpenModal(token: symbol, isStillOpen: () => boolean, alreadyOpen: Set<Element>) {
  await nextTick();
  // The dialog may be inserted a few frames later (async components, lazy Scale
  // loading) and is not focusable until its open transition makes it visible.
  for (let attempt = 0; attempt < MODAL_FOCUS_ATTEMPTS && isStillOpen(); attempt++) {
    const modals = openScaleModals().filter((m) => !alreadyOpen.has(m));
    const modal = modals[modals.length - 1];
    if (modal) {
      await modal.componentOnReady?.();
      if (!modal.isConnected || !modal.opened || !isStillOpen()) return;
      setModalElement(token, modal);
      if (focusModal(modal)) return;
    }
    await new Promise((resolve) => requestAnimationFrame(resolve));
  }
}

/** Focuses the page heading (or main region) like route changes do. */
function focusMainHeading() {
  const target =
    document.querySelector<HTMLElement>(PAGE_HEADING_SELECTOR) ?? document.getElementById("main") ?? undefined;
  if (!target) return;
  if (!target.hasAttribute("tabindex")) {
    target.setAttribute("tabindex", "-1");
    target.addEventListener("blur", () => target.removeAttribute("tabindex"), { once: true });
  }
  // Let the browser scroll it into view: a removed trigger may have been far down a list.
  target.focus();
}

/**
 * Focus can be moved without overriding a user choice when nothing is focused
 * or focus is still inside the closing dialog (or another dialog that is no
 * longer open).
 */
function focusIsReleasable(closing: ScaleModalElement | undefined): boolean {
  if (!deepActiveElement()) return true;
  const host = document.activeElement?.closest<ScaleModalElement>("scale-modal");
  return !!host && (host === closing || !host.opened);
}

/** Moves focus to the dialog still open underneath, or to the page heading. */
function focusFallback() {
  const remaining = modalStack[modalStack.length - 1]?.element;
  if (remaining?.isConnected && remaining.opened && focusModal(remaining)) return;
  focusMainHeading();
}

/**
 * Returns focus to the control that opened the dialog (WCAG 2.4.3). If that
 * control is gone (e.g. the list item was removed before the dialog closed)
 * focus moves to the remaining dialog or the page heading. A successful action
 * may also refresh the view later and replace the control; that drops focus to
 * <body>, so the same fallback applies then. Watching ends as soon as focus
 * moves anywhere else, so it never overrides a later user choice.
 */
function restoreFocus(trigger: HTMLElement | null, closing: ScaleModalElement | undefined) {
  if (trigger?.isConnected) trigger.focus();
  if (!trigger?.isConnected || deepActiveElement() !== trigger) {
    if (focusIsReleasable(closing)) focusFallback();
    return;
  }

  const stop = () => {
    observer.disconnect();
    document.removeEventListener("focusin", onFocusIn, true);
  };
  const onFocusIn = (event: FocusEvent) => {
    if (event.composedPath()[0] !== trigger) stop();
  };
  const observer = new MutationObserver(() => {
    if (trigger.isConnected) return;
    stop();
    if (!deepActiveElement()) focusFallback();
  });
  observer.observe(document.body, { childList: true, subtree: true });
  document.addEventListener("focusin", onFocusIn, true);
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
        void focusOpenModal(modalToken, () => isActive && isTopModal(modalToken), new Set(openScaleModals()));
      }
      isActive = true;
      activateModal(modalToken, onClose);
      if (lockScroll) lockDocumentScroll(scrollLockToken);
      return;
    }

    // Closing a dialog underneath another must not pull focus behind the top one.
    const wasTopModal = isTopModal(modalToken);
    const closingElement = modalElementFor(modalToken);
    deactivateModal(modalToken);
    if (lockScroll) unlockDocumentScroll(scrollLockToken);
    if (isActive) {
      isActive = false;
      const target = returnFocusTo;
      returnFocusTo = null;
      if (wasTopModal) restoreFocus(target, closingElement);
    }
  }

  watch(opened, setActive, { immediate: true, flush: "sync" });

  onBeforeUnmount(() => {
    setActive(false);
  });
}
