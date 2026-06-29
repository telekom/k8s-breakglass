// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { onBeforeUnmount, watch, type Ref } from "vue";

type ModalBehaviorOptions = {
  lockScroll?: boolean;
};

const scrollLockTokens = new Set<symbol>();
const modalStack: Array<{ token: symbol; close: () => void }> = [];
let previousBodyOverflow = "";
let previousDocumentOverflow = "";

function handleDocumentKeydown(event: KeyboardEvent) {
  if (event.key !== "Escape" || modalStack.length === 0) return;

  const activeModal = modalStack[modalStack.length - 1];
  if (!activeModal) return;

  event.preventDefault();
  event.stopImmediatePropagation();
  activeModal.close();
}

function activateModal(token: symbol, onClose: () => void) {
  if (typeof document === "undefined") return;

  deactivateModal(token);
  modalStack.push({ token, close: onClose });
  if (modalStack.length === 1) {
    document.addEventListener("keydown", handleDocumentKeydown, true);
  }
}

function deactivateModal(token: symbol) {
  if (typeof document === "undefined") return;

  const index = modalStack.findIndex((entry) => entry.token === token);
  if (index >= 0) {
    modalStack.splice(index, 1);
  }
  if (modalStack.length === 0) {
    document.removeEventListener("keydown", handleDocumentKeydown, true);
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

export function useModalBehavior(opened: Ref<boolean>, onClose: () => void, options: ModalBehaviorOptions = {}) {
  const lockScroll = options.lockScroll ?? true;
  const scrollLockToken = Symbol("modal-scroll-lock");
  const modalToken = Symbol("modal");

  function setActive(active: boolean) {
    if (typeof document === "undefined") return;

    if (active) {
      activateModal(modalToken, onClose);
      if (lockScroll) lockDocumentScroll(scrollLockToken);
      return;
    }

    deactivateModal(modalToken);
    if (lockScroll) unlockDocumentScroll(scrollLockToken);
  }

  watch(opened, setActive, { immediate: true, flush: "sync" });

  onBeforeUnmount(() => {
    setActive(false);
  });
}
