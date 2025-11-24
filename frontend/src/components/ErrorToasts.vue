<script setup lang="ts">
import type { AppError } from "@/services/toast";
import { useErrors, dismissError } from "@/services/toast";

const { errors } = useErrors();

const BASE_VERTICAL_OFFSET = 16;
const STACK_SPACING = 108;

function headingFor(error: AppError) {
  if (error.type === "success") {
    return "Success";
  }
  return error.status ? `Error [${error.status}]` : "Error";
}

function variantFor(error: AppError) {
  return error.type === "success" ? "success" : "error";
}

function autoHideDurationFor(error: AppError) {
  if (error.autoHideDuration && error.autoHideDuration > 0) {
    return error.autoHideDuration;
  }
  return error.type === "success" ? 6000 : 10000;
}

function updateToastState(id: string, opened: boolean) {
  const toast = errors.find((err) => err.id === id);
  if (toast) {
    toast.opened = opened;
  }
}

function handleToastClosing(id: string) {
  updateToastState(id, false);
}

function handleToastClosed(id: string) {
  dismissError(id);
}

function verticalOffset(index: number) {
  return BASE_VERTICAL_OFFSET + index * STACK_SPACING;
}
</script>

<template>
  <div class="toast-region" aria-live="polite" aria-atomic="true">
    <scale-notification-toast
      v-for="(e, index) in errors"
      :key="e.id"
      alignment="top-right"
      :opened="e.opened !== false"
      :variant="variantFor(e)"
      :position-vertical="verticalOffset(index)"
      :auto-hide="true"
      :auto-hide-duration="autoHideDurationFor(e)"
      :fade-duration="280"
      @scale-closing="handleToastClosing(e.id)"
      @scale-close="handleToastClosed(e.id)"
    >
      <span slot="header">{{ headingFor(e) }}</span>
      <p slot="body" class="toast-body">
        {{ e.message }}
        <span v-if="e.cid" class="cid">(cid: {{ e.cid }})</span>
      </p>
    </scale-notification-toast>
  </div>
</template>

<style scoped>
.toast-region {
  pointer-events: none;
}

.toast-region :deep(scale-notification-toast) {
  pointer-events: all;
}

.toast-body {
  margin: 0;
  font-size: 0.9rem;
}

.cid {
  display: inline-block;
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-left: 0.35rem;
}
</style>
