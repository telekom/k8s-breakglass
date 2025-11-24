<script setup lang="ts">
import type { AppError } from "@/services/toast";
import { useErrors, dismissError } from "@/services/toast";

const { errors } = useErrors();

function headingFor(error: AppError) {
  if (error.type === "success") {
    return "Success";
  }
  return error.status ? `Error [${error.status}]` : "Error";
}

function variantFor(error: AppError) {
  return error.type === "success" ? "success" : "danger";
}
</script>

<template>
  <div class="toast-container" aria-live="polite" aria-atomic="true">
    <transition-group name="toast" tag="div">
      <div v-for="e in errors" :key="e.id" class="toast-wrapper">
        <scale-notification
          :variant="variantFor(e)"
          :heading="headingFor(e)"
          class="toast-notification"
          :data-type="variantFor(e)"
        >
          <div class="toast-content">
            <p>{{ e.message }}</p>
            <span v-if="e.cid" class="cid">(cid: {{ e.cid }})</span>
          </div>
          <div class="toast-actions">
            <scale-button variant="secondary" size="small" @click="dismissError(e.id)">Dismiss</scale-button>
          </div>
        </scale-notification>
      </div>
    </transition-group>
  </div>
</template>

<style scoped>
.toast-container {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 10000;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  max-width: 400px;
  width: 100%;
}

.toast-wrapper {
  width: 100%;
}

.toast-notification {
  width: 100%;
  box-shadow: 0 8px 20px color-mix(in srgb, var(--telekom-color-black) 35%, transparent);
  border-radius: 14px;
  border-left: 4px solid var(--accent-critical);
}

.toast-notification[data-type="success"] {
  border-left-color: var(--accent-success);
}

.toast-notification[data-type="danger"] {
  border-left-color: var(--accent-critical);
}

.toast-content {
  margin-bottom: 0.5rem;
}

.toast-content p {
  margin: 0;
}

.cid {
  display: block;
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-top: 0.2rem;
}

.toast-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 0.5rem;
}

.toast-enter-active,
.toast-leave-active {
  transition: all 0.25s ease;
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(-6px);
}
</style>
