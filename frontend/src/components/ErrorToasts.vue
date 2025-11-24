<script setup lang="ts">
import { useErrors, dismissError } from "@/services/toast";
const { errors } = useErrors();
</script>

<template>
  <div class="toast-container" aria-live="polite" aria-atomic="true">
    <transition-group name="toast" tag="div">
      <div v-for="e in errors" :key="e.id" class="toast-wrapper">
        <scale-notification
          variant="danger"
          :heading="e.status ? `Error [${e.status}]` : 'Error'"
          class="toast-notification"
        >
          <div class="toast-content">
            <p>{{ e.message }}</p>
            <span v-if="e.cid" class="cid">(cid: {{ e.cid }})</span>
          </div>
          <div class="toast-actions">
            <scale-button variant="ghost" size="small" @click="dismissError(e.id)">Dismiss</scale-button>
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
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.25);
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
  opacity: 0.8;
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
