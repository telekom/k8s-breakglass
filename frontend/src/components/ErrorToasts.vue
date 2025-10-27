<script setup lang="ts">
import { useErrors, dismissError } from "@/services/toast";
const { errors } = useErrors();
</script>

<template>
  <div class="toast-container" aria-live="polite" aria-atomic="true">
    <transition-group name="toast" tag="div">
  <div v-for="e in errors" :key="e.id" class="toast" :class="[e.type || 'error']">
  <div class="msg">
          <strong v-if="e.status">[{{ e.status }}]</strong>
          {{ e.message }}
          <span v-if="e.cid" class="cid">(cid: {{ e.cid }})</span>
        </div>
  <button class="close" @click="dismissError(e.id)" aria-label="Dismiss">×</button>
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
  gap: .5rem;
  max-width: 340px;
}
.toast-enter-active, .toast-leave-active { transition: all .25s ease; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateY(-6px); }
.toast {
  background: #fbe9e9;
  border-left: 4px solid #d90000;
  &.success {
    background: #e9fbe9;
    border-left: 4px solid #1bb700;
    border: 1px solid #b6f5c6;
    color: #155724;
  }
  padding: .8rem 1rem .8rem 1rem;
  font-size: .9rem;
  line-height: 1.4;
  box-shadow: 0 4px 8px rgba(0,0,0,.25);
  border-radius: 6px;
  display: flex;
  align-items: flex-start;
  color: #333;
  border: 1px solid #f5c6c6;
}
.msg { flex: 1; color: #333; font-weight: 500; }
.cid { display:block; font-size: .75rem; opacity: .8; margin-top: .2rem; }
.close { background: none; border: none; cursor: pointer; font-size: 1rem; line-height: 1; padding: 0 .25rem; }
.close:hover { color: #900; }
</style>
