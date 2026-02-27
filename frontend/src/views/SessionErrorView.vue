<script setup lang="ts">
import { useRoute, useRouter } from "vue-router";
import { computed } from "vue";

const route = useRoute();
const router = useRouter();

const errorMessage = computed(() => {
  const path = route.path;

  if (path === "/session") {
    return "Invalid session URL. Please use a valid session approval link from your email.";
  }

  // Path like /session/:name without /approve
  const sessionMatch = path.match(/^\/session\/([^/]+)$/);
  if (sessionMatch) {
    const sessionName = sessionMatch[1];
    return `Incomplete session URL. This link should end with "/approve". Session: ${sessionName}`;
  }

  return "Invalid session URL. Please check your link and try again.";
});

const handleGoHome = () => {
  router.push("/");
};

const handleViewSessions = () => {
  router.push("/sessions");
};
</script>

<template>
  <div class="session-error-view">
    <div class="error-container">
      <div class="error-icon">
        <scale-icon-action-circle-close size="64"></scale-icon-action-circle-close>
      </div>

      <h1 class="error-title">Invalid Session Link</h1>

      <scale-notification variant="danger" opened>
        <div class="error-content">
          <p>
            <strong>{{ errorMessage }}</strong>
          </p>
          <p class="mt-3">
            Session approval links should look like:<br />
            <code>/session/[session-name]/approve</code>
          </p>
          <p class="mt-3">
            If you received this link via email, please ensure you clicked the full link or contact your administrator
            for assistance.
          </p>
        </div>
      </scale-notification>

      <div class="action-buttons">
        <scale-button variant="primary" @click="handleGoHome">
          <scale-icon-home slot="icon-before"></scale-icon-home>
          Return to Home
        </scale-button>
        <scale-button variant="secondary" @click="handleViewSessions"> View All Sessions </scale-button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.session-error-view {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 200px);
  padding: 2rem;
}

.error-container {
  max-width: 600px;
  width: 100%;
  text-align: center;
}

.error-icon {
  color: var(--scl-color-danger);
  margin-bottom: 1.5rem;
}

.error-title {
  font-size: 1.75rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
  color: var(--scl-color-danger);
}

.error-content {
  text-align: left;
}

.error-content code {
  background-color: rgba(0, 0, 0, 0.1);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-family: "Courier New", monospace;
  font-size: 0.9rem;
}

.action-buttons {
  display: flex;
  gap: 1rem;
  justify-content: center;
  margin-top: 2rem;
}

.mt-3 {
  margin-top: 1rem;
}
</style>
