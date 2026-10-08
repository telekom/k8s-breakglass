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
        <scale-icon-action-circle-close size="64" decorative></scale-icon-action-circle-close>
      </div>

      <h1 class="error-title">Invalid Session Link</h1>

      <scale-notification variant="danger" :heading="errorMessage" opened data-testid="session-error-details">
        <div slot="text" class="error-content">
          <p>
            Session approval links should look like:<br />
            <code>/session/[session-name]/approve</code>
          </p>
          <p class="mt-3">
            If you received this link via email, please ensure you clicked the full link or contact your administrator
            for assistance.
          </p>
        </div>
      </scale-notification>

      <div class="action-buttons ui-actions ui-actions--center">
        <scale-button variant="primary" @click="handleGoHome">
          <scale-icon-home-home size="20" decorative></scale-icon-home-home>
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
  padding: var(--space-2xl);
}

.error-container {
  max-width: 600px;
  width: 100%;
  text-align: center;
}

/* The icon and title are centred; the notification keeps Scale's start alignment. */
.error-container scale-notification {
  display: block;
  text-align: start;
}

.error-icon {
  color: var(--telekom-color-text-and-icon-functional-danger);
  margin-bottom: var(--space-xl);
}

.error-title {
  font: var(--telekom-text-style-heading-3);
  font-weight: 600;
  margin-bottom: var(--space-xl);
  color: var(--telekom-color-text-and-icon-standard);
}

.error-content {
  text-align: left;
}

.error-content code {
  background-color: var(--surface-card-subtle);
  padding: var(--space-xs) var(--space-sm);
  border-radius: var(--radius-sm);
  font: var(--telekom-text-style-caption);
  font-family: var(--telekom-typography-font-family-mono, monospace);
}

.action-buttons {
  margin-top: var(--space-2xl);
}

.mt-3 {
  margin-top: var(--space-lg);
}
</style>
