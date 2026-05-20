<template>
  <section class="not-found">
    <div class="not-found__card">
      <h1>Page not found</h1>
      <p>The page you’re looking for doesn’t exist. You can return to the dashboard to continue working.</p>
      <scale-button variant="primary" href="/">Return to dashboard</scale-button>
    </div>
  </section>
</template>

<style scoped>
.not-found {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 120px);
  padding: var(--space-xl);
}

.not-found__card {
  max-width: 32rem;
  width: 100%;
  border-radius: var(--radius-lg);
  border: 1px solid var(--telekom-color-ui-border-standard);
  padding: var(--space-xl);
  background: var(--surface-card);
  box-shadow: var(--shadow-card);
  text-align: center;
}

.not-found__card h1 {
  font: var(--telekom-text-style-heading-3);
  margin-bottom: var(--space-sm);
}

.not-found__card p {
  margin: 0 auto var(--space-lg);
  color: var(--telekom-color-text-and-icon-additional);
}

.not-found__card scale-button {
  margin-top: var(--space-sm);
}
</style>
