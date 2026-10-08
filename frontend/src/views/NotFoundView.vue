<template>
  <section class="not-found">
    <div class="not-found__card">
      <h1>Page not found</h1>
      <p>The page you’re looking for doesn’t exist. You can return to the dashboard to continue working.</p>
      <RouterLink class="not-found__cta" to="/">Return to dashboard</RouterLink>
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

/* A router link styled exactly like Scale's primary button (44px, 8px radius,
   20px inline padding, bold body type), so it matches every other primary
   action; high contrast uses the same --cta-* colours as scale-button. */
.not-found__cta {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.75rem;
  border-radius: var(--telekom-radius-standard);
  padding: 0 1.25rem;
  background: var(--telekom-color-primary-standard);
  color: var(--telekom-color-text-and-icon-inverted-standard);
  font: var(--telekom-text-style-body);
  font-weight: 700;
  text-decoration: none;
}

.not-found__cta:hover {
  background: var(--telekom-color-primary-hovered);
  text-decoration: none;
}

:global(:root[data-high-contrast="true"]) .not-found__cta {
  background: var(--cta-bg);
  color: var(--cta-fg);
  border: 2px solid var(--cta-bg);
}

.not-found__cta:focus-visible {
  outline: 2px solid var(--focus-outline);
  outline-offset: 2px;
}
</style>
