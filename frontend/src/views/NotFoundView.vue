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

.not-found__cta {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.75rem;
  margin-top: var(--space-sm);
  border: 2px solid transparent;
  border-radius: var(--radius-pill);
  padding: 0 var(--space-lg);
  background: var(--cta-bg, var(--accent-primary-aaa));
  color: var(--telekom-color-text-and-icon-white, var(--accent-on-primary-aaa));
  font: var(--telekom-text-style-body);
  font-weight: 700;
  text-decoration: none;
}

.not-found__cta:hover {
  background: var(--cta-bg-hover, var(--accent-primary-aaa-hover));
  text-decoration: none;
}

:global(:root[data-high-contrast="true"]) .not-found__cta {
  border-color: var(--cta-bg, currentColor);
}

.not-found__cta:focus-visible {
  outline: 2px solid var(--focus-outline);
  outline-offset: 2px;
}
</style>
