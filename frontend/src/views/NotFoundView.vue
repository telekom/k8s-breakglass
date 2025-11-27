<template>
  <section class="not-found">
    <div class="not-found__card">
      <h1>Page not found</h1>
      <p>The page you’re looking for doesn’t exist. You can return to the dashboard to continue working.</p>
      <router-link class="not-found__cta" to="/">Return to dashboard</router-link>
    </div>
  </section>
</template>

<style scoped>
.not-found {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 120px);
  padding: 2rem;
}

.not-found__card {
  max-width: 32rem;
  width: 100%;
  border-radius: 12px;
  padding: 2rem;
  background: var(--vt-c-white-soft, #ffffff);
  box-shadow: 0 10px 35px rgba(0, 0, 0, 0.12);
  text-align: center;
}

.not-found__card h1 {
  font-size: 1.75rem;
  margin-bottom: 0.75rem;
}

.not-found__card p {
  margin: 0 auto 1.5rem;
  color: #4c566a;
}

.not-found__cta {
  display: inline-block;
  padding: 0.65rem 1.5rem;
  border-radius: 999px;
  background: #e20074;
  color: #fff;
  font-weight: 600;
  text-decoration: none;
}

.not-found__cta:hover {
  background: #b8005c;
}
</style>
