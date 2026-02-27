<script setup lang="ts">
import { computed, ref } from "vue";
import { LoadingState } from "@/components/common";
import { useRadioGridNavigation } from "@/composables/useRadioGridNavigation";
import type { AvailableClusterDetail } from "@/model/debugSession";

defineOptions({ name: "ClusterSelectGrid" });

const { focusNextRadio, focusPrevRadio } = useRadioGridNavigation();

const props = defineProps<{
  clusters: AvailableClusterDetail[];
  selectedCluster: string;
  loading: boolean;
}>();

const emit = defineEmits<{
  "update:selectedCluster": [value: string];
}>();

const clusterFilter = ref("");

const filteredClusters = computed(() => {
  const q = clusterFilter.value.trim().toLowerCase();
  if (!q) return props.clusters;
  return props.clusters.filter((c) => {
    const name = (c.displayName || c.name || "").toLowerCase();
    const env = (c.environment || "").toLowerCase();
    const loc = (c.location || "").toLowerCase();
    return name.includes(q) || env.includes(q) || loc.includes(q);
  });
});

// Whether the currently selected cluster is visible after filtering.
// When it's filtered out, the first visible card should receive tabindex=0
// so the grid remains keyboard-navigable (WCAG 2.4.7).
const selectedClusterVisible = computed(() => filteredClusters.value.some((c) => c.name === props.selectedCluster));
</script>

<template>
  <div class="form-section">
    <h3>Target Cluster</h3>
    <p class="section-description">
      Select the cluster where you need debug access. Each cluster may have different constraints.
    </p>

    <LoadingState v-if="loading" message="Loading cluster details..." />

    <div v-else-if="clusters.length === 0" class="warning-text">No clusters are available for this template.</div>

    <template v-else>
      <!-- Cluster search filter -->
      <div v-if="clusters.length > 5" class="cluster-filter" data-testid="cluster-filter">
        <scale-text-field
          :value="clusterFilter"
          label="Filter clusters"
          placeholder="Search by name, environment, or location..."
          size="small"
          data-testid="cluster-filter-input"
          @scale-change="clusterFilter = ($event.detail?.value ?? ($event.target as HTMLInputElement)?.value) || ''"
        ></scale-text-field>
        <span class="cluster-count"> Showing {{ filteredClusters.length }} of {{ clusters.length }} clusters </span>
      </div>

      <div v-if="filteredClusters.length === 0" class="warning-text">No clusters match "{{ clusterFilter }}".</div>

      <div
        v-else
        class="cluster-grid"
        role="radiogroup"
        aria-label="Select target cluster"
        data-testid="cluster-grid"
        @keydown.arrow-right.prevent="focusNextRadio($event)"
        @keydown.arrow-down.prevent="focusNextRadio($event)"
        @keydown.arrow-left.prevent="focusPrevRadio($event)"
        @keydown.arrow-up.prevent="focusPrevRadio($event)"
      >
        <div
          v-for="(cluster, idx) in filteredClusters"
          :key="cluster.name"
          :class="['cluster-card', { selected: selectedCluster === cluster.name }]"
          role="radio"
          :aria-checked="selectedCluster === cluster.name"
          :aria-label="`Select cluster ${cluster.displayName || cluster.name}`"
          :tabindex="
            selectedCluster === cluster.name || ((!selectedCluster || !selectedClusterVisible) && idx === 0) ? 0 : -1
          "
          data-testid="cluster-card"
          @click="emit('update:selectedCluster', cluster.name)"
          @keydown.enter.prevent="emit('update:selectedCluster', cluster.name)"
          @keydown.space.prevent="emit('update:selectedCluster', cluster.name)"
        >
          <div class="cluster-header">
            <span class="cluster-name">{{ cluster.displayName || cluster.name }}</span>
            <span v-if="cluster.status?.healthy !== false" class="health-badge healthy" role="img" aria-label="Healthy"
              >●</span
            >
            <span v-else class="health-badge unhealthy" role="img" aria-label="Unhealthy">●</span>
          </div>

          <div class="cluster-meta">
            <span v-if="cluster.environment" class="meta-item">{{ cluster.environment }}</span>
            <span v-if="cluster.location" class="meta-item">{{ cluster.location }}</span>
          </div>

          <!-- Access Source Indicator -->
          <div class="cluster-access-source">
            <span
              v-if="cluster.bindingRef"
              class="source-badge binding"
              :title="`Via binding: ${cluster.bindingRef.namespace}/${cluster.bindingRef.name}`"
            >
              <scale-icon-content-link size="12"></scale-icon-content-link>
              via Binding:
              <strong class="binding-name">{{ cluster.bindingRef.displayName || cluster.bindingRef.name }}</strong>
            </span>
            <span v-else class="source-badge direct" title="Direct access from template allowed.clusters">
              <scale-icon-action-success size="12"></scale-icon-action-success>
              Direct
            </span>
          </div>

          <div class="cluster-constraints">
            <span v-if="cluster.constraints?.maxDuration" class="constraint">
              Max: {{ cluster.constraints.maxDuration }}
            </span>
            <span v-if="cluster.approval?.required && cluster.approval?.canAutoApprove" class="constraint auto-approve">
              Auto-Approve
            </span>
            <span v-else-if="cluster.approval?.required" class="constraint approval-required"> Approval Required </span>
            <span v-else class="constraint auto-approve"> No approval needed </span>
          </div>

          <!-- Multiple Access Options Indicator -->
          <div v-if="cluster.bindingOptions && cluster.bindingOptions.length > 1" class="multiple-bindings-indicator">
            <scale-icon-navigation-double-right size="12"></scale-icon-navigation-double-right>
            <strong>{{ cluster.bindingOptions.length }} access configurations</strong>
            <span class="bindings-preview">
              {{ cluster.bindingOptions.map((b) => b.displayName || b.bindingRef.name).join(", ") }}
            </span>
          </div>

          <!-- Additional Info -->
          <div class="cluster-extra-info">
            <span v-if="cluster.impersonation?.enabled" class="extra-item" title="Uses ServiceAccount impersonation">
              <scale-icon-action-random size="12"></scale-icon-action-random> SA Impersonation
            </span>
            <span
              v-if="cluster.schedulingOptions?.options && cluster.schedulingOptions.options.length > 1"
              class="extra-item"
              title="Multiple node options"
            >
              <scale-icon-device-server size="12"></scale-icon-device-server>
              {{ cluster.schedulingOptions?.options?.length }} node options
            </span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.form-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-md);
  padding: var(--space-lg);
  background: var(--telekom-color-background-surface);
  border: 1px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
}

.form-section h3 {
  margin: 0;
  font-size: 1.125rem;
  font-weight: 600;
}

.section-description {
  margin: 0;
  color: var(--telekom-color-text-and-icon-additional);
  font-size: 0.875rem;
}

.warning-text {
  color: var(--telekom-color-functional-warning-standard);
  font-size: 0.875rem;
  margin: 0;
}

.cluster-filter {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-sm);
  margin-bottom: var(--space-md);
}

.cluster-filter .cluster-count {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  white-space: nowrap;
}

.cluster-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: var(--space-md);
}

.cluster-card {
  padding: var(--space-md);
  background: var(--telekom-color-background-surface);
  border: 2px solid var(--telekom-color-ui-border-standard);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition:
    border-color 0.15s,
    box-shadow 0.15s;
}

.cluster-card:hover {
  border-color: var(--telekom-color-primary-standard);
}

.cluster-card:focus-visible {
  outline: 2px solid var(--telekom-color-primary-standard);
  outline-offset: 2px;
}

.cluster-card.selected {
  border-color: var(--telekom-color-primary-standard);
  box-shadow: 0 0 0 3px rgba(226, 0, 116, 0.15);
}

.cluster-header {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.cluster-name {
  font-weight: 600;
  flex: 1;
}

.health-badge {
  font-size: 0.75rem;
}

.health-badge.healthy {
  color: var(--telekom-color-functional-success-standard);
}

.health-badge.unhealthy {
  color: var(--telekom-color-functional-danger-standard);
}

.cluster-meta {
  display: flex;
  gap: var(--space-sm);
  margin-bottom: var(--space-sm);
}

.meta-item {
  font-size: 0.75rem;
  color: var(--telekom-color-text-and-icon-additional);
  padding: 0.125rem 0.375rem;
  background: var(--telekom-color-background-surface-subtle);
  border-radius: var(--radius-xs);
}

.cluster-access-source {
  margin-bottom: var(--space-sm);
}

.source-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.6875rem;
  padding: 0.125rem 0.5rem;
  border-radius: var(--radius-xs);
}

.source-badge.direct {
  background: var(--telekom-color-functional-success-subtle);
  color: var(--telekom-color-functional-success-standard);
  border: 1px solid var(--telekom-color-functional-success-standard);
}

.source-badge.binding {
  background: var(--telekom-color-background-surface-highlight);
  color: var(--telekom-color-primary-standard);
  border: 1px solid var(--telekom-color-primary-standard);
}

.source-badge .binding-name {
  font-weight: 600;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cluster-constraints {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-bottom: var(--space-sm);
}

.constraint {
  font-size: 0.6875rem;
  padding: 0.125rem 0.375rem;
  background: var(--telekom-color-ui-subtle);
  border-radius: var(--radius-xs);
  color: var(--telekom-color-text-and-icon-standard);
}

.constraint.approval-required {
  background: var(--telekom-color-additional-orange-500);
  color: var(--telekom-color-text-and-icon-black-standard);
  font-weight: 500;
}

.constraint.auto-approve {
  background: var(--telekom-color-functional-success-standard);
  color: var(--telekom-color-text-and-icon-black-standard);
}

.multiple-bindings-indicator {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-xs);
  padding: var(--space-sm);
  margin-top: var(--space-sm);
  background: var(--telekom-color-background-surface-highlight);
  border-radius: var(--radius-sm);
  border-left: 3px solid var(--telekom-color-primary-standard);
}

.multiple-bindings-indicator strong {
  color: var(--telekom-color-text-and-icon-standard);
  font-size: 0.75rem;
}

.multiple-bindings-indicator .bindings-preview {
  width: 100%;
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-standard);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  opacity: 0.85;
}

.cluster-extra-info {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-xs);
  margin-top: var(--space-sm);
}

.cluster-extra-info .extra-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--telekom-color-text-and-icon-additional);
}
</style>
