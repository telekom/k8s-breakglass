<script setup lang="ts">
import BreakglassCard from "@/components/BreakglassCard.vue";
import { inject, onMounted, reactive } from "vue";
import { AuthKey } from "@/keys";
import BreakglassService from "@/services/breakglass";
import type { Breakglass } from "@/model/breakglass";
import useCurrentTime from "@/util/currentTime";
import { computed } from "@vue/reactivity";

const auth = inject(AuthKey);
const breakglassService = new BreakglassService(auth!); // eslint-disable-line @typescript-eslint/no-non-null-assertion
const time = useCurrentTime();

const state = reactive({
  breakglasses: new Array<Breakglass>(),
  loading: true,
  refreshing: false,
  search: "",
});

onMounted(async () => {
  state.breakglasses = await breakglassService.getBreakglasses();
  console.log(state.breakglasses);
  state.loading = false;
});

async function refresh() {
  state.refreshing = true;
  state.breakglasses = await breakglassService.getBreakglasses();
  state.refreshing = false;
}

const filteredBreakglasses = computed(() => {
  if (state.search === "") {
    return state.breakglasses;
  }
  return state.breakglasses.filter((bg) => bg.to?.includes(state.search) || bg.from?.includes(state.search));
});

function onRequest(bg: Breakglass) {
  breakglassService.requestBreakglass(bg);
}

async function onDrop(bg: Breakglass) {
  await breakglassService.dropBreakglass(bg);
  state.breakglasses = await breakglassService.getBreakglasses();
}
</script>

<template>
  <main>
    <div v-if="state.loading" class="loading">
      <scale-loading-spinner size="large" />
    </div>
    <div v-else-if="state.breakglasses.length > 0">
      <div class="search">
        <scale-text-field
          label="Search"
          class="search-field"
          :value="state.search"
          @scaleChange="(ev: any) => state.search = ev.target.value"
        ></scale-text-field>
        <div class="refresh">
          <scale-loading-spinner v-if="state.refreshing"></scale-loading-spinner>
          <scale-button v-else icon-only="true" icon-position="before" variant="secondary" @click="refresh()">
            <scale-icon-action-refresh></scale-icon-action-refresh>
          </scale-button>
        </div>
      </div>
      <div class="breakglass-list">
        <BreakglassCard
          v-for="bg in filteredBreakglasses"
          :key="bg.from + bg.to"
          class="card"
          :breakglass="bg"
          :time="time"
          @request="
            () => {
              onRequest(bg);
            }
          "
          @drop="
            () => {
              onDrop(bg);
            }
          "
        >
        </BreakglassCard>
      </div>
    </div>
    <div v-else class="not-found">No requestable Breakglass groups found.</div>
  </main>
</template>

<style scoped>
main {
  margin: 3rem auto;
  max-width: 1200px;
}

.loading {
  margin: 2rem auto;
  text-align: center;
}

.search {
  max-width: 400px;
  margin: 1rem auto;
  display: flex;
  align-items: center;
}

.search-field {
  flex-grow: 1;
  margin-right: 1rem;
}

.refresh {
  width: 48px;
}

.breakglass-list {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
  justify-content: center;
}

.not-found {
  text-align: center;
}

.card {
  flex-grow: 1;
  flex-shrink: 0;
}
</style>
