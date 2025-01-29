<script setup lang="ts">
import { inject, computed, ref, onMounted, reactive } from "vue";
import { AuthKey } from "@/keys";
import { useRoute } from "vue-router";
import { useUser } from "@/services/auth";
import BreakglassSessionService from "@/services/breakglassSession";
import useCurrentTime from "@/util/currentTime";
import BreakglassSessionCard from "@/components/BreakglassSessionCard.vue";

const route = useRoute()
const user = useUser();
const auth = inject(AuthKey);
const authenticated = computed(() => user.value && !user.value?.expired);
const service = new BreakglassSessionService(auth!);
const time = useCurrentTime();

const resourceName = ref(route.query.name?.toString() || "");

const state = reactive({
  breakglasses: new Array(),
  message: "",
  loading: true,
  refreshing: false,
  search: "",
});

onMounted(async () => {
  // const params: BreakglassSessionRequest = { uname: resourceName.value }
  await service.getSessionStatus({ uname: resourceName.value }).then(response => {
    console.log("response:=", response)
    switch (response.status) {
      case 200:
        state.message = ""
        state.breakglasses = response.data
        console.log(state.breakglasses[0])
        break
    }
  }).catch(errResponse => {
    if (errResponse.status == 401) {
      state.message = "You are not authorized to display requested resources"
    }
    console.log("err1:=", errResponse)
  });

  console.log(state.breakglasses);
  state.loading = false;
});

const filteredBreakglasses = computed(() => {
  if (state.search === "") {
    return state.breakglasses;
  }
  return state.breakglasses.filter((bg) => bg.to?.includes(state.search) || bg.from?.includes(state.search));
});

function onRequest(bg: any) {
  console.log("REQUESTING BG", bg)
  // breakglassService.requestBreakglass(bg);
}

async function onDrop(bg: any) {
  console.log("DROPING BG", bg)
  // await breakglassService.dropBreakglass(bg);
  // state.breakglasses = await breakglassService.getBreakglasses();
}
</script>


<template>
  <main>
    <div v-if="authenticated" class="center">
      <div>
        {{ state.message }}
      </div>

      <div class="breakglass-list">
        <BreakglassSessionCard
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
        </BreakglassSessionCard>
      </div>
    </div>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}

scale-data-grid {
  display: block;
  margin: 0 auto;
  max-width: 600px;
}

scale-card {
  display: block;
  margin: 0 auto;
  max-width: 500px;
}
</style>
