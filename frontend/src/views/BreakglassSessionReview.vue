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
const clusterName = ref(route.query.cluster?.toString() || "");
const userName = ref(route.query.username?.toString() || "");
const groupName = ref(route.query.group?.toString() || "");

const state = reactive({
  breakglasses: new Array(),
  getBreakglassesMsg: "",
  loading: true,
  refreshing: false,
  search: "",
});

async function getActiveBreakglasses() {
  state.loading = true;
  await service.getSessionStatus({
    uname: resourceName.value,
    clustername: clusterName.value,
    username: userName.value,
    clustergroup: groupName.value
  }).then(response => {
    switch (response.status) {
      case 200:
        state.getBreakglassesMsg = ""
        state.breakglasses = response.data.filter(
          (breakglass: any) => true);
        break
    }
  }).catch(errResponse => {
    if (errResponse.status == 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources"
    }
    console.log("status list error", errResponse)
  });
  state.loading = false;
}
onMounted(async () => {
  getActiveBreakglasses()
  console.log(state.breakglasses);
});

const filteredBreakglasses = computed(() => {
  if (state.search === "") {
    return state.breakglasses;
  }
  // return state.breakglasses.filter((bg) => true);
});

function onAccept(bg: any) {
  service.approveReview({ uname: bg.metadata.name }).then(response => {
    switch (response.status) {
      case 200:
        getActiveBreakglasses()
        break
    }
  }).catch(errResponse => {
    if (errResponse.status == 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources"
    }
    console.log("approve error", errResponse)
  });
}

async function onReject(bg: any) {
  service.rejectReview({ uname: bg.metadata.name }).then(response => {
    switch (response.status) {
      case 200:
        getActiveBreakglasses()
        break
    }
  }).catch(errResponse => {
    if (errResponse.status == 401) {
      state.getBreakglassesMsg = "You are not authorized to display requested resources"
    }
    console.log("reject error", errResponse)
  });
}
</script>


<template>
  <main>
    <div v-if="authenticated" class="center">
      <div>
        {{ state.getBreakglassesMsg }}
      </div>

      <div class="breakglass-list">
        <BreakglassSessionCard v-for="bg in filteredBreakglasses" class="card" :breakglass="bg" :time="time"
          @accept="() => { onAccept(bg); }" @reject="() => { onReject(bg); }">
        </BreakglassSessionCard>
      </div>
    </div>
  </main>
</template>

<style scoped>
.center {
  text-align: center;
}


.breakglass-list {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
  justify-content: center;
}
</style>
