import BreakglassView from "@/views/BreakglassView.vue";
import BreaglassSessionRequestView from "@/views/BreakglassSessionRequest.vue";
import BreaglassSessionReviewView from "@/views/BreakglassSessionReview.vue";

import { createRouter, createWebHistory } from "vue-router";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      name: "home",
      component: BreakglassView,
    },
    {
      path: "/breakglassSession/request",
      name: "breakglassSessionRequest",
      component: BreaglassSessionRequestView,
    },
    {
      path: "/breakglassSession/review",
      name: "breakglassSessionReview",
      component: BreaglassSessionReviewView,
    },
  ],
});

export default router;
