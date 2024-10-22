import ApproveView from "@/views/ApproveView.vue";
import BreakglassView from "@/views/BreakglassView.vue";
import WebhookAccessView from "@/views/WebhookAccessView.vue";
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
      path: "/approve",
      name: "approve",
      component: ApproveView,
    },
    {
      path: "/cluster_access",
      name: "cluster_access",
      component: WebhookAccessView,
    },
  ],
});

export default router;
