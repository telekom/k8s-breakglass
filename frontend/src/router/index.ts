import MyOutstandingRequests from "@/views/MyOutstandingRequests.vue";

import BreakglassView from "@/views/BreakglassView.vue";
import BreaglassSessionReviewView from "@/views/BreakglassSessionReview.vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import SessionBrowser from "@/views/SessionBrowser.vue";

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
      path: "/sessions/review",
      alias: "/review",
      name: "breakglassSessionReview",
      component: BreaglassSessionReviewView,
    },
    {
      path: "/approvals/pending",
      name: "pendingApprovals",
      component: PendingApprovalsView,
    },
    {
      path: "/requests/mine",
      name: "myOutstandingRequests",
      component: MyOutstandingRequests,
    },
    {
      path: "/sessions",
      name: "sessionBrowser",
      component: SessionBrowser,
    },
  ],
});

export default router;
