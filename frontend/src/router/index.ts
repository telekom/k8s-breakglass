import MyPendingRequests from "@/views/MyPendingRequests.vue";

import BreakglassView from "@/views/BreakglassView.vue";
import BreaglassSessionReviewView from "@/views/BreakglassSessionReview.vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import SessionBrowser from "@/views/SessionBrowser.vue";
import NotFoundView from "@/views/NotFoundView.vue";

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
      name: "myPendingRequests",
      component: MyPendingRequests,
    },
    {
      path: "/sessions",
      name: "sessionBrowser",
      component: SessionBrowser,
    },
    {
      path: "/:pathMatch(.*)*",
      name: "notFound",
      component: NotFoundView,
    },
  ],
});

export default router;
