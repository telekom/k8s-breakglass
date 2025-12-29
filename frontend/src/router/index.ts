import MyPendingRequests from "@/views/MyPendingRequests.vue";

import BreakglassView from "@/views/BreakglassView.vue";
import BreaglassSessionReviewView from "@/views/BreakglassSessionReview.vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import SessionBrowser from "@/views/SessionBrowser.vue";
import NotFoundView from "@/views/NotFoundView.vue";

// Debug Session Views
import DebugSessionBrowser from "@/views/DebugSessionBrowser.vue";
import DebugSessionCreate from "@/views/DebugSessionCreate.vue";
import DebugSessionDetails from "@/views/DebugSessionDetails.vue";

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
    // Debug Session Routes
    {
      path: "/debug-sessions",
      name: "debugSessionBrowser",
      component: DebugSessionBrowser,
    },
    {
      path: "/debug-sessions/create",
      name: "debugSessionCreate",
      component: DebugSessionCreate,
    },
    {
      path: "/debug-sessions/:name",
      name: "debugSessionDetails",
      component: DebugSessionDetails,
    },
    {
      path: "/:pathMatch(.*)*",
      name: "notFound",
      component: NotFoundView,
    },
  ],
});

export default router;
