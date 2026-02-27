import MyPendingRequests from "@/views/MyPendingRequests.vue";

import BreakglassView from "@/views/BreakglassView.vue";
import BreaglassSessionReviewView from "@/views/BreakglassSessionReview.vue";
import SessionApprovalView from "@/views/SessionApprovalView.vue";
import SessionErrorView from "@/views/SessionErrorView.vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import SessionBrowser from "@/views/SessionBrowser.vue";
import NotFoundView from "@/views/NotFoundView.vue";

// Debug Session Views
import DebugSessionBrowser from "@/views/DebugSessionBrowser.vue";
import DebugSessionCreate from "@/views/DebugSessionCreate.vue";
import DebugSessionDetails from "@/views/DebugSessionDetails.vue";

import { createRouter, createWebHistory } from "vue-router";
import logger from "@/services/logger";

const isDev = import.meta.env.DEV;

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
      path: "/session/:sessionName/approve",
      name: "sessionApproval",
      component: SessionApprovalView,
    },
    {
      path: "/session/:sessionName",
      name: "sessionIncomplete",
      component: SessionErrorView,
    },
    {
      path: "/session",
      name: "sessionMissing",
      component: SessionErrorView,
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

// Navigation guards with logging
router.beforeEach((to, from, next) => {
  if (isDev) {
    logger.info("Router", `Navigation: ${from.path} → ${to.path}`, {
      fromName: from.name,
      toName: to.name,
      params: to.params,
      query: to.query,
    });
  }
  next();
});

router.afterEach((to, from, failure) => {
  if (failure) {
    logger.error("Router", "Navigation failed", failure, {
      from: from.path,
      to: to.path,
    });
  } else if (isDev) {
    logger.debug("Router", "Navigation completed", {
      path: to.path,
      name: to.name,
    });
  }
});

router.onError((error) => {
  logger.error("Router", "Router error", error);
});

export default router;
