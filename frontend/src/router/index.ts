import { createRouter, createWebHistory } from "vue-router";

// Route-level code splitting — each view is lazily loaded on first navigation.
// The home view (BreakglassView) is kept eager since it is always the first page.
import BreakglassView from "@/views/BreakglassView.vue";

const BreakglassSessionReviewView = () => import("@/views/BreakglassSessionReview.vue");
const SessionApprovalView = () => import("@/views/SessionApprovalView.vue");
const SessionErrorView = () => import("@/views/SessionErrorView.vue");
const PendingApprovalsView = () => import("@/views/PendingApprovalsView.vue");
const MyPendingRequests = () => import("@/views/MyPendingRequests.vue");
const SessionBrowser = () => import("@/views/SessionBrowser.vue");
const NotFoundView = () => import("@/views/NotFoundView.vue");

// Debug Session Views
const DebugSessionBrowser = () => import("@/views/DebugSessionBrowser.vue");
const DebugSessionCreate = () => import("@/views/DebugSessionCreate.vue");
const DebugSessionDetails = () => import("@/views/DebugSessionDetails.vue");
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
      component: BreakglassSessionReviewView,
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

/** Handle id for the post-navigation focus timer so rapid navigations cancel the previous one. */
let focusTimerId: ReturnType<typeof setTimeout> | null = null;

router.afterEach((to, from, failure) => {
  // Cancel any pending focus move from a previous navigation regardless of outcome
  if (focusTimerId !== null) {
    clearTimeout(focusTimerId);
    focusTimerId = null;
  }

  if (failure) {
    logger.error("Router", "Navigation failed", failure, {
      from: from.path,
      to: to.path,
    });
  } else {
    if (isDev) {
      logger.debug("Router", "Navigation completed", {
        path: to.path,
        name: to.name,
      });
    }

    // Move focus to the main heading after navigation for screen readers.
    // Guarded: skip if the user (or a component) has already placed focus
    // inside #main so we don't override intentional focus targets.
    focusTimerId = setTimeout(() => {
      focusTimerId = null;
      const mainEl = document.getElementById("main");
      if (mainEl && mainEl.contains(document.activeElement)) {
        return; // User or component already focused something inside main
      }
      const heading = document.querySelector("#main h1, #main h2") as HTMLElement | null;
      if (heading) {
        const previousTabIndex = heading.getAttribute("tabindex");
        heading.setAttribute("tabindex", "-1");
        heading.focus({ preventScroll: true });
        // Restore original tabindex on blur to avoid persistent DOM mutations
        // while allowing screen readers time to read the element
        heading.addEventListener(
          "blur",
          () => {
            if (previousTabIndex === null) {
              heading.removeAttribute("tabindex");
            } else {
              heading.setAttribute("tabindex", previousTabIndex);
            }
          },
          { once: true },
        );
      }
    }, 150);
  }
});

router.onError((error) => {
  logger.error("Router", "Router error", error);
});

export default router;
