import type { AxiosInstance, AxiosResponse } from "axios";
import { handleAxiosError, debug } from "@/services/logger";
import { createAuthenticatedApiClient } from "@/services/httpClient";

import type AuthService from "@/services/auth";
import type { ActiveBreakglass, AvailableBreakglass, Breakglass, SessionCR } from "@/model/breakglass";

export type SessionSearchParams = {
  mine?: boolean;
  approver?: boolean;
  approvedByMe?: boolean;
  state?: string;
  cluster?: string;
  user?: string;
  group?: string;
  name?: string;
};

export default class BreakglassService {
  public async fetchMyOutstandingRequests(): Promise<SessionCR[]> {
    // Use RESTful endpoint with filtering
    debug("BreakglassService.fetchMyOutstandingRequests", "Fetching outstanding requests");
    try {
      const r = await this.client.get("/breakglassSessions", {
        params: { mine: true, approver: false, state: "pending" },
      });
      const sessions = Array.isArray(r.data) ? (r.data as SessionCR[]) : [];
      debug("BreakglassService.fetchMyOutstandingRequests", "Fetched outstanding requests", {
        count: sessions.length,
      });
      return sessions;
    } catch (e) {
      handleAxiosError("BreakglassService.fetchMyOutstandingRequests", e, "Failed to fetch outstanding requests");
      debug("BreakglassService.fetchMyOutstandingRequests", "Request failed", { errorMessage: (e as Error)?.message });
      throw e; // Re-throw so UI can show error state
    }
  }
  private client: AxiosInstance;
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;
    debug("BreakglassService", "Initializing authenticated API client");
    this.client = createAuthenticatedApiClient(this.auth);

    this.client.interceptors.response.use(
      (resp) => resp,
      (error) => {
        handleAxiosError("BreakglassService", error);
        debug("BreakglassService", "HTTP error intercepted", { status: error?.response?.status });
        return Promise.reject(error);
      },
    );
  }

  // Backend endpoints:
  // GET /api/breakglassEscalations -> []BreakglassEscalationSpec
  // GET /api/breakglassSessions -> []BreakglassSession
  private async fetchAvailableEscalations(): Promise<AvailableBreakglass[]> {
    debug("BreakglassService.fetchAvailableEscalations", "Fetching available escalations");
    const r = await this.client.get("/breakglassEscalations");
    // Each escalation spec has: allowed (clusters, groups), approvers (users, groups), escalatedGroup, maxValidFor, retainFor, idleTimeout, clusterConfigRefs, denyPolicyRefs
    // We explode multi-cluster escalations into individual entries per cluster so UI can show sessions per cluster.
    const data = Array.isArray(r.data) ? r.data : [];
    const output: AvailableBreakglass[] = [];
    data.forEach((item: Record<string, any>) => {
      const spec = item?.spec || {};
      const allowed = spec.allowed || {};
      const approvers = spec.approvers || {};
      const clusters: string[] = Array.isArray(allowed.clusters) ? allowed.clusters : [];
      const allowedGroups: string[] = Array.isArray(allowed.groups) ? allowed.groups : [];
      const escalatedGroup: string = spec.escalatedGroup || spec.escalatedgroup || spec.escalated_group || "";
      const basePartial = {
        from: allowedGroups[0] || "",
        to: escalatedGroup,
        duration: parseDuration(spec.maxValidFor) || 3600,
        selfApproval: !hasApprovers(approvers),
        approvalGroups: Array.isArray(approvers.groups) ? approvers.groups : [],
        requestReason: spec.requestReason
          ? { mandatory: !!spec.requestReason.mandatory, description: spec.requestReason.description || "" }
          : undefined,
        approvalReason: spec.approvalReason
          ? { mandatory: !!spec.approvalReason.mandatory, description: spec.approvalReason.description || "" }
          : undefined,
      };
      if (clusters.length === 0) {
        output.push({ ...basePartial, cluster: "" });
      } else {
        clusters.forEach((cl) => output.push({ ...basePartial, cluster: cl }));
      }
    });
    debug("BreakglassService.fetchAvailableEscalations", "Built available escalations", { count: output.length });
    return output;
  }

  public async fetchActiveSessions(): Promise<ActiveBreakglass[]> {
    try {
      debug("BreakglassService.fetchActiveSessions", "Fetching active sessions");
      const r = await this.client.get("/breakglassSessions", {
        params: { state: "approved", mine: true, approver: false },
      });
      const data = Array.isArray(r.data) ? (r.data as SessionCR[]) : [];
      debug("BreakglassService.fetchActiveSessions", "Fetched active sessions", { count: data.length });
      // Normalize approved sessions to a shape that includes metadata/spec/status so
      // callers (getBreakglasses) can build sessionActive/sessionPending consistently.
      return data.map((ses: SessionCR) => ({
        name: ses?.metadata?.name || ses.name || "",
        metadata: ses?.metadata || {},
        spec: ses?.spec || {},
        status: ses?.status || {},
        // canonical convenience fields used by matching logic
        group: (ses?.spec && ses.spec.grantedGroup) || ses?.group || "",
        expiry:
          ses?.status && ses.status.expiresAt ? new Date(ses.status.expiresAt).getTime() / 1000 : ses?.expiry || 0,
        cluster: (ses?.spec && ses.spec.cluster) || ses?.cluster || "",
        state: (ses?.status && ses.status.state) || "Approved",
        // include full session object for downstream UI
        sessionActive: ses,
      }));
    } catch (e) {
      handleAxiosError("BreakglassService.fetchActiveSessions", e, "Failed to fetch active sessions");
      debug("BreakglassService.fetchActiveSessions", "Request failed", { errorMessage: (e as Error)?.message });
      return [];
    }
  }

  // Fetch sessions in pending state that the current user can approve
  public async fetchPendingSessionsForApproval(): Promise<SessionCR[]> {
    try {
      debug("BreakglassService.fetchPendingSessionsForApproval", "Fetching pending sessions for approval");
      const r = await this.client.get("/breakglassSessions", {
        params: { state: "pending", approver: true, mine: false },
      });
      const data = Array.isArray(r.data) ? (r.data as SessionCR[]) : [];
      debug("BreakglassService.fetchPendingSessionsForApproval", "Fetched pending sessions", { count: data.length });
      // Fetch available escalations to enrich pending sessions with approvalReason config (if any)
      let escalations: AvailableBreakglass[] = [];
      try {
        escalations = await this.fetchAvailableEscalations();
      } catch {
        // ignore; we can proceed without config
        escalations = [];
      }
      // Map pending sessions to include approvalReason based on cluster+grantedGroup
      return data.map((p: SessionCR) => {
        const cluster = (p.spec && p.spec.cluster) || p.cluster || "";
        const group = (p.spec && p.spec.grantedGroup) || p.group || "";
        const match = escalations.find(
          (e: AvailableBreakglass) => e.cluster === cluster && (e.to === group || (e as any).group === group),
        );
        if (match && match.approvalReason) {
          // augment copy with approvalReason
          const out = { ...p } as SessionCR & { approvalReason?: any };
          out.approvalReason = match.approvalReason;
          return out;
        }
        return p;
      });
    } catch (e) {
      handleAxiosError("BreakglassService.fetchPendingSessionsForApproval", e, "Failed to fetch pending sessions");
      debug("BreakglassService.fetchPendingSessionsForApproval", "Request failed", {
        errorMessage: (e as Error)?.message,
      });
      return [];
    }
  }

  public async searchSessions(params: SessionSearchParams = {}): Promise<SessionCR[]> {
    try {
      debug("BreakglassService.searchSessions", "Searching sessions", { params });
      const response = await this.client.get("/breakglassSessions", {
        params,
      });
      const results = Array.isArray(response.data) ? (response.data as SessionCR[]) : [];
      debug("BreakglassService.searchSessions", "Search complete", { count: results.length });
      return results;
    } catch (e) {
      handleAxiosError("BreakglassService.searchSessions", e, "Failed to search sessions");
      debug("BreakglassService.searchSessions", "Search failed", { errorMessage: (e as Error)?.message });
      return [];
    }
  }

  public async requestBreakglass(
    transition: Breakglass,
    reason?: string,
    duration?: number,
    scheduledStartTime?: string,
  ): Promise<AxiosResponse> {
    // Backend expects POST /api/breakglassSessions with body { cluster, user, group, reason, duration, scheduledStartTime }
    try {
      debug("BreakglassService.requestBreakglass", "Requesting breakglass", {
        transition,
        duration,
        scheduledStartTime,
      });
      const username = await this.auth.getUserEmail(); // Derive username from auth service
      // backend expects short schema keys: cluster, user, group
      const body: {
        cluster: string;
        group: string;
        user: string;
        reason?: string;
        duration?: number;
        scheduledStartTime?: string;
      } = { cluster: transition.cluster, group: transition.to, user: username };
      if (reason && reason.trim().length > 0) body.reason = reason;
      if (duration && duration > 0) body.duration = Math.floor(duration);
      if (scheduledStartTime) body.scheduledStartTime = scheduledStartTime;
      const response = await this.client.post("/breakglassSessions", body);
      debug("BreakglassService.requestBreakglass", "Request submitted", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.requestBreakglass", e, "Failed to request breakglass");
      debug("BreakglassService.requestBreakglass", "Request failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }

  public async validateBreakglassRequest(token: string): Promise<AxiosResponse> {
    // RESTful: GET /breakglassSessions?token=...
    try {
      debug("BreakglassService.validateBreakglassRequest", "Validating breakglass request", { token: !!token });
      const response = await this.client.get("/breakglassSessions", { params: { token } });
      debug("BreakglassService.validateBreakglassRequest", "Validation complete", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.validateBreakglassRequest", e, "Failed to validate breakglass request");
      debug("BreakglassService.validateBreakglassRequest", "Validation failed", {
        errorMessage: (e as Error)?.message,
      });
      throw e;
    }
  }

  // Approve a pending breakglass session by session name (metadata.name)
  public async approveBreakglass(sessionName: string, reason?: string): Promise<AxiosResponse> {
    // RESTful: POST /api/breakglassSessions/:sessionName/approve
    try {
      debug("BreakglassService.approveBreakglass", "Approving breakglass", { sessionName });
      const body: Record<string, any> = {};
      if (reason && reason.trim().length > 0) body.reason = reason;
      const response = await this.client.post(`/breakglassSessions/${encodeURIComponent(sessionName)}/approve`, body);
      debug("BreakglassService.approveBreakglass", "Approval submitted", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.approveBreakglass", e, "Failed to approve breakglass");
      debug("BreakglassService.approveBreakglass", "Approval failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }

  // Reject a pending breakglass session by session name (metadata.name)
  public async rejectBreakglass(sessionName: string, reason?: string): Promise<AxiosResponse> {
    // RESTful: POST /api/breakglassSessions/:sessionName/reject
    try {
      debug("BreakglassService.rejectBreakglass", "Rejecting breakglass", { sessionName });
      const body: Record<string, any> = {};
      if (reason && reason.trim().length > 0) body.reason = reason;
      const response = await this.client.post(`/breakglassSessions/${encodeURIComponent(sessionName)}/reject`, body);
      debug("BreakglassService.rejectBreakglass", "Rejection submitted", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.rejectBreakglass", e, "Failed to reject breakglass");
      debug("BreakglassService.rejectBreakglass", "Rejection failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }

  public async testButton(user_name: string, cluster_name: string): Promise<AxiosResponse> {
    try {
      debug("BreakglassService.testButton", "Triggering test button", { user: user_name, cluster: cluster_name });
      const response = await this.client.post("/test", { user: user_name, cluster: cluster_name });
      debug("BreakglassService.testButton", "Test button response", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.testButton", e, "Test call failed");
      debug("BreakglassService.testButton", "Test button failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }

  public async dropBreakglass(breakglass: Breakglass): Promise<AxiosResponse> {
    // Call backend drop endpoint: POST /api/breakglassSessions/:name/drop
    const bg: Breakglass = breakglass;
    const name =
      bg.sessionActive?.metadata?.name ||
      bg.sessionPending?.metadata?.name ||
      bg.name ||
      bg.sessionActive?.name ||
      bg.sessionPending?.name;
    if (!name) throw new Error("Missing session name for drop");
    try {
      debug("BreakglassService.dropBreakglass", "Dropping breakglass", { name });
      const response = await this.client.post(`/breakglassSessions/${encodeURIComponent(name)}/drop`, {});
      debug("BreakglassService.dropBreakglass", "Drop submitted", { status: response.status });
      return response;
    } catch (e) {
      handleAxiosError("BreakglassService.dropBreakglass", e, "Failed to drop breakglass session");
      debug("BreakglassService.dropBreakglass", "Drop failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }

  public async fetchHistoricalSessions(): Promise<ActiveBreakglass[]> {
    try {
      debug("BreakglassService.fetchHistoricalSessions", "Fetching historical sessions");
      const response = await this.client.get("/breakglassSessions", {
        params: { state: "rejected,withdrawn", mine: true, approver: false },
      });
      const all = Array.isArray(response.data) ? response.data : [];
      debug("BreakglassService.fetchHistoricalSessions", "Fetched historical sessions", { count: all.length });
      return all.map((ses: any) => ({
        name: ses?.metadata?.name || "",
        group: ses?.spec?.grantedGroup || "",
        expiry: ses?.status?.expiresAt ? new Date(ses.status.expiresAt).getTime() / 1000 : 0,
        cluster: ses?.spec?.cluster || "",
        state: ses?.status?.state || "Unknown", // Use canonical state from backend
        started: ses?.status?.startedAt || ses?.metadata?.creationTimestamp || "",
        ended: ses?.status?.endedAt || ses?.status?.expiresAt || "",
        reasonEnded: ses?.status?.reasonEnded || "",
      }));
    } catch (e) {
      handleAxiosError(
        "BreakglassService.fetchHistoricalSessions",
        e,
        "Unable to load historical sessions. Showing recent activity only.",
      );
      debug("BreakglassService.fetchHistoricalSessions", "Request failed", { errorMessage: (e as Error)?.message });
      return [];
    }
  }

  // Fetch sessions belonging to the current user (approved + expired/timed-out + historical)
  public async fetchMySessions(): Promise<ActiveBreakglass[]> {
    try {
      debug("BreakglassService.fetchMySessions", "Fetching my sessions");
      const [activeResp, timedOutResp, historical] = await Promise.all([
        this.client.get("/breakglassSessions", { params: { mine: true, approver: false, state: "approved" } }),
        this.client.get("/breakglassSessions", { params: { mine: true, approver: false, state: "timeout" } }),
        this.fetchHistoricalSessions(),
      ]);
      const approved = Array.isArray(activeResp.data) ? activeResp.data : [];
      const timedOut = Array.isArray(timedOutResp.data) ? timedOutResp.data : [];

      // Normalize entries to ActiveBreakglass shape
      const approvedNormalized = approved.map((ses: any) => this.normalizeSessionRecord(ses));
      const timedOutNormalized = timedOut.map((ses: any) => this.normalizeSessionRecord(ses));

      // Merge all session sources (approved + timed-out + historical) and dedupe by session name
      const combined = [...approvedNormalized, ...timedOutNormalized, ...historical];
      const seen = new Map<string, ActiveBreakglass>();
      for (const s of combined) {
        const key = s?.name || (s?.metadata && s.metadata.name) || `${s.group}-${s.cluster}-${s.expiry}`;
        if (!seen.has(key)) seen.set(key, s);
      }
      const result = Array.from(seen.values());
      debug("BreakglassService.fetchMySessions", "Compiled my sessions", { count: result.length });
      return result;
    } catch (e) {
      handleAxiosError("BreakglassService.fetchMySessions", e, "Failed to fetch my sessions");
      debug("BreakglassService.fetchMySessions", "Request failed", { errorMessage: (e as Error)?.message });
      return [];
    }
  }

  // Fetch sessions that the current user approved (includes approved + timed-out sessions)
  public async fetchSessionsIApproved(): Promise<ActiveBreakglass[]> {
    try {
      debug("BreakglassService.fetchSessionsIApproved", "Fetching sessions I approved");
      const response = await this.client.get("/breakglassSessions", {
        params: { state: "approved,timeout", mine: false, approver: false, approvedByMe: true },
      });
      const data = Array.isArray(response.data) ? response.data : [];

      const combined = data.map((ses: any) => this.normalizeSessionRecord(ses));
      const seen = new Map<string, ActiveBreakglass>();
      for (const s of combined) {
        const key = s?.name || `${s.group}-${s.cluster}-${s.expiry}`;
        if (!seen.has(key)) seen.set(key, s);
      }
      const result = Array.from(seen.values());
      debug("BreakglassService.fetchSessionsIApproved", "Compiled sessions I approved", { count: result.length });
      return result;
    } catch (e) {
      handleAxiosError("BreakglassService.fetchSessionsIApproved", e, "Failed to fetch sessions I approved");
      debug("BreakglassService.fetchSessionsIApproved", "Request failed", { errorMessage: (e as Error)?.message });
      return [];
    }
  }

  public async getBreakglasses(): Promise<Breakglass[]> {
    debug("BreakglassService.getBreakglasses", "Aggregating breakglass data");
    const [available, active, pending, historical] = await Promise.all([
      this.fetchAvailableEscalations(),
      this.fetchActiveSessions(),
      this.fetchMyOutstandingRequests(),
      this.fetchHistoricalSessions(),
    ]);
    debug("BreakglassService.getBreakglasses", "Fetched collections", {
      available: available.length,
      active: active.length,
      pending: pending.length,
      historical: historical.length,
    });
    const result = available.map((av) => {
      const match = active.find((a) => a.group === av.to && a.cluster === av.cluster);
      const pendingMatch = pending.find((p) => p.spec?.grantedGroup === av.to && p.spec?.cluster === av.cluster);
      const historyMatch = historical.find((h) => h.group === av.to && h.cluster === av.cluster);
      // Ensure sessionActive is a full session object with metadata/spec for drop/withdraw
      let sessionActive = null;
      if (match && typeof match === "object") {
        const m: any = match;
        sessionActive = {
          metadata: {
            name: m.metadata?.name || m.name || m.group || "",
            creationTimestamp: m.metadata?.creationTimestamp || "",
          },
          spec: { grantedGroup: m.spec?.grantedGroup || m.group, cluster: m.spec?.cluster || m.cluster },
          status: { expiresAt: m.status?.expiresAt || m.expiry, state: m.status?.state || m.state },
        };
      }
      let sessionPending = null;
      if (pendingMatch && typeof pendingMatch === "object") {
        const p: any = pendingMatch;
        sessionPending = {
          metadata: {
            name: p.metadata?.name || p.name || p.spec?.grantedGroup || p.group || "",
            creationTimestamp: p.metadata?.creationTimestamp || "",
          },
          spec: { grantedGroup: p.spec?.grantedGroup || p.group, cluster: p.spec?.cluster || p.cluster },
          status: { expiresAt: p.status?.expiresAt || p.expiry, state: p.status?.state || p.state },
        };
      }
      return {
        ...av,
        group: av.to,
        expiry: match ? match.expiry : 0,
        cluster: av.cluster,
        state: match ? "Active" : pendingMatch ? "Pending" : historyMatch ? historyMatch.state : "Available",
        sessionPending: sessionPending,
        sessionActive: sessionActive,
      } as Breakglass;
    });
    debug("BreakglassService.getBreakglasses", "Aggregated breakglasses", { count: result.length });
    return result;
  }

  private normalizeSessionRecord(ses: any): ActiveBreakglass {
    return {
      name: ses?.metadata?.name || ses?.name || "",
      group: ses?.spec?.grantedGroup || ses?.group || "",
      cluster: ses?.spec?.cluster || ses?.cluster || "",
      expiry: ses?.status?.expiresAt || 0,
      state: ses?.status?.state || "Approved",
      metadata: ses?.metadata || {},
      spec: ses?.spec || {},
      status: ses?.status || {},
    };
  }

  // Withdraw (cancel) a pending breakglass session request by the user
  public async withdrawMyRequest(req: SessionCR): Promise<void> {
    // Use the new RESTful withdraw endpoint
    // RESTful: POST /api/breakglassSessions/:name/withdraw
    const sessionName = req.metadata?.name;
    if (!sessionName) throw new Error("Missing session name");
    try {
      // backend withdraw endpoint requires only the session name path; additional body is optional
      debug("BreakglassService.withdrawMyRequest", "Withdrawing request", { sessionName });
      await this.client.post(`/breakglassSessions/${encodeURIComponent(sessionName)}/withdraw`, {});
      debug("BreakglassService.withdrawMyRequest", "Withdraw complete");
    } catch (e) {
      handleAxiosError("BreakglassService.withdrawMyRequest", e, "Failed to withdraw request");
      debug("BreakglassService.withdrawMyRequest", "Withdraw failed", { errorMessage: (e as Error)?.message });
      throw e;
    }
  }
}

// Helper: parse simple duration strings like "1h", "30m"; default seconds fallback
function parseDuration(input: string | undefined): number | undefined {
  if (!input) return undefined;
  const match = /^(\d+)([smhd])$/.exec(input);
  if (!match) return undefined;
  // match: [full, digits, unit]
  const raw = match[1] ?? "";
  const unit = match[2] ?? "";
  const val = raw ? parseInt(raw, 10) : NaN;
  if (Number.isNaN(val)) return undefined;
  switch (unit) {
    case "s":
      return val;
    case "m":
      return val * 60;
    case "h":
      return val * 3600;
    case "d":
      return val * 86400;
    default:
      return undefined;
  }
}

function hasApprovers(appr: any): boolean {
  if (!appr) return false;
  const users = Array.isArray(appr.users) ? appr.users : [];
  const groups = Array.isArray(appr.groups) ? appr.groups : [];
  return users.length + groups.length > 0;
}
