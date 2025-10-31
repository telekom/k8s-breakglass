import axios, { type AxiosRequestHeaders, type AxiosResponse } from "axios";
import { handleAxiosError } from "@/services/logger";

import type AuthService from "@/services/auth";
import type { ActiveBreakglass, AvailableBreakglass, Breakglass, SessionCR } from "@/model/breakglass";

export default class BreakglassService {
  public async fetchMyOutstandingRequests(): Promise<SessionCR[]> {
    // Use RESTful endpoint with filtering
    try {
      const r = await this.client.get('/breakglassSessions', { params: { mine: true, approver: false, state: 'pending' } });
      return Array.isArray(r.data) ? r.data as SessionCR[] : [];
    } catch (e) {
      handleAxiosError('BreakglassService.fetchMyOutstandingRequests', e, 'Failed to fetch outstanding requests');
      return [];
    }
  }
  private client = axios.create({
    baseURL: "/api",
  });
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;

    this.client.interceptors.request.use(async (req) => {
      if (!req.headers) {
        req.headers = {} as AxiosRequestHeaders;
      }
      req.headers["Authorization"] = `Bearer ${await this.auth.getAccessToken()}`;
      return req;
    });

    this.client.interceptors.response.use((resp) => resp, (error) => {
      handleAxiosError('BreakglassService', error);
      return Promise.reject(error);
    });
  }

  // Backend endpoints:
  // GET /api/breakglassEscalations -> []BreakglassEscalationSpec
  // GET /api/breakglassSessions -> []BreakglassSession
  private async fetchAvailableEscalations(): Promise<AvailableBreakglass[]> {
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
        requestReason: spec.requestReason ? { mandatory: !!spec.requestReason.mandatory, description: spec.requestReason.description || "" } : undefined,
        approvalReason: spec.approvalReason ? { mandatory: !!spec.approvalReason.mandatory, description: spec.approvalReason.description || "" } : undefined,
      };
      if (clusters.length === 0) {
        output.push({ ...basePartial, cluster: "" });
      } else {
        clusters.forEach((cl) => output.push({ ...basePartial, cluster: cl }));
      }
    });
    return output;
  }

  public async fetchActiveSessions(): Promise<ActiveBreakglass[]> {
    try {
      const r = await this.client.get('/breakglassSessions', { params: { state: 'approved', mine: true, approver: false } });
      const data = Array.isArray(r.data) ? r.data as SessionCR[] : [];
      // Normalize approved sessions to a shape that includes metadata/spec/status so
      // callers (getBreakglasses) can build sessionActive/sessionPending consistently.
      return data.map((ses: SessionCR) => ({
        name: ses?.metadata?.name || ses.name || "",
        metadata: ses?.metadata || {},
        spec: ses?.spec || {},
        status: ses?.status || {},
        // canonical convenience fields used by matching logic
        group: (ses?.spec && ses.spec.grantedGroup) || ses?.group || "",
        expiry: ses?.status && ses.status.expiresAt ? new Date(ses.status.expiresAt).getTime() / 1000 : (ses?.expiry || 0),
        cluster: (ses?.spec && ses.spec.cluster) || ses?.cluster || "",
  state: (ses?.status && ses.status.state) || "Approved",
        // include full session object for downstream UI
        sessionActive: ses,
      }));
    } catch (e) {
      handleAxiosError('BreakglassService.fetchActiveSessions', e, 'Failed to fetch active sessions');
      return [];
    }
  }

  // Fetch sessions in pending state that the current user can approve
  public async fetchPendingSessionsForApproval(): Promise<SessionCR[]> {
    try {
      const r = await this.client.get('/breakglassSessions', { params: { state: 'pending', approver: true, mine: false } });
      const data = Array.isArray(r.data) ? r.data as SessionCR[] : [];
      // Fetch available escalations to enrich pending sessions with approvalReason config (if any)
  let escalations: AvailableBreakglass[] = [];
      try {
        escalations = await this.fetchAvailableEscalations();
      } catch (e) {
        // ignore; we can proceed without config
        escalations = [];
      }
      // Map pending sessions to include approvalReason based on cluster+grantedGroup
  return data.map((p: SessionCR) => {
        const cluster = (p.spec && p.spec.cluster) || p.cluster || "";
        const group = (p.spec && p.spec.grantedGroup) || p.group || "";
  const match = escalations.find((e: AvailableBreakglass) => e.cluster === cluster && (e.to === group || (e as any).group === group));
        if (match && match.approvalReason) {
          // augment copy with approvalReason
          const out = { ...p } as SessionCR & { approvalReason?: any };
          out.approvalReason = match.approvalReason;
          return out;
        }
        return p;
      });
    } catch (e) {
      handleAxiosError('BreakglassService.fetchPendingSessionsForApproval', e, 'Failed to fetch pending sessions');
      return [];
    }
  }

  public async requestBreakglass(transition: Breakglass, reason?: string): Promise<AxiosResponse> {
    // Backend expects POST /api/breakglassSessions with body { cluster, user, group }
    try {
      const username = await this.auth.getUserEmail(); // Derive username from auth service
      // backend expects short schema keys: cluster, user, group
  const body: { cluster: string; group: string; user: string; reason?: string } = { cluster: transition.cluster, group: transition.to, user: username };
  if (reason && reason.trim().length > 0) body.reason = reason;
  return await this.client.post('/breakglassSessions', body);
    } catch (e) {
      handleAxiosError('BreakglassService.requestBreakglass', e, 'Failed to request breakglass');
      throw e;
    }
  }

  public async validateBreakglassRequest(token: string): Promise<AxiosResponse> {
    // RESTful: GET /breakglassSessions?token=...
    try {
      return await this.client.get('/breakglassSessions', { params: { token } });
    } catch (e) {
      handleAxiosError('BreakglassService.validateBreakglassRequest', e, 'Failed to validate breakglass request');
      throw e;
    }
  }

  // Approve a pending breakglass session by session name (metadata.name)
  public async approveBreakglass(sessionName: string, reason?: string): Promise<AxiosResponse> {
    // RESTful: POST /api/breakglassSessions/:sessionName/approve
    try {
  const body: Record<string, any> = {};
  if (reason && reason.trim().length > 0) body.reason = reason;
  return await this.client.post(`/breakglassSessions/${encodeURIComponent(sessionName)}/approve`, body);
    } catch (e) {
      handleAxiosError('BreakglassService.approveBreakglass', e, 'Failed to approve breakglass');
      throw e;
    }
  }

  public async testButton(user_name: string, cluster_name: string): Promise<AxiosResponse> {
    try {
      return await this.client.post('/test', { user: user_name, cluster: cluster_name });
    } catch (e) {
      handleAxiosError('BreakglassService.testButton', e, 'Test call failed');
      throw e;
    }
  }

  public async dropBreakglass(breakglass: Breakglass): Promise<AxiosResponse> {
    // Call backend drop endpoint: POST /api/breakglassSessions/:name/drop
  const bg: Breakglass = breakglass;
  const name = bg.sessionActive?.metadata?.name || bg.sessionPending?.metadata?.name || bg.name || bg.sessionActive?.name || bg.sessionPending?.name;
    if (!name) throw new Error('Missing session name for drop');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(name)}/drop`, {});
    } catch (e) {
      handleAxiosError('BreakglassService.dropBreakglass', e, 'Failed to drop breakglass session');
      throw e;
    }
  }

  public async fetchHistoricalSessions(): Promise<ActiveBreakglass[]> {
    // Fetch both rejected and withdrawn sessions
    const [rejectedResp, withdrawnResp] = await Promise.all([
      // Historical lists for "My previous sessions" should be scoped to the authenticated user
      this.client.get("/breakglassSessions", { params: { state: "rejected", mine: true, approver: false } }),
      this.client.get("/breakglassSessions", { params: { state: "withdrawn", mine: true, approver: false } })
    ]);
    const rejected = Array.isArray(rejectedResp.data) ? rejectedResp.data : [];
    const withdrawn = Array.isArray(withdrawnResp.data) ? withdrawnResp.data : [];
    const all = [...rejected, ...withdrawn];
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
  }

  // Fetch sessions belonging to the current user (approved + historical)
  public async fetchMySessions(): Promise<ActiveBreakglass[]> {
    try {
      const [approvedResp, historical] = await Promise.all([
  this.client.get('/breakglassSessions', { params: { mine: true, approver: false, state: 'approved' } }),
        this.fetchHistoricalSessions(),
      ]);
      const approved = Array.isArray(approvedResp.data) ? approvedResp.data : [];
      // Normalize approved entries to ActiveBreakglass shape used elsewhere
      const approvedNormalized = approved.map((ses: any) => ({
        name: ses?.metadata?.name || ses.name || "",
        group: ses?.spec?.grantedGroup || "",
        cluster: ses?.spec?.cluster || "",
        expiry: ses?.status?.expiresAt || 0,
        state: ses?.status?.state || "Approved",
        metadata: ses?.metadata || {},
        spec: ses?.spec || {},
        status: ses?.status || {},
      }));
      // Merge approved + historical (historical already normalized) and dedupe by session name
      const combined = [...approvedNormalized, ...historical];
      const seen = new Map<string, ActiveBreakglass>();
      for (const s of combined) {
        const key = s?.name || (s?.metadata && s.metadata.name) || `${s.group}-${s.cluster}-${s.expiry}`;
        if (!seen.has(key)) seen.set(key, s);
      }
      return Array.from(seen.values());
    } catch (e) {
      handleAxiosError('BreakglassService.fetchMySessions', e, 'Failed to fetch my sessions');
      return [];
    }
  }

  // Fetch sessions that the current user approved (approximation: look through approved sessions and find conditions mentioning approver email)
  public async fetchSessionsIApproved(): Promise<ActiveBreakglass[]> {
    try {
  const r = await this.client.get('/breakglassSessions', { params: { state: 'approved', mine: false, approver: false } });
      const data = Array.isArray(r.data) ? r.data : [];
      return data.map((ses: any) => ({
        name: ses?.metadata?.name || "",
        group: ses?.spec?.grantedGroup || "",
        cluster: ses?.spec?.cluster || "",
        expiry: ses?.status?.expiresAt || 0,
        state: ses?.status?.state || "Approved",
        metadata: ses?.metadata || {},
        spec: ses?.spec || {},
        status: ses?.status || {},
      }));
    } catch (e) {
      handleAxiosError('BreakglassService.fetchSessionsIApproved', e, 'Failed to fetch sessions I approved');
      return [];
    }
  }

  public async getBreakglasses(): Promise<Breakglass[]> {
    const [available, active, pending, historical] = await Promise.all([
      this.fetchAvailableEscalations(),
      this.fetchActiveSessions(),
      this.fetchMyOutstandingRequests(),
      this.fetchHistoricalSessions(),
    ]);
    return available.map((av) => {
      const match = active.find((a) => a.group === av.to && a.cluster === av.cluster);
      const pendingMatch = pending.find((p) => p.spec?.grantedGroup === av.to && p.spec?.cluster === av.cluster);
      const historyMatch = historical.find((h) => h.group === av.to && h.cluster === av.cluster);
      // Ensure sessionActive is a full session object with metadata/spec for drop/withdraw
      let sessionActive = null;
      if (match && typeof match === 'object') {
        const m: any = match;
        sessionActive = {
          metadata: { name: m.metadata?.name || m.name || m.group || "", creationTimestamp: m.metadata?.creationTimestamp || "" },
          spec: { grantedGroup: m.spec?.grantedGroup || m.group, cluster: m.spec?.cluster || m.cluster },
          status: { expiresAt: m.status?.expiresAt || m.expiry, state: (m.status?.state || m.state) },
        };
      }
      let sessionPending = null;
      if (pendingMatch && typeof pendingMatch === 'object') {
        const p: any = pendingMatch;
        sessionPending = {
          metadata: { name: p.metadata?.name || p.name || p.spec?.grantedGroup || p.group || "", creationTimestamp: p.metadata?.creationTimestamp || "" },
          spec: { grantedGroup: p.spec?.grantedGroup || p.group, cluster: p.spec?.cluster || p.cluster },
          status: { expiresAt: p.status?.expiresAt || p.expiry, state: (p.status?.state || p.state) },
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
  }

  // Withdraw (cancel) a pending breakglass session request by the user
  public async withdrawMyRequest(req: SessionCR): Promise<void> {
    // Use the new RESTful withdraw endpoint
    // RESTful: POST /api/breakglassSessions/:name/withdraw
  const sessionName = req.metadata?.name;
    if (!sessionName) throw new Error('Missing session name');
    try {
  // backend withdraw endpoint requires only the session name path; additional body is optional
  await this.client.post(`/breakglassSessions/${encodeURIComponent(sessionName)}/withdraw`, {});
    } catch (e) {
      handleAxiosError('BreakglassService.withdrawMyRequest', e, 'Failed to withdraw request');
      throw e;
    }
  }
}

// Helper: parse simple duration strings like "1h", "30m"; default seconds fallback
function parseDuration(input: string | undefined): number | undefined {
  if (!input || typeof input !== "string") return undefined;
  const m = input.match(/^(\d+)([smhd])$/); // seconds, minutes, hours, days
  if (!m) return undefined;
  const val = parseInt(m[1]);
  switch (m[2]) {
    case "s": return val;
    case "m": return val * 60;
    case "h": return val * 3600;
    case "d": return val * 86400;
  }
  return undefined;
}

function hasApprovers(appr: any): boolean {
  if (!appr) return false;
  const users = Array.isArray(appr.users) ? appr.users : [];
  const groups = Array.isArray(appr.groups) ? appr.groups : [];
  return users.length + groups.length > 0;
}
