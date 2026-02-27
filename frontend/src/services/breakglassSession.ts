import type { AxiosInstance } from "axios";
import { handleAxiosError } from "@/services/logger";
import { createAuthenticatedApiClient } from "@/services/httpClient";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";

export default class BreakglassSessionService {
  private client: AxiosInstance;
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;
    this.client = createAuthenticatedApiClient(this.auth, { enableDevTokenLogging: true });
    // Note: Error handling is done in individual methods to provide context-specific messages.
    // Do NOT add a response interceptor that calls handleAxiosError here, as it would cause
    // duplicate error toasts (interceptor + method catch block).
  }

  public async requestSession(request: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions
    try {
      // backend expects short schema keys: cluster, user, group
      const payload: Record<string, string | boolean | undefined> = {
        cluster: request.cluster,
        user: request.user,
        group: request.group,
      };
      // name and activeOnly are not part of create request payload in backend API
      if (request.name) payload.name = request.name;
      if (request.reason) payload.reason = request.reason;
      if (request.scheduledStartTime) payload.scheduledStartTime = request.scheduledStartTime;
      return await this.client.post("/breakglassSessions", payload);
    } catch (e) {
      handleAxiosError("BreakglassSessionService.requestSession", e, "Failed to create session request");
      throw e;
    }
  }

  public async getSessionStatus(request: BreakglassSessionRequest) {
    // RESTful: GET /breakglassSessions?user=...&cluster=...&group=...&name=...
    try {
      const params: Record<string, string | boolean> = {};
      if (request.user && request.user !== "") params.user = request.user;
      if (request.cluster && request.cluster !== "") params.cluster = request.cluster;
      if (request.group && request.group !== "") params.group = request.group;
      if (request.name && request.name !== "") params.name = request.name;

      if (typeof request.activeOnly !== "undefined") params.activeOnly = request.activeOnly;
      // Default client-side policy: mine defaults to true, approver defaults to false
      params.mine = request.mine === undefined ? true : request.mine;
      params.approver = request.approver === undefined ? false : request.approver;
      return await this.client.get("/breakglassSessions", { params });
    } catch (e) {
      handleAxiosError("BreakglassSessionService.getSessionStatus", e, "Failed to fetch session status");
      throw e;
    }
  }

  public async getSessionByName(name: string) {
    // RESTful: GET /breakglassSessions/:name - returns a single session
    try {
      return await this.client.get(`/breakglassSessions/${encodeURIComponent(name)}`);
    } catch (e) {
      handleAxiosError("BreakglassSessionService.getSessionByName", e, "Failed to fetch session");
      throw e;
    }
  }

  public async getClusterAccessReviews(): Promise<ClusterAccessReview[]> {
    try {
      const reviews = await this.client.get<ClusterAccessReview[]>("/reviews");
      return reviews.data;
    } catch (e) {
      handleAxiosError("BreakglassSessionService.getClusterAccessReviews", e, "Failed to fetch cluster access reviews");
      return [];
    }
  }

  public async approveReview(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/approve
    if (!review.name) throw new Error("Missing session name for approve");
    try {
      const body: Record<string, string> = {};
      if (review.reason && review.reason.trim().length > 0) body.reason = review.reason;
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/approve`, body);
    } catch (e) {
      handleAxiosError("BreakglassSessionService.approveReview", e, "Failed to approve session");
      throw e;
    }
  }

  public async rejectReview(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/reject
    if (!review.name) throw new Error("Missing session name for reject");
    try {
      const body: Record<string, string> = {};
      if (review.reason && review.reason.trim().length > 0) body.reason = review.reason;
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/reject`, body);
    } catch (e) {
      handleAxiosError("BreakglassSessionService.rejectReview", e, "Failed to reject session");
      throw e;
    }
  }

  public async withdrawSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/withdraw
    if (!review.name) throw new Error("Missing session name for withdraw");
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/withdraw`, {});
    } catch (e) {
      handleAxiosError("BreakglassSessionService.withdrawSession", e, "Failed to withdraw session");
      throw e;
    }
  }

  public async dropSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/drop
    if (!review.name) throw new Error("Missing session name for drop");
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/drop`, {});
    } catch (e) {
      handleAxiosError("BreakglassSessionService.dropSession", e, "Failed to drop session");
      throw e;
    }
  }

  public async cancelSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/cancel (approver cancels running session)
    if (!review.name) throw new Error("Missing session name for cancel");
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/cancel`, {});
    } catch (e) {
      handleAxiosError("BreakglassSessionService.cancelSession", e, "Failed to cancel session");
      throw e;
    }
  }
}
