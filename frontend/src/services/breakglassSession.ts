import type { AxiosInstance, AxiosResponse } from "axios";
import { handleAxiosError } from "@/services/logger";
import { createAuthenticatedApiClient } from "@/services/httpClient";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import type { SessionCR } from "@/model/breakglass";

function normalizeSessionList(value: unknown): SessionCR[] {
  return Array.isArray(value) ? (value as SessionCR[]) : [];
}

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

  public async getSessionStatus(request: BreakglassSessionRequest): Promise<AxiosResponse<SessionCR[]>> {
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
      const response = await this.client.get<unknown>("/breakglassSessions", { params });
      return { ...response, data: normalizeSessionList(response.data) };
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

  private async postSessionAction(
    review: BreakglassSessionRequest,
    action: string,
    errorMessage: string,
    body: Record<string, string> = {},
  ) {
    if (!review.name) throw new Error(`Missing session name for ${action}`);
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/${action}`, body);
    } catch (e) {
      handleAxiosError(`BreakglassSessionService.${action}`, e, errorMessage);
      throw e;
    }
  }

  private static buildReasonBody(review: BreakglassSessionRequest): Record<string, string> {
    const body: Record<string, string> = {};
    if (review.reason && review.reason.trim().length > 0) body.reason = review.reason;
    return body;
  }

  public async approveReview(review: BreakglassSessionRequest) {
    return this.postSessionAction(
      review,
      "approve",
      "Failed to approve session",
      BreakglassSessionService.buildReasonBody(review),
    );
  }

  public async rejectReview(review: BreakglassSessionRequest) {
    return this.postSessionAction(
      review,
      "reject",
      "Failed to reject session",
      BreakglassSessionService.buildReasonBody(review),
    );
  }

  public async withdrawSession(review: BreakglassSessionRequest) {
    return this.postSessionAction(review, "withdraw", "Failed to withdraw session");
  }

  public async dropSession(review: BreakglassSessionRequest) {
    return this.postSessionAction(review, "drop", "Failed to drop session");
  }

  public async cancelSession(review: BreakglassSessionRequest) {
    return this.postSessionAction(review, "cancel", "Failed to cancel session");
  }
}
