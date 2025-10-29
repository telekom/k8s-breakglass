
import axios, { type AxiosResponse, AxiosHeaders } from "axios";
import { handleAxiosError } from "@/services/logger";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";

export default class BreakglassSessionService {
  private client = axios.create({
    baseURL: "/api",
  });
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;

    this.client.interceptors.request.use(async (req) => {
      if (!req.headers) {
        req.headers = {} as AxiosHeaders;
      }
      const token = await this.auth.getAccessToken();
      req.headers["Authorization"] = `Bearer ${token}`;
      // Dev-only: surface Authorization header in console for debugging when VUE_APP_DEV_TOKEN_LOG is set
      try {
        // Use a window-scoped flag for dev logging to avoid bundler/node type issues
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        if (typeof window !== 'undefined' && (window.__DEV_TOKEN_LOG === true || window.__DEV_TOKEN_LOG === 'true')) {
          // eslint-disable-next-line no-console
          console.debug('[BreakglassSessionService] Authorization header:', req.headers['Authorization']);
        }
      } catch (e) {
        // ignore in non-browser or hardened environments
      }
      return req;
    });

    this.client.interceptors.response.use((resp) => resp, (error) => {
      // normalize and record error
      handleAxiosError("BreakglassSessionService", error);
      return Promise.reject(error);
    });
  }

  public async requestSession(request: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions
    try {
      // backend expects short schema keys: cluster, user, group
      const payload: any = {
        cluster: request.cluster,
        user: request.user,
        group: request.group,
      };
      // name and activeOnly are not part of create request payload in backend API
      if (request.name) payload.name = request.name;
      return await this.client.post("/breakglassSessions", payload);
    } catch (e) {
      handleAxiosError("BreakglassSessionService.requestSession", e, "Failed to create session request");
      throw e;
    }
  }

  public async getSessionStatus(request: BreakglassSessionRequest) {
    // RESTful: GET /breakglassSessions?user=...&cluster=...&group=...&name=...
    // backend doesn't implement an `activeOnly` query parameter; filtering is done client-side
    try {
      const params: Record<string, any> = {};
      if (request.user && request.user !== "") params.user = request.user;
      if (request.cluster && request.cluster !== "") params.cluster = request.cluster;
      if (request.group && request.group !== "") params.group = request.group;
      if (request.name && request.name !== "") params.name = request.name;
      // Default client-side policy: mine defaults to true, approver defaults to false
      params.mine = request.mine === undefined ? true : request.mine;
      params.approver = request.approver === undefined ? false : request.approver;
      return await this.client.get("/breakglassSessions", { params });
    } catch (e) {
      handleAxiosError("BreakglassSessionService.getSessionStatus", e, "Failed to fetch session status");
      throw e;
    }
  }

  public async getClusterAccessReviews(): Promise<ClusterAccessReview[]> {
    try {
      const reviews = await this.client.get<ClusterAccessReview[]>('/reviews');
      return reviews.data;
    } catch (e) {
      handleAxiosError('BreakglassSessionService.getClusterAccessReviews', e, 'Failed to fetch cluster access reviews');
      return [];
    }
  }

  public async approveReview(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/approve
    if (!review.name) throw new Error('Missing session name for approve');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/approve`);
    } catch (e) {
      handleAxiosError('BreakglassSessionService.approveReview', e, 'Failed to approve session');
      throw e;
    }
  }

  public async rejectReview(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/reject
    if (!review.name) throw new Error('Missing session name for reject');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/reject`);
    } catch (e) {
      handleAxiosError('BreakglassSessionService.rejectReview', e, 'Failed to reject session');
      throw e;
    }
  }

  public async withdrawSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/withdraw
    if (!review.name) throw new Error('Missing session name for withdraw');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/withdraw`, {});
    } catch (e) {
      handleAxiosError('BreakglassSessionService.withdrawSession', e, 'Failed to withdraw session');
      throw e;
    }
  }

  public async dropSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/drop
    if (!review.name) throw new Error('Missing session name for drop');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/drop`, {});
    } catch (e) {
      handleAxiosError('BreakglassSessionService.dropSession', e, 'Failed to drop session');
      throw e;
    }
  }

  public async cancelSession(review: BreakglassSessionRequest) {
    // RESTful: POST /breakglassSessions/:name/cancel (approver cancels running session)
    if (!review.name) throw new Error('Missing session name for cancel');
    try {
      return await this.client.post(`/breakglassSessions/${encodeURIComponent(review.name)}/cancel`, {});
    } catch (e) {
      handleAxiosError('BreakglassSessionService.cancelSession', e, 'Failed to cancel session');
      throw e;
    }
  }
}
