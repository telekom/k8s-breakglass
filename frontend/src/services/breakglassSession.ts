
import axios, { type AxiosResponse, AxiosHeaders } from "axios";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";
import cluster from "cluster";

export default class BreakglassSessionService {
  private client = axios.create({
    baseURL: "/api/breakglassSession/",
  });
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;

    this.client.interceptors.request.use(async (req) => {
      if (!req.headers) {
        req.headers = {} as AxiosHeaders;
      }
      req.headers["Authorization"] = `Bearer ${await this.auth.getAccessToken()}`;
      return req;
    });
  }

  public async requestSession(request: BreakglassSessionRequest) {
    return await this.client.post("/request", request)
  }

  public async checkSessionStatus(request: BreakglassSessionRequest) {
    return await this.client.get("/status", {
      params: {
        username: request.username,
        clustername: request.clustername,
        groupname: request.clustergroup,
      }
    })
  }

  public async getClusterAccessReviews(): Promise<ClusterAccessReview[]> {
    const reviews = await this.client.get<ClusterAccessReview[]>("/reviews")
    return reviews.data
  }

  public async approveReview(review: ClusterAccessReview) {
    return await this.client.post("/accept/" + review.name)
  }

  public async rejectReview(review: ClusterAccessReview) {
    return await this.client.post("/reject/" + review.name)
  }

  // public async getBreakglasses(): Promise<Breakglass[]> {
  //   const available = await this.getAvailableBreakglass();
  //   const active = await this.getActiveBreakglass();
  //
  //   return available.data.map((available) => {
  //     const bg = available as Breakglass;
  //     const actBg = active.data.find((active) => active.group == bg.to);
  //     if (actBg) {
  //       bg.expiry = actBg.expiry;
  //     }
  //     return bg;
  //   });
  // }
  //
  // public async requestBreakglass(transition: Breakglass): Promise<AxiosResponse> {
  //   return this.client.post("/request", {
  //     transition,
  //   });
  // }
  //
  // public async validateBreakglassRequest(token: string): Promise<AxiosResponse> {
  //   return this.client.get("/request", {
  //     params: {
  //       token,
  //     },
  //   });
  // }
  //
  // public async approveBreakglass(token: string): Promise<AxiosResponse> {
  //   return this.client.post("/approve", {
  //     token,
  //   });
  // }

  // public async dropBreakglass(breakglass: Breakglass): Promise<AxiosResponse> {
  //   return this.client.delete("/drop", {
  //     params: {
  //       group: breakglass.to,
  //     },
  //   });
  // }
}
