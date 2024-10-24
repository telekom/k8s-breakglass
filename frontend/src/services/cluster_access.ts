
import axios, { type AxiosResponse } from "axios";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";

export default class ClusterAccessService {
  private client = axios.create({
    baseURL: "/api/breakglass/cluster_access",
  });
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;

    this.client.interceptors.request.use(async (req) => {
      if (!req.headers) {
        req.headers = {};
      }
      req.headers["Authorization"] = `Bearer ${await this.auth.getAccessToken()}`;
      return req;
    });
  }

  public async getClusterAccessReviews(): Promise<ClusterAccessReview[]> {
    const reviews = await this.client.get<ClusterAccessReview[]>("/reviews")
    return reviews.data
  }

  public async approveReview(review: ClusterAccessReview) {
    return await this.client.post("/accept/"+review.id)
  }

  public async rejectReview(review: ClusterAccessReview) {
    return await this.client.post("/reject/"+review.id)
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
