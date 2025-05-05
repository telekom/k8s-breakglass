
import axios, { type AxiosResponse, AxiosHeaders } from "axios";

import type AuthService from "@/services/auth";
import type { ClusterAccessReview } from "@/model/cluster_access";
import type { BreakglassSessionRequest } from "@/model/breakglassSession";

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

  public async getSessionStatus(request: BreakglassSessionRequest) {
    return await this.client.get("/status", {
      params: {
        username: request.username,
        clustername: request.clustername,
        groupname: request.clustergroup,
        uname: request.uname,
      }
    })
  }

  public async getClusterAccessReviews(): Promise<ClusterAccessReview[]> {
    const reviews = await this.client.get<ClusterAccessReview[]>("/reviews")
    return reviews.data
  }

  public async approveReview(review: BreakglassSessionRequest) {
    return await this.client.post("/approve/" + review.uname)
  }

  public async rejectReview(review: BreakglassSessionRequest) {
    return await this.client.post("/reject/" + review.uname)
  }
}
