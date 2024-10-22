import axios, { type AxiosResponse } from "axios";

import type AuthService from "@/services/auth";
import type { ActiveBreakglass, AvailableBreakglass, Breakglass } from "@/model/breakglass";

export default class BreakglassService {
  private client = axios.create({
    baseURL: "/api/breakglass",
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

  public async getActiveBreakglass() {
    return this.client.get<ActiveBreakglass[]>("/");
  }

  public async getAvailableBreakglass() {
    return this.client.get<AvailableBreakglass[]>("/available");
  }

  public async getBreakglasses(): Promise<Breakglass[]> {
    const available = await this.getAvailableBreakglass();
    const active = await this.getActiveBreakglass();

    return available.data.map((available) => {
      const bg = available as Breakglass;
      const actBg = active.data.find((active) => active.group == bg.to);
      if (actBg) {
        bg.expiry = actBg.expiry;
      }
      return bg;
    });
  }

  public async requestBreakglass(transition: Breakglass): Promise<AxiosResponse> {
    return this.client.post("/request", {
      transition,
    });
  }

  public async validateBreakglassRequest(token: string): Promise<AxiosResponse> {
    return this.client.get("/request", {
      params: {
        token,
      },
    });
  }

  public async approveBreakglass(token: string): Promise<AxiosResponse> {
    return this.client.post("/approve", {
      token,
    });
  }

  public async testButton(user_name: string, cluster_name: string): Promise<AxiosResponse> {
    return this.client.post("/test", {
        user_name: user_name,
        cluster_name: cluster_name,
    });
  }

  public async dropBreakglass(breakglass: Breakglass): Promise<AxiosResponse> {
    return this.client.delete("/drop", {
      params: {
        group: breakglass.to,
      },
    });
  }
}
