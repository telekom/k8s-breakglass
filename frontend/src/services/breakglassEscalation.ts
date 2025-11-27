import type { AxiosInstance } from "axios";
import { pushError } from "@/services/errors";

import type AuthService from "@/services/auth";
import { createAuthenticatedApiClient } from "@/services/httpClient";

export default class BreakglassEscalationService {
  private client: AxiosInstance;
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;
    this.client = createAuthenticatedApiClient(this.auth);

    this.client.interceptors.response.use(
      (resp) => resp,
      (error) => {
        const r = error?.response;
        const cid = r?.data?.cid || r?.headers?.["x-request-id"];
        const msg = r?.data?.error || r?.data || error.message || "Request failed";
        pushError(String(msg), r?.status, cid);
        return Promise.reject(error);
      },
    );
  }

  public async getEscalations() {
    return await this.client.get("/breakglassEscalations", {});
  }
}
