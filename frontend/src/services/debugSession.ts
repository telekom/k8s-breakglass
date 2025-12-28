import type { AxiosInstance } from "axios";
import { handleAxiosError } from "@/services/logger";
import { createAuthenticatedApiClient } from "@/services/httpClient";

import type AuthService from "@/services/auth";
import type {
  DebugSession,
  DebugSessionListResponse,
  DebugSessionTemplateListResponse,
  DebugPodTemplateListResponse,
  DebugSessionTemplateResponse,
  DebugPodTemplateResponse,
  CreateDebugSessionRequest,
  JoinDebugSessionRequest,
  RenewDebugSessionRequest,
  ApproveDebugSessionRequest,
  RejectDebugSessionRequest,
  DebugSessionSearchParams,
} from "@/model/debugSession";

export default class DebugSessionService {
  private client: AxiosInstance;
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;
    this.client = createAuthenticatedApiClient(this.auth, { enableDevTokenLogging: true });

    this.client.interceptors.response.use(
      (resp) => resp,
      (error) => {
        handleAxiosError("DebugSessionService", error);
        return Promise.reject(error);
      },
    );
  }

  /**
   * List debug sessions with optional filters
   */
  public async listSessions(params?: DebugSessionSearchParams): Promise<DebugSessionListResponse> {
    try {
      const queryParams: Record<string, any> = {};
      if (params?.cluster) queryParams.cluster = params.cluster;
      if (params?.state) queryParams.state = params.state;
      if (params?.user) queryParams.user = params.user;
      if (params?.mine !== undefined) queryParams.mine = params.mine;

      const response = await this.client.get<DebugSessionListResponse>("/debugSessions", { params: queryParams });
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.listSessions", e, "Failed to list debug sessions");
      throw e;
    }
  }

  /**
   * Get a single debug session by name
   */
  public async getSession(name: string): Promise<DebugSession> {
    try {
      const response = await this.client.get<DebugSession>(`/debugSessions/${encodeURIComponent(name)}`);
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.getSession", e, "Failed to get debug session");
      throw e;
    }
  }

  /**
   * Create a new debug session
   */
  public async createSession(request: CreateDebugSessionRequest): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>("/debugSessions", request);
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.createSession", e, "Failed to create debug session");
      throw e;
    }
  }

  /**
   * Join an existing debug session
   */
  public async joinSession(name: string, request?: JoinDebugSessionRequest): Promise<DebugSession> {
    try {
      const body = request || { role: "viewer" };
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/join`,
        body,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.joinSession", e, "Failed to join debug session");
      throw e;
    }
  }

  /**
   * Leave a debug session (participants only, not owner)
   */
  public async leaveSession(name: string): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/leave`,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.leaveSession", e, "Failed to leave debug session");
      throw e;
    }
  }

  /**
   * Renew a debug session (extend duration)
   */
  public async renewSession(name: string, request: RenewDebugSessionRequest): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/renew`,
        request,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.renewSession", e, "Failed to renew debug session");
      throw e;
    }
  }

  /**
   * Terminate a debug session (owner only)
   */
  public async terminateSession(name: string): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/terminate`,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.terminateSession", e, "Failed to terminate debug session");
      throw e;
    }
  }

  /**
   * Approve a debug session in PendingApproval state
   */
  public async approveSession(name: string, request?: ApproveDebugSessionRequest): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/approve`,
        request || {},
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.approveSession", e, "Failed to approve debug session");
      throw e;
    }
  }

  /**
   * Reject a debug session in PendingApproval state
   */
  public async rejectSession(name: string, request: RejectDebugSessionRequest): Promise<DebugSession> {
    try {
      const response = await this.client.post<DebugSession>(
        `/debugSessions/${encodeURIComponent(name)}/reject`,
        request,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.rejectSession", e, "Failed to reject debug session");
      throw e;
    }
  }

  /**
   * List available debug session templates
   */
  public async listTemplates(): Promise<DebugSessionTemplateListResponse> {
    try {
      const response = await this.client.get<DebugSessionTemplateListResponse>("/debugSessions/templates");
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.listTemplates", e, "Failed to list debug session templates");
      throw e;
    }
  }

  /**
   * Get a specific debug session template
   */
  public async getTemplate(name: string): Promise<DebugSessionTemplateResponse> {
    try {
      const response = await this.client.get<DebugSessionTemplateResponse>(
        `/debugSessions/templates/${encodeURIComponent(name)}`,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.getTemplate", e, "Failed to get debug session template");
      throw e;
    }
  }

  /**
   * List available debug pod templates
   */
  public async listPodTemplates(): Promise<DebugPodTemplateListResponse> {
    try {
      const response = await this.client.get<DebugPodTemplateListResponse>("/debugSessions/podTemplates");
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.listPodTemplates", e, "Failed to list debug pod templates");
      throw e;
    }
  }

  /**
   * Get a specific debug pod template
   */
  public async getPodTemplate(name: string): Promise<DebugPodTemplateResponse> {
    try {
      const response = await this.client.get<DebugPodTemplateResponse>(
        `/debugSessions/podTemplates/${encodeURIComponent(name)}`,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.getPodTemplate", e, "Failed to get debug pod template");
      throw e;
    }
  }
}
