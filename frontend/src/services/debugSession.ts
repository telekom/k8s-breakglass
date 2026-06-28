import type { AxiosInstance } from "axios";
import { handleAxiosError } from "@/services/logger";
import { createAuthenticatedApiClient } from "@/services/httpClient";

import type AuthService from "@/services/auth";
import type {
  DebugSession,
  DebugSessionSummary,
  DebugSessionDetailResponse,
  DebugSessionListResponse,
  DebugSessionTemplateListResponse,
  DebugPodTemplateListResponse,
  DebugSessionTemplateResponse,
  DebugPodTemplateResponse,
  CreateDebugSessionRequest,
  RenewDebugSessionRequest,
  ApproveDebugSessionRequest,
  RejectDebugSessionRequest,
  DebugSessionSearchParams,
  InjectEphemeralContainerRequest,
  InjectEphemeralContainerResponse,
  CreatePodCopyRequest,
  CreatePodCopyResponse,
  CreateNodeDebugPodRequest,
  CreateNodeDebugPodResponse,
  TemplateClustersResponse,
} from "@/model/debugSession";

function normalizeDebugSessionListResponse(value: unknown): DebugSessionListResponse {
  if (Array.isArray(value)) {
    return { sessions: value as DebugSessionSummary[], total: value.length };
  }

  if (!value || typeof value !== "object") {
    return { sessions: [], total: 0 };
  }

  const response = value as Partial<DebugSessionListResponse>;
  const sessions = Array.isArray(response.sessions) ? response.sessions : [];
  return {
    sessions,
    total: typeof response.total === "number" ? response.total : sessions.length,
  };
}

export default class DebugSessionService {
  private client: AxiosInstance;
  private auth: AuthService;

  constructor(auth: AuthService) {
    this.auth = auth;
    this.client = createAuthenticatedApiClient(this.auth, { enableDevTokenLogging: true });
    // Note: Error handling is done in individual methods to provide context-specific messages.
    // Do NOT add a response interceptor that calls handleAxiosError here, as it would cause
    // duplicate error toasts (interceptor + method catch block + component catch block).
  }

  /**
   * List debug sessions with optional filters
   */
  public async listSessions(params?: DebugSessionSearchParams): Promise<DebugSessionListResponse> {
    try {
      const queryParams: Record<string, string | boolean> = {};
      if (params?.cluster) queryParams.cluster = params.cluster;
      if (params?.state) queryParams.state = params.state;
      if (params?.user) queryParams.user = params.user;
      if (params?.mine !== undefined) queryParams.mine = params.mine;

      const response = await this.client.get<unknown>("/debugSessions", { params: queryParams });
      return normalizeDebugSessionListResponse(response.data);
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
  public async createSession(request: CreateDebugSessionRequest): Promise<DebugSessionDetailResponse> {
    try {
      const response = await this.client.post<DebugSessionDetailResponse>("/debugSessions", request);
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.createSession", e, "Failed to create debug session");
      throw e;
    }
  }

  private async postSessionAction(
    name: string,
    action: string,
    errorMessage: string,
    body?: unknown,
  ): Promise<DebugSession> {
    try {
      const endpoint = `/debugSessions/${encodeURIComponent(name)}/${action}`;
      const response =
        body === undefined
          ? await this.client.post<DebugSession>(endpoint)
          : await this.client.post<DebugSession>(endpoint, body);
      return response.data;
    } catch (e) {
      handleAxiosError(`DebugSessionService.${action}Session`, e, errorMessage);
      throw e;
    }
  }

  public async joinSession(name: string): Promise<DebugSession> {
    return this.postSessionAction(name, "join", "Failed to join debug session");
  }

  public async leaveSession(name: string): Promise<DebugSession> {
    return this.postSessionAction(name, "leave", "Failed to leave debug session");
  }

  public async renewSession(name: string, request: RenewDebugSessionRequest): Promise<DebugSession> {
    return this.postSessionAction(name, "renew", "Failed to renew debug session", request);
  }

  public async terminateSession(name: string): Promise<DebugSession> {
    return this.postSessionAction(name, "terminate", "Failed to terminate debug session");
  }

  public async approveSession(name: string, request?: ApproveDebugSessionRequest): Promise<DebugSession> {
    return this.postSessionAction(name, "approve", "Failed to approve debug session", request || {});
  }

  public async rejectSession(name: string, request: RejectDebugSessionRequest): Promise<DebugSession> {
    return this.postSessionAction(name, "reject", "Failed to reject debug session", request);
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
   * Get available clusters for a template with resolved constraints.
   * Returns detailed cluster information including bindings, constraints, and availability.
   */
  public async getTemplateClusters(templateName: string): Promise<TemplateClustersResponse> {
    try {
      const response = await this.client.get<TemplateClustersResponse>(
        `/debugSessions/templates/${encodeURIComponent(templateName)}/clusters`,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.getTemplateClusters", e, "Failed to get template clusters");
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

  // ==========================================================================
  // Kubectl-Debug Operations
  // ==========================================================================

  /**
   * Inject an ephemeral container into a target pod for debugging
   * Requires kubectl-debug or hybrid mode session
   */
  public async injectEphemeralContainer(
    sessionName: string,
    request: InjectEphemeralContainerRequest,
  ): Promise<InjectEphemeralContainerResponse> {
    try {
      const response = await this.client.post<InjectEphemeralContainerResponse>(
        `/debugSessions/${encodeURIComponent(sessionName)}/injectEphemeralContainer`,
        request,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.injectEphemeralContainer", e, "Failed to inject ephemeral container");
      throw e;
    }
  }

  /**
   * Create a copy of a pod for debugging (modifies the copy, not original)
   * Requires kubectl-debug or hybrid mode session
   */
  public async createPodCopy(sessionName: string, request: CreatePodCopyRequest): Promise<CreatePodCopyResponse> {
    try {
      const response = await this.client.post<CreatePodCopyResponse>(
        `/debugSessions/${encodeURIComponent(sessionName)}/createPodCopy`,
        request,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.createPodCopy", e, "Failed to create pod copy");
      throw e;
    }
  }

  /**
   * Create a privileged debug pod on a specific node
   * Requires kubectl-debug or hybrid mode session with nodeDebug enabled
   */
  public async createNodeDebugPod(
    sessionName: string,
    request: CreateNodeDebugPodRequest,
  ): Promise<CreateNodeDebugPodResponse> {
    try {
      const response = await this.client.post<CreateNodeDebugPodResponse>(
        `/debugSessions/${encodeURIComponent(sessionName)}/createNodeDebugPod`,
        request,
      );
      return response.data;
    } catch (e) {
      handleAxiosError("DebugSessionService.createNodeDebugPod", e, "Failed to create node debug pod");
      throw e;
    }
  }
}
