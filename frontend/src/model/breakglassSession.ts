export interface BreakglassSessionRequest {
  clustername?: string;
  username?: string;
  clustergroup?: string;
  uname?: string;
  activeOnly?: boolean;
}

export interface BreakglassSessionResponse {
  clustername?: string;
  username?: string;
  clustergroup?: string;
  uname?: string;
}
