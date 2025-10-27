export interface BreakglassSessionRequest {
  cluster?: string;
  user?: string;
  group?: string;
  name?: string;
  activeOnly?: boolean;
  mine?: boolean;
  approver?: boolean;
}

export interface BreakglassSessionResponse {
  cluster?: string;
  user?: string;
  group?: string;
  name?: string;
}
