export interface BreakglassSessionRequest {
  cluster?: string;
  user?: string;
  group?: string;
  name?: string;
  activeOnly?: boolean;
  mine?: boolean;
  approver?: boolean;
  reason?: string;
  scheduledStartTime?: string; // ISO 8601 date-time, e.g., "2024-01-20T15:30:00Z"
}

export interface BreakglassSessionResponse {
  cluster?: string;
  user?: string;
  group?: string;
  name?: string;
}
