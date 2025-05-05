export interface BreakglassEscalationSpec {
  cluster: string;
  username: string;
  escalatedGroup: string;
  allowedGroups: Array<string>;
  allowed: BreakglassEscalationAllowed;
  approvers: BreakglassEscalationApprovers;
}

interface BreakglassEscalationApprovers {
  users: Array<string>;
  groups: Array<string>;
}

interface BreakglassEscalationAllowed {
  clusters: Array<string>;
  groups: Array<string>;
  users: Array<string>;
}
