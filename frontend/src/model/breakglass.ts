// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

export interface Breakglass extends AvailableBreakglass, ActiveBreakglass {}

export interface AvailableBreakglass {
  from: string;            // source role/group user has (base role for escalation)
  cluster: string;         // cluster name escalation applies to
  to: string;              // escalated (granted) group
  duration: number;        // seconds
  selfApproval: boolean;   // true if no approvers defined
  approvalGroups: string[];// approver groups (if any)
  // optional reason configuration shown to requesters
  requestReason?: { mandatory?: boolean; description?: string };
  // optional reason configuration shown to approvers
  approvalReason?: { mandatory?: boolean; description?: string };
}

export interface ActiveBreakglass {
  group: string;           // active session granted group (mirror of 'to')
  expiry: number;          // unix epoch seconds (0 if inactive)
  cluster: string;         // cluster name the active session applies to
  state: string;           // session state (e.g., Active, Available, etc.)
  // optional full session objects for more advanced UI actions
  sessionActive?: SessionCR;
  sessionPending?: SessionCR;
  // optional metadata for normalized historical/approved shapes
  name?: string;
  metadata?: SessionMetadata;
  spec?: SessionSpec;
  status?: SessionStatus;
  started?: string;
  ended?: string;
  reasonEnded?: string;
}

export interface SessionMetadata {
  name?: string;
  creationTimestamp?: string;
  [key: string]: any;
}

export interface SessionSpec {
  grantedGroup?: string;
  cluster?: string;
  user?: string;
  denyPolicyRefs?: string[];
  [key: string]: any;
}

export interface SessionStatus {
  approvedAt?: string;
  rejectedAt?: string;
  expiresAt?: string;
  timeoutAt?: string;
  retainedUntil?: string;
  state?: string;
  approver?: string;
  approvers?: string[];
  reasonEnded?: string;
  [key: string]: any;
}

export interface SessionCR {
  name?: string;
  metadata?: SessionMetadata;
  spec?: SessionSpec;
  status?: SessionStatus;
  // convenience fields sometimes present in older payloads
  group?: string;
  cluster?: string;
  expiry?: number;
}
