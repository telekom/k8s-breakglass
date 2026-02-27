import type { SessionCR } from "@/model/breakglass";

function normalizeEmail(value?: string | null): string | null {
  if (!value || typeof value !== "string") return null;
  return value.trim().toLowerCase();
}

export function wasApprovedBy(session: SessionCR, email?: string | null): boolean {
  const normalized = normalizeEmail(email);
  if (!session || !normalized) return false;

  const status = session.status || {};
  const direct = normalizeEmail(status.approver as string | undefined);
  if (direct && direct === normalized) {
    return true;
  }

  if (Array.isArray(status.approvers)) {
    const match = (status.approvers as unknown[]).some(
      (item: unknown) => normalizeEmail(item as string) === normalized,
    );
    if (match) return true;
  }

  if (Array.isArray(status.conditions)) {
    const conditionMatch = (status.conditions as Record<string, unknown>[]).some(
      (condition: Record<string, unknown>) => {
        if (typeof condition?.message !== "string") return false;
        return condition.message.toLowerCase().includes(normalized);
      },
    );
    if (conditionMatch) return true;
  }

  return false;
}

export function describeApprover(session: SessionCR): string {
  const status = session.status || {};
  if (typeof status.approver === "string") {
    return status.approver;
  }
  const approvers = status.approvers as unknown[] | undefined;
  if (Array.isArray(approvers) && approvers.length > 0) {
    return approvers[approvers.length - 1] as string;
  }
  return "-";
}
