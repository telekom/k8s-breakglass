import type { SessionCR } from "@/model/breakglass";

function normalizeEmail(value?: string | null): string | null {
  if (!value || typeof value !== "string") return null;
  return value.trim().toLowerCase();
}

export function wasApprovedBy(session: SessionCR, email?: string | null): boolean {
  const normalized = normalizeEmail(email);
  if (!session || !normalized) return false;

  const status = session.status || {};
  const direct = normalizeEmail((status as any).approver);
  if (direct && direct === normalized) {
    return true;
  }

  if (Array.isArray((status as any).approvers)) {
    const match = (status as any).approvers.some((item: unknown) => normalizeEmail(item as string) === normalized);
    if (match) return true;
  }

  if (Array.isArray((status as any).conditions)) {
    const conditionMatch = (status as any).conditions.some((condition: Record<string, unknown>) => {
      if (typeof condition?.message !== "string") return false;
      return condition.message.toLowerCase().includes(normalized);
    });
    if (conditionMatch) return true;
  }

  return false;
}

export function describeApprover(session: SessionCR): string {
  const status = session.status || {};
  if (typeof (status as any).approver === "string") {
    return (status as any).approver;
  }
  if (Array.isArray((status as any).approvers) && (status as any).approvers.length > 0) {
    return (status as any).approvers[(status as any).approvers.length - 1] as string;
  }
  return "-";
}
