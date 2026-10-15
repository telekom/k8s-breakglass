import type { SessionCR } from "@/model/breakglass";

export function decideRejectOrWithdraw(currentUserEmail: string | undefined, bg?: SessionCR): "withdraw" | "reject" {
  if (!bg) return "reject";
  if (typeof bg.isRequester === "boolean") {
    return bg.isRequester ? "withdraw" : "reject";
  }
  if (typeof bg.approvalMeta?.isRequester === "boolean") {
    return bg.approvalMeta.isRequester ? "withdraw" : "reject";
  }
  const requesterEmail = bg.spec?.requesterEmail;
  if (currentUserEmail && requesterEmail) {
    return currentUserEmail === requesterEmail ? "withdraw" : "reject";
  }
  const owner = bg?.spec?.user || bg?.spec?.username || bg?.spec?.requester || "";
  if (currentUserEmail && owner && currentUserEmail === owner) return "withdraw";
  return "reject";
}
