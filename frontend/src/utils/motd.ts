// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

import type { DebugSession, DebugPodInfo } from "@/model/debugSession";
import type { MessageOfTheDay } from "@/model/motd";

/** A binding motd replaces the template motd, matching the controller. */
export function effectiveSessionMotd(session?: DebugSession | null): MessageOfTheDay | undefined {
  const status = session?.status;
  return status?.resolvedBindingSpec?.motd || status?.resolvedTemplate?.motd || undefined;
}

/**
 * kubectl exec command for a debug pod. With a motd, the shell first prints the
 * BREAKGLASS_MOTD and BREAKGLASS_RUNBOOK_URL values the controller exported.
 */
export function debugPodExecCommand(pod: Pick<DebugPodInfo, "name" | "namespace">, withMotd = false): string {
  const base = `kubectl exec -it ${pod.name} -n ${pod.namespace} -- /bin/sh`;
  if (!withMotd) {
    return base;
  }
  const banner =
    'printf "%s\\n" "$BREAKGLASS_MOTD"; [ -z "$BREAKGLASS_RUNBOOK_URL" ] || printf "Runbook: %s\\n" "$BREAKGLASS_RUNBOOK_URL"; echo; exec /bin/sh';
  return `${base} -c '${banner}'`;
}
