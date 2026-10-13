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
 * kubectl exec command for a debug pod. The controller mounts a shell hook, so
 * the interactive shell itself prints the session motd on start.
 */
export function debugPodExecCommand(pod: Pick<DebugPodInfo, "name" | "namespace">): string {
  return `kubectl exec -it ${pod.name} -n ${pod.namespace} -- /bin/sh`;
}
