// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import type { SessionCR } from '@/model/breakglass';

export function decideRejectOrWithdraw(currentUserEmail: string | undefined, bg?: SessionCR): 'withdraw' | 'reject' {
  if (!bg) return 'reject';
  const owner = bg?.spec?.user || bg?.spec?.username || bg?.spec?.requester || '';
  if (currentUserEmail && owner && currentUserEmail === owner) return 'withdraw';
  return 'reject';
}
