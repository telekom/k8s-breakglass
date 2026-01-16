// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

export { config, getConfig, rewriteToFrontendUrl, rewriteUrlOrigin, type E2EConfig } from "./config";
export { AuthHelper, TEST_USERS, type TestUser, type TestUsers } from "./auth";
export { MailHogClient, type MailHogMessage, type MailHogAddress } from "./mailhog";
export { NavigationHelper, WaitHelper } from "./navigation";
export {
  ScaleComponentHelper,
  fillScaleTextarea,
  fillScaleInput,
  fillScaleTextField,
  waitForScaleToast,
  hasScaleToast,
  findAvailableEscalationCard,
  findEscalationCardByName,
  getAvailableEscalationCards,
  openScaleDropdown,
  selectScaleDropdownOption,
  waitForScaleModal,
  assertScaleDropdownOptionAvailable,
} from "./scale-components";
export { APICleanupHelper, cleanupPendingSessions } from "./api-cleanup";
export {
  setupPageDebugListeners,
  logAuthState,
  logPageState,
  waitForWithLogging,
  diagnosticScreenshot,
  logApiResponse,
} from "./debug";
