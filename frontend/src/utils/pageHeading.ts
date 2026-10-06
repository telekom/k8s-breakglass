// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Visible page heading inside the main region. The app shell renders a
 * screen-reader-only brand `<h1>` first; focusing it would leave keyboard users
 * on an invisible element without a focus indicator.
 */
export const PAGE_HEADING_SELECTOR = "#main h1:not(.sr-only), #main h2:not(.sr-only)";
