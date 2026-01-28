// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E Test Configuration
 *
 * Centralized configuration for E2E tests with environment variable support
 * and sensible defaults for local development.
 *
 * Environment variables:
 * - BREAKGLASS_UI_URL: Frontend dev server URL (default: http://localhost:5173)
 * - BREAKGLASS_API_URL: Backend API URL (default: http://localhost:8080)
 * - MAILHOG_URL: MailHog server URL (default: http://localhost:8025)
 * - KEYCLOAK_URL: Keycloak server URL (default: http://localhost:8081)
 */

export interface E2EConfig {
  /** Frontend dev server URL (Vite) */
  frontendUrl: string;
  /** Backend API URL */
  backendUrl: string;
  /** MailHog server URL */
  mailhogUrl: string;
  /** Keycloak server URL */
  keycloakUrl: string;
}

/**
 * Default configuration values for local development.
 *
 * NOTE: For e2e tests running against the backend-served UI (not Vite dev server),
 * frontendUrl should match backendUrl since the backend serves both API and UI.
 * The Vite dev server (5173) is only used for local development, not e2e tests.
 */
const DEFAULTS: E2EConfig = {
  frontendUrl: "http://localhost:8080", // Backend serves the frontend in e2e mode
  backendUrl: "http://localhost:8080",
  mailhogUrl: "http://localhost:8025",
  keycloakUrl: "http://localhost:8081",
};

/**
 * Get the E2E test configuration from environment variables with defaults.
 */
export function getConfig(): E2EConfig {
  return {
    frontendUrl: process.env.BREAKGLASS_UI_URL || DEFAULTS.frontendUrl,
    backendUrl: process.env.BREAKGLASS_API_URL || DEFAULTS.backendUrl,
    mailhogUrl: process.env.MAILHOG_URL || DEFAULTS.mailhogUrl,
    keycloakUrl: process.env.KEYCLOAK_URL || DEFAULTS.keycloakUrl,
  };
}

/**
 * Singleton instance of the config for convenient access.
 */
export const config = getConfig();

/**
 * Rewrite a URL from one origin to another.
 * Useful for converting backend URLs in emails to frontend URLs for navigation.
 *
 * @param url - The URL to rewrite
 * @param fromUrl - The origin to replace (e.g., backend URL)
 * @param toUrl - The origin to use instead (e.g., frontend URL)
 * @returns The rewritten URL
 */
export function rewriteUrlOrigin(url: string, fromUrl: string, toUrl: string): string {
  // Extract just the origin (protocol + host + port) from the URLs
  const fromOrigin = new URL(fromUrl).origin;
  const toOrigin = new URL(toUrl).origin;
  return url.replace(new RegExp(escapeRegExp(fromOrigin), "g"), toOrigin);
}

/**
 * Rewrite a backend URL to the frontend URL using the current configuration.
 * This is the most common use case - email links contain backend URLs but
 * we need to navigate to frontend URLs to preserve OIDC session.
 *
 * @param url - The backend URL to rewrite
 * @returns The URL rewritten to use the frontend origin
 */
export function rewriteToFrontendUrl(url: string): string {
  return rewriteUrlOrigin(url, config.backendUrl, config.frontendUrl);
}

/**
 * Escape special regex characters in a string.
 */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
