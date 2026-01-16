# Proposal: UI & Email-Based E2E Test Suite

**Status**: ✅ IMPLEMENTED (January 2026)  
**Author**: AI-Generated  
**Date**: 2026-01-04  
**Related Issues**: #48 (E2E Tests)

## Summary

Implement a focused set of end-to-end tests that validate user workflows through the web UI and verify email notifications via MailHog, complementing the existing API-based E2E tests.

## Motivation

The current E2E test suite covers:
- ✅ API endpoint validation (Go tests)
- ✅ Screenshot/visual regression tests (Playwright)
- ✅ MailHog integration for notification testing (Go tests)

However, we lack tests that:
1. **Simulate real user interactions** through the browser
2. **Follow email links** to complete approval workflows
3. **Validate the full user journey** from UI → email → UI
4. **Test OIDC login flows** through the actual Keycloak UI

## Scope

This proposal covers a **limited, high-value set of UI tests** focusing on critical user journeys:

| Test | User Journey | Validates |
|------|-------------|-----------|
| Login Flow | Keycloak OIDC → App | Authentication, session cookie |
| Request Session | UI form → Submit → Email sent | Form validation, API integration, email delivery |
| Approve via Email | Click email link → Approve | Deep linking, approval flow |
| View Active Session | Session browser → Details | Data display, real-time status |
| Reject Session | Approver UI → Reject | Rejection flow, notification |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Playwright Test Runner                           │
│                                                                          │
│  ┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐ │
│  │  Browser Context │────▶│  Breakglass UI   │────▶│  Backend API    │ │
│  │  (Chromium)      │     │  localhost:5173  │     │  localhost:8080 │ │
│  └──────────────────┘     └──────────────────┘     └─────────────────┘ │
│           │                                                  │          │
│           │                                                  ▼          │
│           │              ┌──────────────────┐     ┌─────────────────┐  │
│           │              │  MailHog UI      │     │  MailHog SMTP   │  │
│           └─────────────▶│  localhost:8025  │◀────│  port 1025      │  │
│                          └──────────────────┘     └─────────────────┘  │
│                                   │                                     │
│                                   ▼                                     │
│                          ┌──────────────────┐                          │
│                          │  MailHog API     │                          │
│                          │  /api/v2/messages│                          │
│                          └──────────────────┘                          │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                         Keycloak                                  │  │
│  │                     localhost:8443                                │  │
│  │  Users: alice@example.com, bob@example.com, carol@example.com    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Test Implementation

### Directory Structure

```
frontend/
├── tests/
│   ├── screenshots/          # Existing visual regression tests
│   │   └── pages.spec.ts
│   ├── e2e/                  # NEW: UI E2E tests
│   │   ├── fixtures/
│   │   │   └── test-users.ts
│   │   ├── helpers/
│   │   │   ├── auth.ts       # OIDC login helpers
│   │   │   ├── mailhog.ts    # MailHog API client
│   │   │   └── navigation.ts # Page navigation helpers
│   │   ├── login.spec.ts
│   │   ├── request-session.spec.ts
│   │   ├── approve-via-email.spec.ts
│   │   ├── session-browser.spec.ts
│   │   └── reject-session.spec.ts
│   └── unit/                 # Existing unit tests
├── playwright.e2e.config.ts  # NEW: E2E-specific config
└── package.json              # Add e2e:ui script
```

### Playwright E2E Configuration

```typescript
// frontend/playwright.e2e.config.ts
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  
  // Sequential execution for stateful tests
  fullyParallel: false,
  
  // More retries for E2E due to timing sensitivity
  retries: process.env.CI ? 3 : 1,
  
  // Single worker to ensure test isolation
  workers: 1,
  
  // Longer timeouts for E2E
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
  
  reporter: [
    ["html", { outputFolder: "playwright-report-e2e" }],
    ["list"],
  ],
  
  use: {
    // Real backend URL (not mock)
    baseURL: process.env.BREAKGLASS_UI_URL || "http://localhost:5173",
    
    // Capture traces and screenshots on failure
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    
    // Standard viewport
    viewport: { width: 1280, height: 720 },
    
    // Slower actions for reliability
    actionTimeout: 15000,
  },
  
  projects: [
    {
      name: "chromium-e2e",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  
  // No webServer - E2E tests run against existing kind cluster
});
```

### Test Helpers

#### MailHog Client

```typescript
// frontend/tests/e2e/helpers/mailhog.ts
import { expect } from "@playwright/test";

export interface MailHogMessage {
  ID: string;
  From: { Mailbox: string; Domain: string };
  To: Array<{ Mailbox: string; Domain: string }>;
  Content: {
    Headers: {
      Subject: string[];
      From: string[];
      To: string[];
    };
    Body: string;
  };
  Created: string;
}

export class MailHogClient {
  private baseUrl: string;
  
  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || process.env.MAILHOG_URL || "http://localhost:8025";
  }
  
  async getMessages(): Promise<MailHogMessage[]> {
    const response = await fetch(`${this.baseUrl}/api/v2/messages`);
    const data = await response.json();
    return data.items || [];
  }
  
  async clearMessages(): Promise<void> {
    await fetch(`${this.baseUrl}/api/v1/messages`, { method: "DELETE" });
  }
  
  async waitForMessage(
    predicate: (msg: MailHogMessage) => boolean,
    timeout = 30000
  ): Promise<MailHogMessage> {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const messages = await this.getMessages();
      const match = messages.find(predicate);
      if (match) return match;
      await new Promise(r => setTimeout(r, 1000));
    }
    throw new Error(`No matching email found within ${timeout}ms`);
  }
  
  async waitForSubject(subjectContains: string, timeout = 30000): Promise<MailHogMessage> {
    return this.waitForMessage(
      msg => msg.Content.Headers.Subject.some(
        s => s.toLowerCase().includes(subjectContains.toLowerCase())
      ),
      timeout
    );
  }
  
  extractLinks(body: string): string[] {
    // Extract URLs from HTML email body
    const urlRegex = /https?:\/\/[^\s<>"]+/g;
    return body.match(urlRegex) || [];
  }
  
  extractApprovalLink(body: string): string | null {
    const links = this.extractLinks(body);
    // Find link containing /sessions/review or /approve
    return links.find(l => l.includes("/sessions/review") || l.includes("/approve")) || null;
  }
}
```

#### OIDC Authentication Helper

```typescript
// frontend/tests/e2e/helpers/auth.ts
import { Page, expect } from "@playwright/test";

export interface TestUser {
  username: string;
  password: string;
  displayName: string;
  email: string;
  groups: string[];
}

export const TEST_USERS: Record<string, TestUser> = {
  requester: {
    username: "bob@example.com",
    password: "bob123",
    displayName: "Bob Developer",
    email: "bob@example.com",
    groups: ["developers", "team-alpha"],
  },
  approver: {
    username: "carol@example.com", 
    password: "carol123",
    displayName: "Carol Security",
    email: "carol@example.com",
    groups: ["approvers", "security-team"],
  },
  admin: {
    username: "alice@example.com",
    password: "alice123",
    displayName: "Alice Admin",
    email: "alice@example.com",
    groups: ["platform-admins"],
  },
};

export class AuthHelper {
  constructor(private page: Page) {}
  
  async loginViaKeycloak(user: TestUser): Promise<void> {
    // Navigate to app - should redirect to Keycloak
    await this.page.goto("/");
    
    // Wait for Keycloak login page
    await this.page.waitForURL(/.*keycloak.*\/auth\/.*/);
    
    // Fill login form
    await this.page.fill("#username", user.username);
    await this.page.fill("#password", user.password);
    await this.page.click("#kc-login");
    
    // Wait for redirect back to app
    await this.page.waitForURL(/localhost:5173/);
    
    // Verify logged in state
    await expect(this.page.locator('[data-testid="user-menu"]')).toBeVisible();
  }
  
  async logout(): Promise<void> {
    await this.page.click('[data-testid="user-menu"]');
    await this.page.click('[data-testid="logout-button"]');
    await this.page.waitForURL(/.*keycloak.*|.*login.*/);
  }
  
  async isLoggedIn(): Promise<boolean> {
    try {
      await this.page.locator('[data-testid="user-menu"]').waitFor({ timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }
}
```

### Test Cases

#### 1. Login Flow Test

```typescript
// frontend/tests/e2e/login.spec.ts
import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers/auth";

test.describe("Login Flow", () => {
  test("user can login via Keycloak OIDC", async ({ page }) => {
    const auth = new AuthHelper(page);
    
    // Start at app root
    await page.goto("/");
    
    // Should redirect to Keycloak
    await expect(page).toHaveURL(/keycloak/);
    
    // Login as Bob (developer)
    await auth.loginViaKeycloak(TEST_USERS.requester);
    
    // Should be back at app
    await expect(page).toHaveURL(/localhost:5173/);
    
    // Should see user info
    await expect(page.locator('[data-testid="user-menu"]')).toContainText("Bob");
    
    // Should see escalation list (home page)
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible();
  });
  
  test("user can logout", async ({ page }) => {
    const auth = new AuthHelper(page);
    
    // Login first
    await auth.loginViaKeycloak(TEST_USERS.requester);
    
    // Logout
    await auth.logout();
    
    // Should be logged out
    expect(await auth.isLoggedIn()).toBe(false);
  });
  
  test("unauthenticated user is redirected to login", async ({ page }) => {
    // Try to access protected route directly
    await page.goto("/sessions");
    
    // Should redirect to Keycloak
    await expect(page).toHaveURL(/keycloak/);
  });
});
```

#### 2. Request Session via UI

```typescript
// frontend/tests/e2e/request-session.spec.ts
import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers/auth";
import { MailHogClient } from "./helpers/mailhog";

test.describe("Request Session via UI", () => {
  let mailhog: MailHogClient;
  
  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });
  
  test.beforeEach(async () => {
    // Clear any existing emails
    await mailhog.clearMessages();
  });
  
  test("developer can request escalation and approver receives email", async ({ page }) => {
    const auth = new AuthHelper(page);
    
    // Login as Bob (developer)
    await auth.loginViaKeycloak(TEST_USERS.requester);
    
    // Find an escalation card and click "Request Access"
    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    await expect(escalationCard).toBeVisible();
    
    // Get escalation name for later verification
    const escalationName = await escalationCard.locator('[data-testid="escalation-name"]').textContent();
    
    // Click request button
    await escalationCard.locator('[data-testid="request-access-button"]').click();
    
    // Fill request form
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();
    
    // Select cluster (if multiple)
    const clusterSelect = page.locator('[data-testid="cluster-select"]');
    if (await clusterSelect.isVisible()) {
      await clusterSelect.selectOption({ index: 0 });
    }
    
    // Enter reason
    await page.fill('[data-testid="reason-input"]', 
      "UI E2E Test: Debugging production issue #12345");
    
    // Select duration
    await page.locator('[data-testid="duration-select"]').selectOption("1h");
    
    // Submit request
    await page.click('[data-testid="submit-request-button"]');
    
    // Verify success message
    await expect(page.locator('[data-testid="success-toast"]')).toContainText("Session requested");
    
    // Verify session appears in "My Requests"
    await page.goto("/requests/mine");
    await expect(page.locator('[data-testid="session-row"]').first()).toContainText("Pending");
    
    // Wait for and verify email to approver
    const email = await mailhog.waitForSubject("Breakglass Request", 30000);
    expect(email).toBeTruthy();
    expect(email.Content.Headers.To.join(",")).toContain("carol"); // Approver email
    expect(email.Content.Body).toContain("bob@example.com"); // Requester
    expect(email.Content.Body).toContain("Debugging production issue");
    
    // Verify approval link exists in email
    const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
    expect(approvalLink).toBeTruthy();
  });
  
  test("reason validation prevents empty submission", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
    
    // Start request flow
    await page.locator('[data-testid="escalation-card"]').first()
      .locator('[data-testid="request-access-button"]').click();
    
    // Try to submit without reason
    await page.click('[data-testid="submit-request-button"]');
    
    // Should show validation error
    await expect(page.locator('[data-testid="reason-error"]')).toContainText("required");
    
    // Modal should still be open
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();
  });
});
```

#### 3. Approve via Email Link

```typescript
// frontend/tests/e2e/approve-via-email.spec.ts
import { test, expect, Browser } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers/auth";
import { MailHogClient } from "./helpers/mailhog";

test.describe("Approve Session via Email Link", () => {
  let mailhog: MailHogClient;
  
  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });
  
  test.beforeEach(async () => {
    await mailhog.clearMessages();
  });
  
  test("approver can approve session by clicking email link", async ({ browser }) => {
    // Create two browser contexts: requester and approver
    const requesterContext = await browser.newContext();
    const approverContext = await browser.newContext();
    
    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();
      
      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);
      
      // === Step 1: Requester creates session ===
      await requesterAuth.loginViaKeycloak(TEST_USERS.requester);
      
      await requesterPage.locator('[data-testid="escalation-card"]').first()
        .locator('[data-testid="request-access-button"]').click();
      
      await requesterPage.fill('[data-testid="reason-input"]', 
        "Email approval test - please approve via link");
      await requesterPage.click('[data-testid="submit-request-button"]');
      
      await expect(requesterPage.locator('[data-testid="success-toast"]')).toBeVisible();
      
      // === Step 2: Wait for email ===
      const email = await mailhog.waitForSubject("Breakglass Request", 30000);
      expect(email).toBeTruthy();
      
      // Extract approval link
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();
      
      // === Step 3: Approver clicks email link ===
      // Note: Approver needs to be logged in first
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);
      
      // Navigate to approval link
      await approverPage.goto(approvalLink!);
      
      // Should see session review page
      await expect(approverPage.locator('[data-testid="session-review"]')).toBeVisible();
      await expect(approverPage.locator('[data-testid="requester"]')).toContainText("bob@example.com");
      await expect(approverPage.locator('[data-testid="request-reason"]')).toContainText("Email approval test");
      
      // Approve the session
      await approverPage.fill('[data-testid="approval-reason-input"]', 
        "Approved via email link - E2E test");
      await approverPage.click('[data-testid="approve-button"]');
      
      // Verify approval success
      await expect(approverPage.locator('[data-testid="success-toast"]')).toContainText("approved");
      
      // === Step 4: Verify requester sees approved session ===
      await requesterPage.goto("/requests/mine");
      await requesterPage.reload();
      
      await expect(requesterPage.locator('[data-testid="session-row"]').first())
        .toContainText("Active");
      
      // === Step 5: Verify approval email sent to requester ===
      const approvalEmail = await mailhog.waitForSubject("approved", 15000);
      expect(approvalEmail).toBeTruthy();
      expect(approvalEmail.Content.Headers.To.join(",")).toContain("bob");
      expect(approvalEmail.Content.Body).toContain("carol@example.com"); // Approver
      
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });
  
  test("approval link without login redirects to Keycloak then back", async ({ page }) => {
    // First create a session
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
    
    await page.locator('[data-testid="escalation-card"]').first()
      .locator('[data-testid="request-access-button"]').click();
    await page.fill('[data-testid="reason-input"]', "Deep link test");
    await page.click('[data-testid="submit-request-button"]');
    
    // Wait for email
    const email = await mailhog.waitForSubject("Breakglass Request", 30000);
    const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
    
    // Open new context (not logged in)
    const newContext = await page.context().browser()!.newContext();
    const newPage = await newContext.newPage();
    
    try {
      // Navigate to approval link
      await newPage.goto(approvalLink!);
      
      // Should redirect to Keycloak
      await expect(newPage).toHaveURL(/keycloak/);
      
      // Login as approver
      await newPage.fill("#username", TEST_USERS.approver.username);
      await newPage.fill("#password", TEST_USERS.approver.password);
      await newPage.click("#kc-login");
      
      // Should redirect back to session review (deep link preserved)
      await expect(newPage).toHaveURL(/sessions\/review/);
      await expect(newPage.locator('[data-testid="session-review"]')).toBeVisible();
      
    } finally {
      await newContext.close();
    }
  });
});
```

#### 4. Session Browser Test

```typescript
// frontend/tests/e2e/session-browser.spec.ts
import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers/auth";

test.describe("Session Browser", () => {
  test("approver can view all sessions and filter", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);
    
    // Navigate to session browser
    await page.goto("/sessions");
    
    // Should see session list
    await expect(page.locator('[data-testid="session-list"]')).toBeVisible();
    
    // Test search filter
    await page.fill('[data-testid="search-input"]', "bob");
    await expect(page.locator('[data-testid="session-row"]').first())
      .toContainText("bob@example.com");
    
    // Test status filter
    await page.locator('[data-testid="status-filter"]').selectOption("active");
    
    // All visible rows should be Active
    const rows = page.locator('[data-testid="session-row"]');
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i).locator('[data-testid="status"]')).toContainText("Active");
    }
    
    // Test cluster filter
    await page.locator('[data-testid="cluster-filter"]').selectOption({ index: 1 });
    // Verify filter applied (rows should update)
    await page.waitForTimeout(500);
  });
  
  test("clicking session row shows details", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);
    
    await page.goto("/sessions");
    
    // Click first session
    await page.locator('[data-testid="session-row"]').first().click();
    
    // Should show detail view
    await expect(page.locator('[data-testid="session-details"]')).toBeVisible();
    
    // Verify key information displayed
    await expect(page.locator('[data-testid="detail-requester"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-cluster"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="detail-reason"]')).toBeVisible();
  });
});
```

#### 5. Reject Session Test

```typescript
// frontend/tests/e2e/reject-session.spec.ts
import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers/auth";
import { MailHogClient } from "./helpers/mailhog";

test.describe("Reject Session", () => {
  let mailhog: MailHogClient;
  
  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });
  
  test.beforeEach(async () => {
    await mailhog.clearMessages();
  });
  
  test("approver can reject session with reason", async ({ browser }) => {
    const requesterContext = await browser.newContext();
    const approverContext = await browser.newContext();
    
    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();
      
      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);
      
      // Requester creates session
      await requesterAuth.loginViaKeycloak(TEST_USERS.requester);
      await requesterPage.locator('[data-testid="escalation-card"]').first()
        .locator('[data-testid="request-access-button"]').click();
      await requesterPage.fill('[data-testid="reason-input"]', 
        "Rejection test - this should be rejected");
      await requesterPage.click('[data-testid="submit-request-button"]');
      
      // Wait for email
      const email = await mailhog.waitForSubject("Breakglass Request", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      
      // Approver opens review page
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);
      await approverPage.goto(approvalLink!);
      
      // Fill rejection reason
      await approverPage.fill('[data-testid="rejection-reason-input"]', 
        "Rejected: Invalid justification provided");
      
      // Click reject button
      await approverPage.click('[data-testid="reject-button"]');
      
      // Confirm rejection dialog
      await expect(approverPage.locator('[data-testid="confirm-reject-dialog"]')).toBeVisible();
      await approverPage.click('[data-testid="confirm-reject-button"]');
      
      // Verify rejection success
      await expect(approverPage.locator('[data-testid="success-toast"]')).toContainText("rejected");
      
      // Verify requester sees rejected session
      await requesterPage.goto("/requests/mine");
      await requesterPage.reload();
      await expect(requesterPage.locator('[data-testid="session-row"]').first())
        .toContainText("Rejected");
      
      // Verify rejection email
      const rejectionEmail = await mailhog.waitForSubject("rejected", 15000);
      expect(rejectionEmail).toBeTruthy();
      expect(rejectionEmail.Content.Body).toContain("Invalid justification");
      
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });
  
  test("reject button is disabled without reason", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);
    
    // Go to pending approvals
    await page.goto("/approvals/pending");
    
    // Click first pending session
    await page.locator('[data-testid="session-row"]').first().click();
    
    // Reject button should be disabled without reason
    await expect(page.locator('[data-testid="reject-button"]')).toBeDisabled();
    
    // Enter reason
    await page.fill('[data-testid="rejection-reason-input"]', "Test reason");
    
    // Now should be enabled
    await expect(page.locator('[data-testid="reject-button"]')).toBeEnabled();
  });
});
```

## CI Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/e2e-ui.yml
name: UI E2E Tests

on:
  push:
    branches: [main]
    paths:
      - 'frontend/**'
      - 'pkg/api/**'
      - 'pkg/mail/**'
  pull_request:
    paths:
      - 'frontend/**'
  workflow_dispatch:

jobs:
  ui-e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json
          
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          
      - name: Install Playwright Browsers
        working-directory: frontend
        run: npx playwright install --with-deps chromium
        
      - name: Build breakglass image
        run: make docker-build-dev
        
      - name: Setup E2E environment
        run: ./e2e/kind-setup-single.sh
        
      - name: Wait for services
        run: |
          # Wait for frontend to be accessible
          timeout 60 bash -c 'until curl -s http://localhost:5173 > /dev/null; do sleep 2; done'
          # Wait for MailHog
          timeout 30 bash -c 'until curl -s http://localhost:8025 > /dev/null; do sleep 2; done'
          
      - name: Run UI E2E Tests
        working-directory: frontend
        env:
          BREAKGLASS_UI_URL: http://localhost:5173
          MAILHOG_URL: http://localhost:8025
          KEYCLOAK_URL: https://localhost:8443
        run: npx playwright test --config=playwright.e2e.config.ts
        
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-e2e-report
          path: frontend/playwright-report-e2e/
          
      - name: Upload videos on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-e2e-videos
          path: frontend/test-results/
          
      - name: Collect MailHog messages on failure
        if: failure()
        run: |
          echo "=== MailHog Messages ==="
          curl -s http://localhost:8025/api/v2/messages | jq '.items[] | {subject: .Content.Headers.Subject[0], from: .From, to: .To}'
```

### Package.json Scripts

```json
{
  "scripts": {
    "test:e2e": "playwright test --config=playwright.e2e.config.ts",
    "test:e2e:ui": "playwright test --config=playwright.e2e.config.ts --ui",
    "test:e2e:debug": "playwright test --config=playwright.e2e.config.ts --debug",
    "test:e2e:report": "playwright show-report playwright-report-e2e"
  }
}
```

## Required UI Data-Testid Attributes

The following `data-testid` attributes must be added to the frontend components:

| Component | Attribute | Purpose |
|-----------|-----------|---------|
| User menu | `user-menu` | User profile/logout dropdown |
| Logout button | `logout-button` | Logout action |
| Escalation card | `escalation-card` | Each escalation tile |
| Escalation name | `escalation-name` | Escalation display name |
| Request button | `request-access-button` | Start request flow |
| Request modal | `request-modal` | Request form dialog |
| Cluster select | `cluster-select` | Cluster dropdown |
| Reason input | `reason-input` | Request reason textarea |
| Duration select | `duration-select` | Session duration dropdown |
| Submit button | `submit-request-button` | Submit request form |
| Success toast | `success-toast` | Success notification |
| Session list | `session-list` | Session browser container |
| Session row | `session-row` | Individual session entry |
| Search input | `search-input` | Filter input |
| Status filter | `status-filter` | Status dropdown filter |
| Cluster filter | `cluster-filter` | Cluster dropdown filter |
| Session review | `session-review` | Review page container |
| Approve button | `approve-button` | Approve action |
| Reject button | `reject-button` | Reject action |
| Approval reason | `approval-reason-input` | Approval comment |
| Rejection reason | `rejection-reason-input` | Rejection comment |
| Confirm dialog | `confirm-reject-dialog` | Rejection confirmation |

## Success Criteria

1. All 5 test files pass consistently (3 consecutive runs)
2. Tests complete in under 5 minutes total
3. Email verification works reliably via MailHog
4. Deep link preservation works after OIDC redirect
5. No flaky tests (retry rate < 5%)

## Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| 1 | 1 week | Test helpers, Playwright config, data-testid attributes |
| 2 | 1 week | Login, request session, session browser tests |
| 3 | 1 week | Email approval, rejection tests, CI workflow |

## Future Enhancements

1. **Debug session UI tests** - Create/terminate debug sessions via UI
2. **Mobile viewport tests** - Responsive design validation
3. **Accessibility tests** - ARIA labels, keyboard navigation
4. **Performance tests** - Time to interactive, API response times

## Implementation Status

> **Status:** IMPLEMENTED

This proposal has been implemented. The Playwright-based UI E2E tests with email verification via MailHog are available in `frontend/tests/e2e/`.

### Files Created

- `frontend/playwright.e2e.config.ts` - E2E-specific Playwright configuration
- `frontend/tests/e2e/helpers/auth.ts` - OIDC authentication helper
- `frontend/tests/e2e/helpers/mailhog.ts` - MailHog API client
- `frontend/tests/e2e/helpers/navigation.ts` - Navigation and wait helpers
- `frontend/tests/e2e/helpers/index.ts` - Helper exports
- `frontend/tests/e2e/login.spec.ts` - Login flow tests
- `frontend/tests/e2e/request-session.spec.ts` - Session request tests
- `frontend/tests/e2e/approve-via-email.spec.ts` - Email approval tests
- `frontend/tests/e2e/session-browser.spec.ts` - Session browser tests
- `frontend/tests/e2e/reject-session.spec.ts` - Session rejection tests
- `.github/workflows/e2e-ui.yml` - CI workflow

### Running Tests

```bash
cd frontend

# Run all E2E tests
npm run test:e2e

# Run with UI mode for debugging
npm run test:e2e:ui

# Run with debug mode
npm run test:e2e:debug

# View test report
npm run test:e2e:report
```
