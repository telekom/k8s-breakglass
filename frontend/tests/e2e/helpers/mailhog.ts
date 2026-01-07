// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * MailHog API client for E2E tests.
 * Used to verify email notifications are sent correctly.
 */

export interface MailHogAddress {
  Mailbox: string;
  Domain: string;
}

export interface MailHogMessage {
  ID: string;
  From: MailHogAddress;
  To: MailHogAddress[];
  Content: {
    Headers: {
      Subject: string[];
      From: string[];
      To: string[];
      "Content-Type": string[];
    };
    Body: string;
    MIME?: {
      Parts?: Array<{
        Headers: Record<string, string[]>;
        Body: string;
      }>;
    };
  };
  Created: string;
  Raw: {
    From: string;
    To: string[];
    Data: string;
  };
}

export interface MailHogMessagesResponse {
  total: number;
  count: number;
  start: number;
  items: MailHogMessage[];
}

/**
 * Client for interacting with MailHog API to verify email delivery.
 */
export class MailHogClient {
  private baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || process.env.MAILHOG_URL || "http://localhost:8025";
  }

  /**
   * Get all messages from MailHog.
   */
  async getMessages(): Promise<MailHogMessage[]> {
    const response = await fetch(`${this.baseUrl}/api/v2/messages`);
    if (!response.ok) {
      throw new Error(`MailHog API error: ${response.status}`);
    }
    const data: MailHogMessagesResponse = await response.json();
    return data.items || [];
  }

  /**
   * Clear all messages from MailHog.
   */
  async clearMessages(): Promise<void> {
    await fetch(`${this.baseUrl}/api/v1/messages`, { method: "DELETE" });
  }

  /**
   * Delete a specific message by ID.
   */
  async deleteMessage(id: string): Promise<void> {
    await fetch(`${this.baseUrl}/api/v1/messages/${id}`, { method: "DELETE" });
  }

  /**
   * Wait for a message matching the predicate to arrive.
   * @param predicate Function to match messages
   * @param timeout Maximum time to wait in milliseconds
   * @returns The matching message
   * @throws Error if no matching message is found within timeout
   */
  async waitForMessage(predicate: (msg: MailHogMessage) => boolean, timeout = 30000): Promise<MailHogMessage> {
    const deadline = Date.now() + timeout;
    const pollInterval = 1000;

    while (Date.now() < deadline) {
      const messages = await this.getMessages();
      const match = messages.find(predicate);
      if (match) {
        return match;
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    throw new Error(`No matching email found within ${timeout}ms`);
  }

  /**
   * Wait for an email with a subject containing the given text.
   */
  async waitForSubject(subjectContains: string, timeout = 30000): Promise<MailHogMessage> {
    return this.waitForMessage(
      (msg) =>
        msg.Content.Headers.Subject?.some((s) => s.toLowerCase().includes(subjectContains.toLowerCase())) ?? false,
      timeout,
    );
  }

  /**
   * Wait for an email sent to a specific recipient.
   */
  async waitForRecipient(recipientEmail: string, timeout = 30000): Promise<MailHogMessage> {
    const localPart = (recipientEmail.split("@")[0] ?? "").toLowerCase();
    return this.waitForMessage((msg) => msg.To?.some((to) => to.Mailbox.toLowerCase() === localPart) ?? false, timeout);
  }

  /**
   * Extract all URLs from an email body.
   */
  extractLinks(body: string): string[] {
    // Decode quoted-printable if needed
    const decoded = this.decodeQuotedPrintable(body);
    // Extract URLs
    const urlRegex = /https?:\/\/[^\s<>"']+/g;
    const matches = decoded.match(urlRegex) || [];
    // Clean up trailing punctuation
    return matches.map((url) => url.replace(/[.,;:!?)]+$/, ""));
  }

  /**
   * Extract the approval/review link from an email body.
   */
  extractApprovalLink(body: string): string | null {
    const links = this.extractLinks(body);
    // Find link containing session review or approve paths
    return (
      links.find((l) => l.includes("/sessions/review") || l.includes("/approve") || l.includes("/session/")) || null
    );
  }

  /**
   * Get the plain text body from a message, handling MIME parts.
   */
  getPlainTextBody(message: MailHogMessage): string {
    // Check for MIME parts
    if (message.Content.MIME?.Parts) {
      const textPart = message.Content.MIME.Parts.find((part) =>
        part.Headers["Content-Type"]?.some((ct) => ct.includes("text/plain")),
      );
      if (textPart) {
        return this.decodeQuotedPrintable(textPart.Body);
      }
    }
    // Fall back to main body
    return this.decodeQuotedPrintable(message.Content.Body);
  }

  /**
   * Get the HTML body from a message, handling MIME parts.
   */
  getHtmlBody(message: MailHogMessage): string | null {
    if (message.Content.MIME?.Parts) {
      const htmlPart = message.Content.MIME.Parts.find((part) =>
        part.Headers["Content-Type"]?.some((ct) => ct.includes("text/html")),
      );
      if (htmlPart) {
        return this.decodeQuotedPrintable(htmlPart.Body);
      }
    }
    // Check if main body is HTML
    if (message.Content.Headers["Content-Type"]?.some((ct) => ct.includes("text/html"))) {
      return this.decodeQuotedPrintable(message.Content.Body);
    }
    return null;
  }

  /**
   * Decode quoted-printable encoded text.
   */
  private decodeQuotedPrintable(text: string): string {
    return text
      .replace(/=\r?\n/g, "") // Remove soft line breaks
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
}
