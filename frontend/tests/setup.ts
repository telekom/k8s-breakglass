/**
 * Vitest setup file
 * Configures global test utilities and mocks for Vue component testing
 */

import { vi } from "vitest";

// Mock window.history to avoid SecurityError in jsdom
const originalReplaceState = window.history.replaceState;
window.history.replaceState = function (...args: Parameters<typeof originalReplaceState>) {
  try {
    return originalReplaceState.apply(window.history, args);
  } catch (e) {
    // Ignore SecurityError in jsdom when URL is not same-origin
    if (e instanceof Error && e.name === "SecurityError") {
      return;
    }
    throw e;
  }
};

// Mock window.matchMedia for components that use media queries
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock ResizeObserver
globalThis.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
})) as unknown as typeof ResizeObserver;

// Mock IntersectionObserver
globalThis.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
  root: null,
  rootMargin: "",
  thresholds: [],
})) as unknown as typeof IntersectionObserver;

// Mock sessionStorage
const sessionStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

Object.defineProperty(window, "sessionStorage", {
  value: sessionStorageMock,
});

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

Object.defineProperty(window, "localStorage", {
  value: localStorageMock,
});

// Custom element registry stub for Scale components
if (!customElements.get("scale-card")) {
  customElements.define(
    "scale-card",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-tag")) {
  customElements.define(
    "scale-tag",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-button")) {
  customElements.define(
    "scale-button",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-divider")) {
  customElements.define(
    "scale-divider",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-modal")) {
  customElements.define(
    "scale-modal",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-dropdown-select")) {
  customElements.define(
    "scale-dropdown-select",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-dropdown-select-option")) {
  customElements.define(
    "scale-dropdown-select-option",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-table")) {
  customElements.define(
    "scale-table",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-text-field")) {
  customElements.define(
    "scale-text-field",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-checkbox")) {
  customElements.define(
    "scale-checkbox",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-notification-toast")) {
  customElements.define(
    "scale-notification-toast",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-notification")) {
  customElements.define(
    "scale-notification",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

if (!customElements.get("scale-loading-spinner")) {
  customElements.define(
    "scale-loading-spinner",
    class extends HTMLElement {
      connectedCallback() {
        if (!this.shadowRoot) this.attachShadow({ mode: "open" });
      }
    },
  );
}

// Scale tooltip and icon stubs used by SessionMetaGrid
for (const tag of ["scale-tooltip", "scale-icon-action-info"]) {
  if (!customElements.get(tag)) {
    customElements.define(
      tag,
      class extends HTMLElement {
        connectedCallback() {
          if (!this.shadowRoot) this.attachShadow({ mode: "open" });
        }
      },
    );
  }
}
