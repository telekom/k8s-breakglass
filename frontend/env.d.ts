/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_USE_MOCK_AUTH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  __DEV_TOKEN_LOG?: boolean | string;
}

declare module "@telekom/scale-components-neutral/loader" {
  export function defineCustomElements(win?: Window, opts?: any): Promise<void>;
  export function applyPolyfills(): Promise<void>;
}
