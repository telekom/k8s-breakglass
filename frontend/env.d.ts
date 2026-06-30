/// <reference types="vite/client" />

declare module "@telekom/scale-components-neutral/loader" {
  export function defineCustomElements(win: Window): Promise<void>;
  export function applyPolyfills(): Promise<void>;
}

interface Window {
  __DEV_TOKEN_LOG?: boolean | string;
}

interface ImportMetaEnv {
  readonly VITE_USE_MOCK_AUTH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
