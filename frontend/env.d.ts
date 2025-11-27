/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_USE_MOCK_AUTH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
