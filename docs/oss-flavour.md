# Open-Source (OSS) Frontend Flavour

This repository includes an OSS-friendly frontend flavour that uses the neutral,
MPL-2.0 compatible Scale components package instead of Telekom-branded assets.

Overview
- The OSS flavour loads `@telekom/scale-components-neutral`, which ships neutral
  design tokens, fonts and web components.
- The OSS frontend entry point is `frontend/oss-index.html`. The normal `index.html`
  includes Telekom proprietary components and should not be used for OSS deployments.

Building the OSS Docker image

By default the OSS Dockerfile installs the `@next` neutral package. You can build
the image with a specific neutral package version by passing the `NEUTRAL_VERSION`
build ARG.

Examples

Build default (OSS flavour, neutral components) with unified Dockerfile:

```bash
docker build -t breakglass:oss .
```

Opt-in to Telekom branded flavour:

```bash
docker build --build-arg UI_FLAVOUR=telekom -t breakglass:telekom .
```

Notes about using the neutral components

- Plain HTML setup (no bundler): include in your HTML head:

  <link rel="stylesheet" href="/node_modules/@telekom/scale-components-neutral/dist/scale-components/scale-components.css">
  <script type="module" src="/node_modules/@telekom/scale-components-neutral/dist/scale-components/scale-components.esm.js"></script>

- Bundler/ESM setup (preferred for Vue apps):

  import '@telekom/scale-components-neutral/dist/scale-components/scale-components.css';
  import { applyPolyfills, defineCustomElements } from '@telekom/scale-components-neutral/loader';
  applyPolyfills().then(() => defineCustomElements(window));

Using source code directly

If you intend to build the neutral components from source instead of using npm packages,
please remove the proprietary folders described in the Scale project's documentation
(`assets`, `packages/components/src/components/telekom`, `packages/components/src/telekom`, etc.)
before distributing the result to remain compliant with the MPL-2.0 license.

To test Telekom branded flavour:

```bash
docker build --build-arg UI_FLAVOUR=telekom -t breakglass:telekom .
IMAGE=breakglass:telekom UI_FLAVOUR=telekom bash e2e/kind-setup-single.sh
```

The script will pass `UI_FLAVOUR` through so the frontend loads appropriate components.

## Branding & Favicon

For OSS distributions a neutral favicon (`frontend/public/favicon-oss.svg`) is provided and loaded by default. When the
`UI_FLAVOUR=telekom` build arg / env is used the runtime script switches to the legacy branded `favicon.ico`. If you
publish the OSS build ensure the `.ico` file does not contain proprietary marks or remove it entirely. Custom project
branding can be applied by replacing `favicon-oss.svg` with your own SVG or PNG (update the `index.html` type attribute
accordingly if not using SVG).
