# Open-Source (OSS) Frontend Flavour

This repository includes an OSS-friendly frontend flavour that uses the neutral,
MPL-2.0 compatible Scale components package instead of Telekom-branded assets.

## Runtime Configuration

The UI flavour can now be configured at **runtime** via the backend configuration,
eliminating the need for build-time configuration in most cases. Simply set the
`frontend.uiFlavour` option in your `config.yaml`:

```yaml
frontend:
  oidcAuthority: http://127.0.0.1:8080/realms/master
  oidcClientID: breakglass-ui
  baseURL: http://localhost:5173
  # Set UI theme at runtime (default: "oss")
  # Supported: "oss", "neutral" (both use neutral components), "telekom" (branded)
  uiFlavour: "telekom"
```

Supported values:

- **`"oss"` or `"neutral"`**: Uses neutral, MPL-2.0 compatible Scale components
- **`"telekom"`**: Uses Telekom-branded Scale components
- **`"default"`**: Alias for `"oss"`

## Legacy: Build-Time Configuration

For older deployments, the UI flavour could be set at build-time via the `VITE_UI_FLAVOUR`
environment variable. **This approach is still supported for backward compatibility**, but
runtime configuration via `config.yaml` is now the recommended approach.

### Overview

- The OSS flavour loads `@telekom/scale-components-neutral`, which ships neutral
  design tokens, fonts and web components.
- The OSS frontend entry point is `frontend/oss-index.html`. The normal `index.html`
  includes Telekom proprietary components and should not be used for OSS deployments.

### Building the OSS Docker image

By default the OSS Dockerfile installs the `@next` neutral package. You can build
the image with a specific neutral package version by passing the `NEUTRAL_VERSION`
build ARG.

### Examples

Build default (OSS flavour, neutral components) with unified Dockerfile:

```bash
docker build -t breakglass:oss .
```

Opt-in to Telekom branded flavour via runtime config (recommended):

```bash
# Configure in config.yaml
echo "frontend.uiFlavour: telekom" >> config.yaml
```

Or use build-time configuration (legacy):

```bash
docker build --build-arg UI_FLAVOUR=telekom -t breakglass:telekom .
```

## Notes about using the neutral components

- Plain HTML setup (no bundler): include in your HTML head:

  ```html
  <link rel="stylesheet" href="/node_modules/@telekom/scale-components-neutral/dist/scale-components/scale-components.css">
  <script type="module" src="/node_modules/@telekom/scale-components-neutral/dist/scale-components/scale-components.esm.js"></script>
  ```

- Bundler/ESM setup (preferred for Vue apps):

  ```javascript
  import '@telekom/scale-components-neutral/dist/scale-components/scale-components.css';
  import { applyPolyfills, defineCustomElements } from '@telekom/scale-components-neutral/loader';
  applyPolyfills().then(() => defineCustomElements(window));
  ```

## Using source code directly

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
