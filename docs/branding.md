# UI Branding

You can configure the branding name that the frontend displays (page title, header logo title, etc.) by setting `frontend.brandingName` in your controller configuration file (`config.yaml` or the path referenced by the `BREAKGLASS_CONFIG_PATH` environment variable).

Example (add under the `frontend:` section):

```yaml
frontend:
  oidcAuthority: https://keycloak.example.com/realms/master
  oidcClientID: breakglass-ui
  baseURL: https://breakglass.example.com
  # Optional branding shown in the UI
  brandingName: "Das SCHIFF Breakglass"
```

Behavior:

- If `brandingName` is set, the backend will include it in the `/api/config` response and the frontend will use it to set the page title and header.

- If the backend doesn't provide a branding name or the API can't be reached, the frontend will show a neutral placeholder title (`Breakglass`).

- The `brandingName` field is optional and safe to omit; omitting it does not break default behavior.

Mail sender configuration

You can also configure the From address and display name used for outgoing emails by setting `mail.senderAddress` and `mail.senderName` in your controller configuration file. The sender name will default to the frontend branding when present, and finally to a generic placeholder.

Example:

```yaml
mail:
  host: smtp.example.com
  port: 587
  user: mailbot@example.com
  password: s3cr3t
  # Optional sender address used in the From header
  senderAddress: noreply@example.com
  # Optional sender display name. If empty, the server will use frontend.brandingName
  # (if set) or fall back to a neutral default like "Breakglass".
  senderName: "Das SCHIFF Breakglass"
```

Behavior:

- If `mail.senderName` is set, it will be used as the display name in the email From header.
- If `mail.senderName` is empty but `frontend.brandingName` is set, the branding name is used for the From display name.
- If neither is set, a generic placeholder ("Breakglass") is used so emails always have a sensible From name.

This keeps UI branding and outgoing email sender names consistent while allowing fine-grained overrides where needed.
