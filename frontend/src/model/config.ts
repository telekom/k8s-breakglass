export default interface Config {
  oidcAuthority: string;
  oidcClientID: string;
  // Optional branding name provided by backend (e.g. "Platform Breakglass")
  brandingName?: string;
  // Optional UI flavour provided by backend (e.g. "telekom", "oss", "neutral")
  uiFlavour?: string;
  // Watch the IdP session (OIDC check_session_iframe) and sign out when it ends.
  // Unset means enabled; false is the transitional opt-out.
  monitorSession?: boolean;
}
