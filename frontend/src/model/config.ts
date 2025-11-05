export default interface Config {
  oidcAuthority: string;
  oidcClientID: string;
  // Optional branding name provided by backend (e.g. "Das SCHIFF Breakglass")
  brandingName?: string;
  // Optional UI flavour provided by backend (e.g. "telekom", "oss", "neutral")
  uiFlavour?: string;
}
