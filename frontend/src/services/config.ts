import type Config from "@/model/config";
import axios from "axios";
import { error as logError } from "@/services/logger";

// Supports both legacy flat shape { oidcAuthority, oidcClientID }
// and new nested shape { frontend: { oidcAuthority, oidcClientID }, authorizationServer: {...} }
export default async function getConfig(): Promise<Config> {
  const res = await axios.get<any>("/api/config");
  const data = res.data || {};
  if (data.oidcAuthority && data.oidcClientID) {
    return { oidcAuthority: data.oidcAuthority, oidcClientID: data.oidcClientID, brandingName: data.brandingName };
  }
  if (data.frontend && data.frontend.oidcAuthority && data.frontend.oidcClientID) {
    return { oidcAuthority: data.frontend.oidcAuthority, oidcClientID: data.frontend.oidcClientID, brandingName: data.frontend.brandingName };
  }
  logError('ConfigService', 'Config missing OIDC fields', data);
  return { oidcAuthority: "", oidcClientID: "", brandingName: undefined };
}
