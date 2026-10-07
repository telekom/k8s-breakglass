import type { InjectionKey } from "vue";
import type AuthService from "@/services/auth";

export const AuthKey: InjectionKey<AuthService> = Symbol("auth");
// Branding key provides an optional product name (e.g. "Platform Breakglass")
export const BrandingKey: InjectionKey<string | undefined> = Symbol("branding");
