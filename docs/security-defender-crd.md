# Defender CRD hardening

The CRD validation and debug-session binding paths enforce the same policy at admission and runtime:

- IdentityProvider uniqueness uses the effective issuer (explicit issuer or OIDC authority) with trailing-slash normalization.
- Binding constraints are intersected with template limits; a binding cannot widen duration, concurrency, or renewal limits.
- Restricted extra-deploy options are omitted from validation error choices and use generic authorization errors.
- Number inputs must be finite, and extended day durations reject `time.Duration` overflow.
- Empty cluster selectors are rejected and are not expanded at runtime.

When `spec.issuer` is set, it is authoritative: `oidc.authority` is no longer accepted as a second token issuer alias. Before upgrading, set `spec.issuer` to the issuer carried by your tokens, or omit it to use the authority. Existing duplicate effective issuers fail authentication until the configuration is disambiguated. Disabled providers are ignored during authentication.
