package api

import (
	"errors"
	"net/url"
	"strings"
)

var allowedOIDCProxyPathPrefixes = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/jwks.json",
	"/auth/realms/",
	"/protocol/openid-connect/auth",
	"/protocol/openid-connect/token",
	"/protocol/openid-connect/certs",
	"/protocol/openid-connect/userinfo",
	"/protocol/openid-connect/logout",
	"/certs",
	"/token",
	"/authorize",
	"/userinfo",
	"/revocation",
	"/introspection",
}

var (
	errProxyPathNotAllowed    = errors.New("requested path is not an allowed OIDC endpoint")
	errProxyPathSuspicious    = errors.New("invalid proxy path: absolute URLs and path traversal not allowed")
	errProxyPathMalformed     = errors.New("invalid proxy path: malformed")
	errProxyPathAbsolute      = errors.New("invalid proxy path: must be relative")
	errProxyAuthorityMissing  = errors.New("invalid proxy path: OIDC authority not configured")
	errInvalidAuthorityHeader = errors.New("invalid X-OIDC-Authority header")
	errUnknownOIDCAuthority   = errors.New("unknown OIDC authority")
	errURLResolutionAttack    = errors.New("invalid proxy path: resolved to different host")
)

func normalizeProxyPath(raw string) string {
	if parsed, err := url.Parse(raw); err == nil {
		if path := parsed.EscapedPath(); path != "" {
			return path
		}
	}
	normalized := raw
	if idx := strings.Index(normalized, "?"); idx != -1 {
		normalized = normalized[:idx]
	}
	if idx := strings.Index(normalized, "#"); idx != -1 {
		normalized = normalized[:idx]
	}
	return normalized
}

func validateOIDCProxyPath(proxyPath string) (string, error) {
	normalizedPath := normalizeProxyPath(proxyPath)
	if !isOIDCProxyPathAllowed(normalizedPath) {
		return "", errProxyPathNotAllowed
	}
	if hasSuspiciousOIDCProxyPattern(proxyPath) || hasSuspiciousOIDCProxyPattern(normalizedPath) || hasEncodedTraversal(normalizedPath) {
		return "", errProxyPathSuspicious
	}
	if decoded, err := url.PathUnescape(normalizedPath); err == nil {
		if hasSuspiciousOIDCProxyPattern(decoded) {
			return "", errProxyPathSuspicious
		}
	}
	parsedPath, err := url.Parse(normalizedPath)
	if err != nil {
		return "", errProxyPathMalformed
	}
	if parsedPath.Scheme != "" || parsedPath.Host != "" {
		return "", errProxyPathAbsolute
	}
	return normalizedPath, nil
}

func isOIDCProxyPathAllowed(path string) bool {
	for _, prefix := range allowedOIDCProxyPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func hasSuspiciousOIDCProxyPattern(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "://") || strings.HasPrefix(lower, "//") || strings.Contains(lower, "..") || strings.Contains(lower, "\\")
}

func hasEncodedTraversal(path string) bool {
	candidate := path
	for i := 0; i < 3; i++ {
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") || strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
			return true
		}
		decoded, err := url.QueryUnescape(candidate)
		if err != nil || decoded == candidate {
			break
		}
		candidate = decoded
	}
	return false
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	cpy := *u
	return &cpy
}

func buildOIDCProxyTargetURL(base *url.URL, normalizedPath, proxyPath string) (*url.URL, error) {
	if base == nil {
		return nil, errProxyAuthorityMissing
	}
	baseCopy := cloneURL(base)
	if baseCopy.Path != "" {
		baseCopy.Path = strings.TrimRight(baseCopy.Path, "/")
	}
	targetPath := normalizedPath
	if baseCopy.Path != "" && strings.HasPrefix(normalizedPath, "/") {
		targetPath = baseCopy.Path + normalizedPath
	}
	relativeURL := &url.URL{Path: targetPath}
	if idx := strings.Index(proxyPath, "?"); idx != -1 {
		relativeURL.RawQuery = proxyPath[idx+1:]
	}
	targetURL := baseCopy.ResolveReference(relativeURL)
	if targetURL.Scheme != baseCopy.Scheme || targetURL.Host != baseCopy.Host {
		return nil, errURLResolutionAttack
	}
	return targetURL, nil
}

func (s *Server) selectOIDCProxyAuthority(headerValue string) (*url.URL, error) {
	if headerValue == "" {
		return cloneURL(s.oidcAuthority), nil
	}
	parsed, err := url.Parse(headerValue)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errInvalidAuthorityHeader
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errInvalidAuthorityHeader
	}
	if !s.isKnownIDPAuthority(headerValue) {
		return nil, errUnknownOIDCAuthority
	}
	return parsed, nil
}
