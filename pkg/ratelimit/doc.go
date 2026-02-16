// Package ratelimit provides per-IP and per-user token-bucket rate limiting
// middleware for Gin HTTP servers, with configurable limits for authenticated
// vs. unauthenticated requests and automatic stale-entry cleanup.
package ratelimit
