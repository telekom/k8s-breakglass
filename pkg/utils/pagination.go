// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/base64"
	"fmt"
	"strconv"
)

const (
	// DefaultPageSize is the default number of items returned per page.
	DefaultPageSize = 100
	// MaxPageSize is the maximum number of items that can be requested per page.
	MaxPageSize = 500
)

// ParsePageLimit parses the ?limit query parameter string.
// Returns DefaultPageSize if the string is empty.
// Returns an error if the value is present but not a positive integer or exceeds MaxPageSize.
func ParsePageLimit(limitStr string) (int, error) {
	if limitStr == "" {
		return DefaultPageSize, nil
	}
	n, err := strconv.Atoi(limitStr)
	if err != nil {
		return 0, fmt.Errorf("invalid limit parameter %q: must be a positive integer: %w", limitStr, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid limit parameter %d: must be a positive integer", n)
	}
	if n > MaxPageSize {
		return 0, fmt.Errorf("invalid limit parameter %d: exceeds maximum allowed page size of %d", n, MaxPageSize)
	}
	return n, nil
}

// ParseContinueToken decodes a base64-encoded continue token to an integer offset.
// An empty token is treated as offset 0 (beginning of the list).
// Returns an error if the token is non-empty but cannot be decoded.
func ParseContinueToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("invalid continue token: %w", err)
	}
	offset, err := strconv.Atoi(string(decoded))
	if err != nil {
		return 0, fmt.Errorf("invalid continue token: encoded value is not an integer: %w", err)
	}
	if offset < 0 {
		return 0, fmt.Errorf("invalid continue token: offset must be non-negative")
	}
	return offset, nil
}

// EncodeContinueToken encodes an integer offset as an opaque base64 continue token.
func EncodeContinueToken(offset int) string {
	return base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// Paginate applies limit and offset to items and returns the current page and the next
// continue token. The returned token is empty if there are no more items after this page.
func Paginate[T any](items []T, limit, offset int) (page []T, nextToken string) {
	total := len(items)

	// Offset past end of list → empty page, no continuation.
	if offset >= total {
		return []T{}, ""
	}

	end := offset + limit
	if end > total {
		end = total
	}

	page = items[offset:end]

	// If there are more items after this page, encode the next offset.
	if end < total {
		nextToken = EncodeContinueToken(end)
	}

	return page, nextToken
}
