// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrEmptyBody indicates that a required JSON request body was empty.
var ErrEmptyBody = errors.New("empty JSON body")

// ErrUnexpectedBody indicates that a no-body endpoint received payload content.
var ErrUnexpectedBody = errors.New("request body must be empty")

// DecodeStrict decodes exactly one JSON value and rejects unknown fields and
// trailing non-whitespace content.
func DecodeStrict(r io.Reader, dest interface{}) error {
	if r == nil {
		return ErrEmptyBody
	}

	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dest); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrEmptyBody
		}
		return err
	}

	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected extra JSON input")
		}
		return err
	}

	return nil
}

// RequireEmptyBody accepts nil, empty, or JSON-whitespace-only request bodies.
func RequireEmptyBody(r io.Reader) error {
	if r == nil {
		return nil
	}

	reader := bufio.NewReader(r)
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !isJSONWhitespace(b) {
			return ErrUnexpectedBody
		}
	}
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}
