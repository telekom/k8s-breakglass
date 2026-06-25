// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrEmptyBody indicates that a required JSON request body was empty.
var ErrEmptyBody = errors.New("empty JSON body")

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
