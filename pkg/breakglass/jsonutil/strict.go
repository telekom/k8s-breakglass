// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeStrict decodes exactly one JSON value and rejects unknown fields and
// trailing non-whitespace content.
func DecodeStrict(r io.Reader, dest interface{}) error {
	if r == nil {
		return io.EOF
	}

	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dest); err != nil {
		return err
	}

	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected extra JSON input")
		}
		return err
	}

	return nil
}
