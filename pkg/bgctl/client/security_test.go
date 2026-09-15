// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseBodyBoundaries(t *testing.T) {
	for _, size := range []int{maxResponseBody - 1, maxResponseBody, maxResponseBody + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := "\"" + strings.Repeat("a", size-2) + "\""
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer srv.Close()
			c, err := New(WithServer(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			var got string
			err = c.do(context.Background(), http.MethodGet, "/", nil, &got)
			if size <= maxResponseBody {
				if err != nil || len(got) != size-2 {
					t.Fatalf("boundary response: len=%d err=%v", len(got), err)
				}
			} else if err == nil {
				t.Fatal("oversize accepted")
			}
		})
	}
}

func TestErrorBodyReadIsBoundedAndTerminalSafe(t *testing.T) {
	for _, size := range []int{maxResponseBody - 1, maxResponseBody, maxResponseBody + 100} {
		reader := strings.NewReader(strings.Repeat("a", size))
		err := decodeError(&http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(reader)}, "trace")
		var got *HTTPError
		if !errors.As(err, &got) {
			t.Fatalf("expected HTTP error: %v", err)
		}
		want := min(size, maxResponseBody)
		if len(got.Message) != want || size-reader.Len() > maxResponseBody+1 {
			t.Fatalf("unbounded body: message=%d read=%d", len(got.Message), size-reader.Len())
		}
	}
	err := decodeError(&http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(`{"error":"bad\u001b\u009b\u009d"}`))}, "trace\u009d")
	if strings.ContainsAny(err.Error(), "\x1b\u009b\u009d") {
		t.Fatalf("unsafe error %q", err)
	}
}
