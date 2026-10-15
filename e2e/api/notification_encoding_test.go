// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/base64"
	"io"
	stdmail "net/mail"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/gomail.v2"

	"github.com/telekom/k8s-breakglass/pkg/mail"
)

func TestDecodeMailHogBody(t *testing.T) {
	for _, tc := range []struct {
		name, encoding, body, want string
		wantError                  bool
	}{
		{name: "absent encoding", body: "group=value", want: "group=value"},
		{name: "7bit", encoding: "7bit", body: "group=value", want: "group=value"},
		{name: "8bit", encoding: "8bit", body: "Grüppe", want: "Grüppe"},
		{name: "binary", encoding: "binary", body: "a\x00b", want: "a\x00b"},
		{name: "empty body", encoding: "quoted-printable"},
		{name: "quoted printable", encoding: " Quoted-Printable ", body: "group=3Dpre=\r\nfixed", want: "group=prefixed"},
		{name: "base64", encoding: "base64", body: base64.StdEncoding.EncodeToString([]byte("Grüppe=value")), want: "Grüppe=value"},
		{name: "invalid base64", encoding: "base64", body: "!", wantError: true},
		{name: "invalid quoted printable", encoding: "quoted-printable", body: "=\x00", wantError: true},
		{name: "unsupported encoding", encoding: "gzip", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := MailHogMessage{}
			message.Content.Body = tc.body
			if tc.encoding != "" {
				message.Content.Headers.ContentTransferEncoding = []string{tc.encoding}
			}
			got, err := decodeMailHogBody(message)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDecodeMailHogBody_RequestNotification(t *testing.T) {
	group := "escalated-notif-group-notif-3453"
	body, err := mail.RenderBreakglassSessionRequest(mail.RequestBreakglassSessionMailParams{RequestedGroup: group})
	require.NoError(t, err)
	message := gomail.NewMessage()
	message.SetBody("text/html", body)
	var wire bytes.Buffer
	_, err = message.WriteTo(&wire)
	require.NoError(t, err)
	parsed, err := stdmail.ReadMessage(&wire)
	require.NoError(t, err)
	encoded, err := io.ReadAll(parsed.Body)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), group, "fixture must reproduce the raw-body matching failure")
	observed := MailHogMessage{}
	observed.Content.Body = string(encoded)
	observed.Content.Headers.ContentTransferEncoding = []string{parsed.Header.Get("Content-Transfer-Encoding")}
	decoded, err := decodeMailHogBody(observed)
	require.NoError(t, err)
	require.Contains(t, decoded, group)
	// MIME uses CRLF line endings even when the template uses LF.
	require.Equal(t, body, strings.ReplaceAll(decoded, "\r\n", "\n"))
}
