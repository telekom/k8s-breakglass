// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// fixture-server is built only by the integration proof. It provides
// disposable HTTP, TLS, and DNS endpoints inside the kind network; it is not
// part of the workload-debug runtime image.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type httpFixture struct {
	slow          time.Duration
	expectedToken string
}

const expectedAuthTokenPath = "/var/run/secrets/workload-debug/" + "to" + "ken"

func (h httpFixture) acceptsAuthorization(r *http.Request) bool {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return false
	}
	if h.expectedToken == "" {
		return true
	}
	return authorization == "Bearer "+h.expectedToken
}

func (h httpFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "workload-debug-fixture/1")
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead:
		if r.URL.Path != "/head" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Fixture", "head")
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		switch r.URL.Path {
		case "/get":
			writeBody(w, http.StatusOK, []byte("fixture-get\n"))
		case "/redirect":
			http.Redirect(w, r, "/get", http.StatusFound)
		case "/large":
			writeBody(w, http.StatusOK, []byte(strings.Repeat("x", 4096)))
		case "/auth":
			if !h.acceptsAuthorization(r) {
				writeBody(w, http.StatusUnauthorized, []byte("authorization-required\n"))
				return
			}
			writeBody(w, http.StatusOK, []byte("authenticated\n"))
		case "/auth-chunked":
			if !h.acceptsAuthorization(r) {
				writeBody(w, http.StatusUnauthorized, []byte("authorization-required\n"))
				return
			}
			fallthrough
		case "/chunked":
			// Write a deliberately minimal HTTP/1.1 chunked response. The
			// response-body limiter applies its configured bound independently
			// to response headers and body; keeping this fixture's headers below
			// the small integration-test limit ensures the test exercises the
			// unknown-length body path rather than rejecting ordinary headers.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				writeBody(w, http.StatusInternalServerError, []byte("hijacking is unavailable\n"))
				return
			}
			conn, buffered, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer func() {
				if err := conn.Close(); err != nil {
					// The fixture never includes request data in connection-close
					// errors, so this diagnostic cannot disclose credentials or
					// response content to the integration-test log.
					log.Printf("chunked fixture connection close failed: %v", err)
				}
			}()
			if _, err := io.WriteString(buffered, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
				return
			}
			if err := buffered.Flush(); err != nil {
				return
			}
			for i := 0; i < 4096; i++ {
				if _, err := io.WriteString(buffered, "1\r\nx\r\n"); err != nil {
					return
				}
				if err := buffered.Flush(); err != nil {
					return
				}
			}
			_, _ = io.WriteString(buffered, "0\r\n\r\n")
			_ = buffered.Flush()
		case "/auth-oversized-headers":
			if !h.acceptsAuthorization(r) {
				writeBody(w, http.StatusUnauthorized, []byte("authorization-required\n"))
				return
			}
			fallthrough
		case "/oversized-headers":
			w.Header().Set("X-Fixture-Large", strings.Repeat("x", 4096))
			writeBody(w, http.StatusOK, []byte("fixture-header-bound\n"))
		case "/slow":
			time.Sleep(h.slow)
			writeBody(w, http.StatusOK, []byte("fixture-slow\n"))
		default:
			if strings.HasPrefix(r.URL.Path, "/slow/") {
				time.Sleep(h.slow)
				writeBody(w, http.StatusOK, []byte("fixture-slow\n"))
				return
			}
			writeBody(w, http.StatusNotFound, []byte("not-found\n"))
		}
	default:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeBody(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func runHTTP(ctx context.Context, listen string, slow time.Duration, tlsCert, tlsKey string) error {
	expectedToken := ""
	if tokenFile := os.Getenv("EXPECTED_AUTH_TOKEN_FILE"); tokenFile != "" {
		if tokenFile != expectedAuthTokenPath {
			return fmt.Errorf("expected auth token path must be %q", expectedAuthTokenPath)
		}
		contents, err := os.ReadFile(expectedAuthTokenPath)
		if err != nil {
			return fmt.Errorf("read expected auth token: %w", err)
		}
		expectedToken = strings.TrimSpace(string(contents))
		if expectedToken == "" {
			return errors.New("expected auth token file is empty")
		}
	}
	server := &http.Server{Addr: listen, Handler: httpFixture{slow: slow, expectedToken: expectedToken}, ReadHeaderTimeout: 3 * time.Second}
	errs := make(chan error, 1)
	go func() {
		if tlsCert == "" || tlsKey == "" {
			errs <- server.ListenAndServe()
			return
		}
		errs <- server.ListenAndServeTLS(tlsCert, tlsKey)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runDNS(ctx context.Context, listen, expectedName, address string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer func() { _ = sock.Close() }()
	buffer := make([]byte, 4096)
	for {
		_ = sock.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		size, peer, readErr := sock.ReadFromUDP(buffer)
		if readErr != nil {
			var timeoutErr net.Error
			if errors.As(readErr, &timeoutErr) && timeoutErr.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return readErr
		}
		response, ok := dnsResponse(buffer[:size], expectedName, address)
		if ok {
			if _, err := sock.WriteToUDP(response, peer); err != nil {
				return err
			}
		}
	}
}

func dnsResponse(packet []byte, expectedName, address string) ([]byte, bool) {
	if len(packet) < 12 {
		return nil, false
	}
	labels, end, ok := dnsQuestion(packet)
	if !ok {
		return nil, false
	}
	question := packet[12 : end+5]
	name := strings.Join(labels, ".")
	flags := uint16(0x8183)
	answerCount := uint16(0)
	answer := []byte{}
	if strings.EqualFold(name, expectedName) {
		ip := net.ParseIP(address).To4()
		if ip != nil {
			flags = 0x8180
			answerCount = 1
			answer = []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ip[0], ip[1], ip[2], ip[3]}
		}
	}
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], binary.BigEndian.Uint16(packet[0:2]))
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], answerCount)
	return append(append(header, question...), answer...), true
}

func dnsQuestion(packet []byte) ([]string, int, bool) {
	labels := []string{}
	position := 12
	for position < len(packet) {
		length := int(packet[position])
		position++
		if length == 0 {
			if position+4 > len(packet) {
				return nil, 0, false
			}
			return labels, position - 1, true
		}
		if length > 63 || position+length > len(packet) {
			return nil, 0, false
		}
		labels = append(labels, string(packet[position:position+length]))
		position += length
	}
	return nil, 0, false
}

func main() {
	mode := flag.String("mode", "http", "fixture mode: http, tls, or dns")
	listen := flag.String("listen", ":8080", "listen address")
	name := flag.String("name", "workload.fixture.test", "DNS name")
	address := flag.String("address", "203.0.113.7", "DNS A record")
	slow := flag.Duration("slow", 4*time.Second, "delay for /slow")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS private key")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	switch *mode {
	case "http":
		err = runHTTP(ctx, *listen, *slow, "", "")
	case "tls":
		err = runHTTP(ctx, *listen, *slow, *cert, *key)
	case "dns":
		err = runDNS(ctx, *listen, *name, *address)
	default:
		log.Fatalf("unknown fixture mode %q", *mode)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
