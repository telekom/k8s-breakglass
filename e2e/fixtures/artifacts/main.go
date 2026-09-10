// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// A test-only provisioner and TLS edge for the single-cluster Kind fixture.
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("expected provision or serve")
	}
	if os.Args[1] == "provision" {
		for _, path := range []string{"/artifacts/objects", "/artifacts/staging", "/artifacts/uploads"} {
			if err := os.MkdirAll(path, 0700); err != nil {
				log.Fatal(err)
			}
			if err := os.Chmod(path, 0700); err != nil {
				log.Fatal(err)
			}
		}
		err := local.ProvisionSentinels(local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: "/artifacts/objects", StagingRoot: "/artifacts/staging", InstanceID: "kind-artifact-fixture-v1", ExpectedUID: 65532, ExpectedGID: 65532, ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited})
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if os.Args[1] != "serve" {
		log.Fatal("unknown mode")
	}
	upstream, _ := url.Parse("http://127.0.0.1:8080")
	server := &http.Server{Addr: ":8444", ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, Handler: httputil.NewSingleHostReverseProxy(upstream)}
	log.Fatal(server.ListenAndServeTLS("/fixture-tls/tls.crt", "/fixture-tls/tls.key"))
}
