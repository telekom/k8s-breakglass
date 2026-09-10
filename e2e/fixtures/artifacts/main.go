// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// A test-only provisioner and TLS edge for the single-cluster Kind fixture.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
	artifacts3 "github.com/telekom/k8s-breakglass/pkg/artifacts/storage/s3"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("expected provision or serve")
	}
	if strings.HasPrefix(os.Args[1], "s3-") {
		if err := s3Fixture(os.Args[1]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if os.Args[1] == "provision" {
		bundle, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile("/artifacts/ca-bundle.pem", bundle, 0600); err != nil {
			log.Fatal(err)
		}
		for _, path := range []string{"/artifacts/objects", "/artifacts/staging", "/artifacts/uploads"} {
			if err := os.MkdirAll(path, 0700); err != nil {
				log.Fatal(err)
			}
			if err := os.Chmod(path, 0700); err != nil {
				log.Fatal(err)
			}
		}
		err = local.ProvisionSentinels(local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: "/artifacts/objects", StagingRoot: "/artifacts/staging", InstanceID: "kind-artifact-fixture-v1", ExpectedUID: 65532, ExpectedGID: 65532, ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited})
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

// Fixture-only administrator provisioning and independent version inventory.
func s3Fixture(mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	access, err := os.ReadFile("/fixture-s3/accessKeyID")
	if err != nil {
		return err
	}
	secret, err := os.ReadFile("/fixture-s3/secretAccessKey")
	if err != nil {
		return err
	}
	creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: string(access), SecretAccessKey: string(secret)}, nil
	})
	cfg := artifacts3.Config{Endpoint: "https://artifact-s3.breakglass-system.svc:9000", Region: "us-east-1", Bucket: "artifact-kind", Prefix: "e2e", InstanceID: "kind-artifact-s3-fixture-v1", UsePathStyle: true, RequireVersioned: true}
	c := awss3.NewFromConfig(aws.Config{Region: cfg.Region, Credentials: creds}, func(o *awss3.Options) { o.BaseEndpoint = aws.String(cfg.Endpoint); o.UsePathStyle = true })
	if mode == "s3-ready" {
		_, err := c.ListBuckets(ctx, &awss3.ListBucketsInput{})
		return err
	}
	if mode == "s3-provision" {
		if _, err := c.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
			return err
		}
		if _, err := c.PutBucketVersioning(ctx, &awss3.PutBucketVersioningInput{Bucket: aws.String(cfg.Bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
			return err
		}
		store, err := artifacts3.NewWithClient(c, cfg)
		if err != nil {
			return err
		}
		return store.ProvisionSentinel(ctx)
	}
	if mode != "s3-inventory" {
		return fmt.Errorf("unknown S3 fixture mode %q", mode)
	}
	pages := awss3.NewListObjectVersionsPaginator(c, &awss3.ListObjectVersionsInput{Bucket: aws.String(cfg.Bucket)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, v := range page.Versions {
			if !strings.HasSuffix(aws.ToString(v.Key), ".breakglass-artifact-instance-v1") {
				fmt.Printf("%s@%s\n", aws.ToString(v.Key), aws.ToString(v.VersionId))
			}
		}
		for _, v := range page.DeleteMarkers {
			fmt.Printf("delete:%s@%s\n", aws.ToString(v.Key), aws.ToString(v.VersionId))
		}
	}
	return nil
}
