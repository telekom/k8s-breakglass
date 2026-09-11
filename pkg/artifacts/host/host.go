// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package host constructs the administrator-owned artifact transport. It is
// the only package allowed to turn config and Kubernetes Secrets into the
// provider-independent backend and its API/controller adapters.
package host

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	aws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	rootapi "github.com/telekom/k8s-breakglass/pkg/api"
	artifactapi "github.com/telekom/k8s-breakglass/pkg/artifacts/api"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactcontroller "github.com/telekom/k8s-breakglass/pkg/artifacts/controller"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/s3"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	tokenAudience = "breakglass-diagnostic-artifact"
	maxTokenTTL   = 15 * time.Minute
)

// LeaseFence is supplied by the durable session/lease implementation. A
// missing fence is a startup error when artifacts are enabled.
type LeaseFence interface {
	AuthorizeArtifact(context.Context, backend.SessionBinding) error
}

// BindingSource supplies the live target/epoch binding for API requests. It
// must read the same durable lease identity used by LeaseFence.
type BindingSource interface {
	ResolveArtifactBinding(context.Context, string, string, string) (backend.SessionBinding, error)
}

// Dependencies are the host-owned runtime seams. Client must be an uncached
// client for exact Secret reads; Reader must be an uncached API reader.
type Dependencies struct {
	Client          ctrlclient.Client
	Reader          ctrlclient.Reader
	Manager         ctrl.Manager
	DebugAPI        *debug.DebugSessionAPIController
	Lease           LeaseFence
	ClusterProvider artifactcontroller.TargetClientProvider
	BindingSource   BindingSource
	Log             *zap.SugaredLogger
}

// Components are registered by the application after construction.
type Components struct {
	Service        *backend.Service
	Controller     *artifactcontroller.Reconciler
	APIControllers []rootapi.APIController
	Close          func() error
}

// Build constructs the complete enabled artifact host. Disabled artifacts
// return nil without reading Secrets or contacting a provider.
func Build(ctx context.Context, artifactConfig config.Artifacts, namespace string, deps Dependencies) (*Components, error) {
	if !artifactConfig.Enabled {
		return nil, nil
	}
	if ctx == nil || deps.Client == nil || deps.Reader == nil || deps.Manager == nil || deps.DebugAPI == nil || deps.Lease == nil || deps.ClusterProvider == nil {
		return nil, errors.New("enabled diagnostic artifacts require uncached clients, manager, debug API, and lease fence")
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, errors.New("artifact backend namespace is invalid")
	}
	if len(validation.IsDNS1123Subdomain(artifactConfig.TokenSecretName)) != 0 || artifactConfig.TokenSignerKeyID == "" {
		return nil, errors.New("artifact token Secret and signer key ID are required")
	}
	imageParts := strings.Split(artifactConfig.CollectorImage, "@sha256:")
	validImage := len(imageParts) == 2 && imageParts[0] != "" && len(imageParts[1]) == 64
	if validImage {
		_, imageErr := hex.DecodeString(imageParts[1])
		validImage = imageErr == nil
	}
	if artifactConfig.StagingDir == "" || !validImage {
		return nil, errors.New("artifact staging directory and pinned collector image are required")
	}
	if artifactConfig.UploadMaxBytes < 1 || artifactConfig.UploadMaxBytes > archive.MaxCollectorArchiveBytes {
		return nil, errors.New("artifact upload maximum is outside the bounded contract")
	}
	issuer, err := controllerOrigin(artifactConfig.ControllerURL)
	if err != nil {
		return nil, err
	}
	keyring, err := loadKeyring(ctx, deps.Client, namespace, artifactConfig.TokenSecretName, artifactConfig.TokenSignerKeyID, issuer)
	if err != nil {
		return nil, err
	}
	repository, err := kube.NewRepositoryInNamespace(deps.Client, namespace)
	if err != nil {
		return nil, err
	}
	if deps.BindingSource == nil {
		deps.BindingSource = repositoryBindingSource{repository: repository}
	}
	store, closeStore, err := openStore(ctx, artifactConfig, deps.Client, namespace)
	if err != nil {
		return nil, err
	}
	service, err := backend.New(backend.Config{Repository: repository, Store: store, Authorizer: NewLiveSessionAuthorizer(deps.Reader, deps.Lease, nil), Tokens: keyring, StagingDir: artifactConfig.StagingDir})
	if err != nil {
		_ = closeStore()
		return nil, err
	}
	issuerAdapter := &uploadTokenIssuer{keyring: keyring, now: time.Now}
	reconciler := &artifactcontroller.Reconciler{Client: deps.Manager.GetClient(), LiveReader: deps.Reader, ClusterProvider: deps.ClusterProvider, Service: service, TokenIssuer: issuerAdapter, Image: artifactConfig.CollectorImage, ControllerURL: strings.TrimSuffix(artifactConfig.ControllerURL, "/"), Log: deps.Log}
	controllers, err := artifactAPIControllers(service, deps, artifactConfig.UploadMaxBytes)
	if err != nil {
		_ = closeStore()
		return nil, err
	}
	return &Components{Service: service, Controller: reconciler, APIControllers: controllers, Close: closeStore}, nil
}

func artifactAPIControllers(service *backend.Service, deps Dependencies, maximum int64) ([]rootapi.APIController, error) {
	resolver := newReadBindingResolver(deps.DebugAPI, deps.BindingSource)
	uploadController, err := artifactapi.NewUploadController(service)
	if err != nil {
		return nil, err
	}
	readController, err := artifactapi.NewReadController(service, resolver, deps.DebugAPI.Handlers()...)
	if err != nil {
		return nil, err
	}
	return []rootapi.APIController{uploadController, readController, &collectionController{service: service, debug: deps.DebugAPI, provider: deps.ClusterProvider, maximum: maximum}}, nil
}

// repositoryBindingSource reads the immutable session and target binding from
// the administrator-owned artifact record. The live lease fence is applied
// separately for every operation; this source never authorizes from a cache.
type repositoryBindingSource struct {
	repository backend.Repository
}

func (source repositoryBindingSource) ResolveArtifactBinding(ctx context.Context, namespace, sessionName, artifactID string) (backend.SessionBinding, error) {
	if source.repository == nil || namespace == "" || sessionName == "" || artifactID == "" {
		return backend.SessionBinding{}, backend.ErrForbidden
	}
	record, err := source.repository.Get(ctx, namespace, sessionName, artifactID)
	if err != nil || record.Namespace != namespace || record.SessionName != sessionName || record.SessionUID == "" || record.TargetClusterUID == "" || record.TargetIdentityDigest == "" || record.OperationEpoch == 0 {
		return backend.SessionBinding{}, backend.ErrForbidden
	}
	return backend.SessionBinding{
		Namespace:            record.Namespace,
		Name:                 record.SessionName,
		UID:                  record.SessionUID,
		TargetClusterUID:     record.TargetClusterUID,
		TargetIdentityDigest: record.TargetIdentityDigest,
		OperationEpoch:       record.OperationEpoch,
		ConnectionLeaseUID:   record.ConnectionLeaseUID,
		TargetPodNamespace:   record.TargetPodNamespace,
		TargetPodName:        record.TargetPodName,
		TargetPodUID:         record.TargetPodUID,
		TargetNodeUID:        record.TargetNodeUID,
	}, nil
}

// NewConnectionLeaseFence adapts the durable DebugSession connection lease to
// the provider-neutral artifact authorization contract. The adapter checks
// the session's persisted lease identity and then performs the lease's live
// UID, holder, target, epoch, and expiry validation.
func NewConnectionLeaseFence(reader ctrlclient.Reader, leases *debug.ConnectionLeaseService, providers ...artifactcontroller.TargetClientProvider) LeaseFence {
	fence := &connectionLeaseFence{reader: reader, leases: leases}
	if len(providers) > 0 {
		fence.provider = providers[0]
	}
	return fence
}

type connectionLeaseFence struct {
	reader   ctrlclient.Reader
	leases   *debug.ConnectionLeaseService
	provider artifactcontroller.TargetClientProvider
}

func (fence *connectionLeaseFence) AuthorizeArtifact(ctx context.Context, binding backend.SessionBinding) error {
	if fence == nil || fence.reader == nil || fence.leases == nil || binding.Namespace == "" || binding.Name == "" || binding.UID == "" || binding.TargetClusterUID == "" || binding.OperationEpoch == 0 || binding.OperationEpoch > uint64(1<<63-1) {
		return backend.ErrForbidden
	}
	var session breakglassv1alpha1.DebugSession
	if err := fence.reader.Get(ctx, types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}, &session); err != nil {
		return backend.ErrForbidden
	}
	lease := session.Status.ConnectionLease
	if lease == nil || binding.ConnectionLeaseUID == "" || string(lease.UID) != binding.ConnectionLeaseUID || !artifactSessionIsLive(&session, binding, time.Now()) || string(lease.TargetUID) != binding.TargetClusterUID || lease.Epoch != int64(binding.OperationEpoch) || lease.ExpiresAt.IsZero() {
		return backend.ErrForbidden
	}
	ref := debug.ConnectionLeaseRef{
		Namespace:     lease.Namespace,
		Name:          lease.Name,
		UID:           lease.UID,
		HolderUID:     lease.HolderUID,
		TargetUID:     lease.TargetUID,
		ProfileDigest: lease.ProfileDigest,
		Epoch:         lease.Epoch,
		ExpiresAt:     lease.ExpiresAt.Time,
	}
	if err := fence.leases.Validate(ctx, ref, -1); err != nil {
		return backend.ErrForbidden
	}
	if binding.TargetPodUID != "" {
		if fence.provider == nil {
			return backend.ErrForbidden
		}
		target, config, err := fence.provider.GetClientForPrivilegedOperation(ctx, session.Spec.Cluster)
		if err != nil {
			return backend.ErrForbidden
		}
		defer fence.provider.ReleasePrivilegedOperationClusterConfig(config)
		var pod corev1.Pod
		if string(config.UID) != binding.TargetClusterUID {
			return backend.ErrForbidden
		}
		if err := target.Get(ctx, ctrlclient.ObjectKey{Namespace: binding.TargetPodNamespace, Name: binding.TargetPodName}, &pod); err != nil || string(pod.UID) != binding.TargetPodUID || !pod.DeletionTimestamp.IsZero() {
			return backend.ErrForbidden
		}
		if binding.TargetNodeUID != "" {
			var node corev1.Node
			if err := target.Get(ctx, ctrlclient.ObjectKey{Name: pod.Spec.NodeName}, &node); err != nil || string(node.UID) != binding.TargetNodeUID || !node.DeletionTimestamp.IsZero() {
				return backend.ErrForbidden
			}
		}
		if err := fence.provider.ValidatePrivilegedOperationClusterConfig(ctx, config); err != nil {
			return backend.ErrForbidden
		}
	}
	if err := fence.leases.Validate(ctx, ref, -1); err != nil {
		return backend.ErrForbidden
	}
	var current breakglassv1alpha1.DebugSession
	if err := fence.reader.Get(ctx, types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}, &current); err != nil || !artifactSessionIsLive(&current, binding, time.Now()) || current.Status.ConnectionLease == nil || string(current.Status.ConnectionLease.UID) != binding.ConnectionLeaseUID || current.Status.ConnectionLease.Epoch != int64(binding.OperationEpoch) {
		return backend.ErrForbidden
	}
	return nil
}

func controllerOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("artifact controller URL must be an HTTPS origin or path without query or fragment")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func loadKeyring(ctx context.Context, client ctrlclient.Client, namespace, name, signer, issuer string) (*token.Keyring, error) {
	var secret corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, errors.New("artifact token Secret is missing")
		}
		return nil, fmt.Errorf("read artifact token Secret: %w", err)
	}
	if secret.Namespace != namespace || len(secret.Data) == 0 || len(secret.Data) > 32 {
		return nil, errors.New("artifact token Secret is outside its bounded contract")
	}
	ids := make([]string, 0, len(secret.Data))
	for id := range secret.Data {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := make([]token.Key, 0, len(ids))
	for _, id := range ids {
		if len(secret.Data[id]) < 32 {
			return nil, errors.New("artifact token Secret key is below the cryptographic floor")
		}
		keys = append(keys, token.Key{ID: id, Secret: secret.Data[id]})
	}
	keyring, err := token.NewKeyring(issuer, tokenAudience, signer, keys, token.Limits{MaxTTL: maxTokenTTL})
	if err != nil {
		return nil, fmt.Errorf("construct artifact token keyring: %w", err)
	}
	return keyring, nil
}

func openStore(ctx context.Context, cfg config.Artifacts, client ctrlclient.Client, namespace string) (artifactstorage.Store, func() error, error) {
	switch cfg.Backend {
	case "s3":
		if cfg.S3 == nil || cfg.Local != nil || len(validation.IsDNS1123Subdomain(cfg.S3.CredentialsSecretName)) != 0 {
			return nil, nil, errors.New("S3 artifact configuration and one credentials Secret are required")
		}
		var secret corev1.Secret
		if err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: cfg.S3.CredentialsSecretName}, &secret); err != nil {
			return nil, nil, fmt.Errorf("read artifact S3 credentials Secret: %w", err)
		}
		access, ok := secret.Data["accessKeyID"]
		if !ok || len(access) == 0 {
			return nil, nil, errors.New("artifact S3 credentials Secret lacks accessKeyID")
		}
		password, ok := secret.Data["secretAccessKey"]
		if !ok || len(password) == 0 {
			return nil, nil, errors.New("artifact S3 credentials Secret lacks secretAccessKey")
		}
		provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: string(access), SecretAccessKey: string(password), SessionToken: string(secret.Data["sessionToken"]), Source: "breakglass artifact Secret"}, nil
		})
		store, err := s3.New(s3.Config{Endpoint: cfg.S3.Endpoint, Region: cfg.S3.Region, Bucket: cfg.S3.Bucket, Prefix: cfg.S3.Prefix, InstanceID: cfg.S3.InstanceID, UsePathStyle: cfg.S3.UsePathStyle, RequireVersioned: cfg.S3.RequireVersioned, MaximumObjectBytes: cfg.UploadMaxBytes}, provider)
		if err != nil {
			return nil, nil, fmt.Errorf("construct S3 artifact store: %w", err)
		}
		if err := store.Verify(ctx); err != nil {
			return nil, nil, fmt.Errorf("verify S3 artifact store: %w", err)
		}
		return store, func() error { return nil }, nil
	case "local":
		if cfg.Local == nil || cfg.S3 != nil {
			return nil, nil, errors.New("local artifact configuration is required and cannot be combined with S3")
		}
		store, err := local.Open(local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: cfg.Local.PrivateRootAcknowledged, ArtifactRoot: cfg.Local.ArtifactRoot, StagingRoot: cfg.Local.StagingRoot, InstanceID: cfg.Local.InstanceID, ExpectedUID: cfg.Local.ExpectedUID, ExpectedGID: cfg.Local.ExpectedGID, ServingReplicas: cfg.Local.ServingReplicas, AccessMode: cfg.Local.AccessMode, DeploymentStrategy: cfg.Local.DeploymentStrategy, EncryptionAcknowledged: cfg.Local.EncryptionAcknowledged, SnapshotPolicy: cfg.Local.SnapshotPolicy, MaximumObjectBytes: cfg.Local.MaximumObjectBytes, MinimumFreeBytes: cfg.Local.MinimumFreeBytes})
		if err != nil {
			return nil, nil, fmt.Errorf("open local artifact store: %w", err)
		}
		return store, store.Close, nil
	default:
		return nil, nil, errors.New("artifact backend must be explicitly set to s3 or local")
	}
}

type uploadTokenIssuer struct {
	keyring *token.Keyring
	now     func() time.Time
}

func (issuer *uploadTokenIssuer) IssueUploadToken(_ context.Context, record backend.Record, route string) (string, error) {
	return backend.ReservationToken(issuer.keyring, record, route, issuer.now(), maxTokenTTL)
}

type liveSessionAuthorizer struct {
	reader ctrlclient.Reader
	lease  LeaseFence
	now    func() time.Time
}

// NewLiveSessionAuthorizer adds exact session UID/state/expiry checks before
// delegating target and epoch checks to the durable lease fence.
func NewLiveSessionAuthorizer(reader ctrlclient.Reader, lease LeaseFence, now func() time.Time) backend.SessionAuthorizer {
	if now == nil {
		now = time.Now
	}
	return &liveSessionAuthorizer{reader: reader, lease: lease, now: now}
}

func (authorizer *liveSessionAuthorizer) AuthorizeArtifact(ctx context.Context, binding backend.SessionBinding) error {
	if authorizer == nil || authorizer.reader == nil || authorizer.lease == nil || binding.Namespace == "" || binding.Name == "" || binding.UID == "" {
		return backend.ErrForbidden
	}
	var session breakglassv1alpha1.DebugSession
	if err := authorizer.reader.Get(ctx, types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}, &session); err != nil {
		return backend.ErrForbidden
	}
	if !artifactSessionIsLive(&session, binding, authorizer.now()) {
		return backend.ErrForbidden
	}
	if err := authorizer.lease.AuthorizeArtifact(ctx, binding); err != nil {
		return backend.ErrForbidden
	}
	var current breakglassv1alpha1.DebugSession
	if err := authorizer.reader.Get(ctx, types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}, &current); err != nil || !artifactSessionIsLive(&current, binding, authorizer.now()) {
		return backend.ErrForbidden
	}
	return nil
}

func artifactSessionIsLive(session *breakglassv1alpha1.DebugSession, binding backend.SessionBinding, now time.Time) bool {
	return session != nil && session.Annotations[quotas.AdmissionAnnotation] != quotas.Pending && session.DeletionTimestamp == nil && string(session.UID) == binding.UID && session.Status.State == breakglassv1alpha1.DebugSessionStateActive && session.Status.ExpiresAt != nil && now.Before(session.Status.ExpiresAt.Time) && !breakglass.DebugSessionIdleExpired(session, now)
}

type readBindingResolver struct {
	debugAPI *debug.DebugSessionAPIController
	source   BindingSource
}

func newReadBindingResolver(debugAPI *debug.DebugSessionAPIController, source BindingSource) artifactapi.BindingResolver {
	resolver := &readBindingResolver{debugAPI: debugAPI, source: source}
	return resolver.Resolve
}

func (resolver *readBindingResolver) Resolve(ctx *gin.Context, namespace, name, artifactID string) (backend.SessionBinding, error) {
	identity, err := resolver.debugAPI.AuthorizeArtifactRead(ctx, namespace, name)
	if err != nil {
		return backend.SessionBinding{}, backend.ErrForbidden
	}
	if artifactID == "" {
		return backend.SessionBinding{Namespace: identity.Namespace, Name: identity.Name, UID: string(identity.UID)}, nil
	}
	binding, err := resolver.source.ResolveArtifactBinding(ctx.Request.Context(), namespace, name, artifactID)
	if err != nil || binding.Namespace != identity.Namespace || binding.Name != identity.Name || binding.UID != string(identity.UID) {
		return backend.SessionBinding{}, backend.ErrForbidden
	}
	return binding, nil
}
