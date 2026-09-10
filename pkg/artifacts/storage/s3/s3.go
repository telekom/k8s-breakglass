// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

const (
	runtimeBindingHeader = "runtime-binding-sha256"
	sha256Header         = "sha256"
)

// Store is a versioned, create-only S3 artifact store. The client is created
// from administrator-owned configuration and is never reconstructed from an
// HTTP request.
type Store struct {
	client       *awss3.Client
	config       Config
	instanceID   string
	maximumBytes int64
}

// New constructs a store with an administrator-owned credential provider. The
// provider is never derived from an artifact request or collector Job.
func New(config Config, credentials aws.CredentialsProvider) (*Store, error) {
	validated, err := config.validate()
	if err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, errors.New("administrator-owned S3 credentials are required")
	}
	awsConfig := aws.Config{Region: validated.Region, Credentials: credentials}
	client := awss3.NewFromConfig(awsConfig, func(options *awss3.Options) {
		if validated.Endpoint != "" {
			options.BaseEndpoint = aws.String(validated.Endpoint)
		}
		options.UsePathStyle = validated.UsePathStyle
	})
	return NewWithClient(client, validated)
}

// NewWithClient is useful for contract tests and for callers that construct
// an AWS client with an explicitly managed credential provider.
func NewWithClient(client *awss3.Client, config Config) (*Store, error) {
	validated, err := config.validate()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("s3 client is required")
	}
	return &Store{client: client, config: validated, instanceID: validated.InstanceID, maximumBytes: validated.MaximumObjectBytes}, nil
}

func (store *Store) Backend() string { return artifactstorage.BackendS3 }

func (store *Store) BackendInstanceID() string {
	if store == nil {
		return ""
	}
	return store.instanceID
}

// Verify checks the startup fence. The bucket must remain versioned and the
// administrator-provisioned sentinel must identify the same backend instance.
// This is deliberately separate from New so construction never performs a
// provider mutation or network request unexpectedly.
func (store *Store) Verify(ctx context.Context) error {
	if store == nil || store.client == nil {
		return artifactstorage.ErrBackendDrift
	}
	versioning, err := store.client.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{Bucket: aws.String(store.config.Bucket)})
	if err != nil {
		return fmt.Errorf("verify S3 bucket versioning: %w", err)
	}
	if versioning.Status != "Enabled" {
		return fmt.Errorf("S3 artifact bucket versioning is not enabled: %w", artifactstorage.ErrBackendDrift)
	}
	output, err := store.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(store.sentinelKey())})
	if err != nil {
		return fmt.Errorf("verify S3 artifact sentinel: %w", artifactstorage.ErrBackendDrift)
	}
	if output.Metadata == nil || output.Metadata["instance-id"] != store.instanceID {
		return fmt.Errorf("S3 artifact sentinel identifies a different instance: %w", artifactstorage.ErrBackendDrift)
	}
	return nil
}

// ProvisionSentinel performs the one administrator-owned sentinel creation.
// It is separate from Verify and should be run as part of storage provisioning,
// never from an artifact request path.
func (store *Store) ProvisionSentinel(ctx context.Context) error {
	if store == nil || store.client == nil {
		return artifactstorage.ErrBackendDrift
	}
	_, err := store.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(store.config.Bucket), Key: aws.String(store.sentinelKey()),
		Body: strings.NewReader(store.instanceID), IfNoneMatch: aws.String("*"),
		Metadata: map[string]string{"instance-id": store.instanceID},
	})
	if err != nil {
		if isPreconditionFailed(err) {
			return artifactstorage.ErrAlreadyExists
		}
		return fmt.Errorf("provision S3 artifact sentinel: %w", err)
	}
	return nil
}

func (store *Store) PutIfAbsent(ctx context.Context, object artifactstorage.Object, source io.Reader) (metadata artifactstorage.Metadata, result error) {
	if err := store.ready(object); err != nil {
		return metadata, err
	}
	if ctx == nil || source == nil {
		return metadata, errors.New("s3 artifact source and context are required")
	}
	key, err := store.key(object.Key)
	if err != nil {
		return metadata, err
	}
	digesting := &boundedDigestReader{reader: io.LimitReader(source, object.Size+1), expected: object.Size, expectedSHA256: object.SHA256}
	output, err := store.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:      aws.String(store.config.Bucket),
		Key:         aws.String(key),
		Body:        digesting,
		ContentType: aws.String("application/gzip"),
		IfNoneMatch: aws.String("*"),
		Metadata: map[string]string{
			runtimeBindingHeader: object.RuntimeBindingDigest,
			sha256Header:         object.SHA256,
		},
	})
	if err != nil {
		if isPreconditionFailed(err) {
			return metadata, artifactstorage.ErrAlreadyExists
		}
		return metadata, fmt.Errorf("put S3 artifact object: %w", err)
	}
	if err := digesting.Err(); err != nil {
		if cleanupErr := store.deleteOutput(ctx, key, output.VersionId); cleanupErr != nil {
			return metadata, errors.Join(fmt.Errorf("validate S3 artifact source: %w", err), cleanupErr, artifactstorage.ErrAmbiguous)
		}
		return metadata, fmt.Errorf("validate S3 artifact source: %w", err)
	}
	versionID := aws.ToString(output.VersionId)
	if versionID == "" {
		return metadata, fmt.Errorf("S3 provider returned no version ID: %w", artifactstorage.ErrAmbiguous)
	}
	modified := time.Now().UTC()
	metadata = artifactstorage.Metadata{
		BackendInstanceID:    store.instanceID,
		Key:                  object.Key,
		VersionID:            versionID,
		RuntimeBindingDigest: object.RuntimeBindingDigest,
		Size:                 object.Size,
		SHA256:               object.SHA256,
		ETag:                 strings.Trim(aws.ToString(output.ETag), `"`),
		ProviderChecksum:     aws.ToString(output.ChecksumSHA256),
		ModifiedAt:           modified,
	}
	return metadata, nil
}

func (store *Store) OpenVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (io.ReadCloser, artifactstorage.Metadata, error) {
	actual, err := store.StatVersion(ctx, object, expected)
	if err != nil {
		return nil, artifactstorage.Metadata{}, err
	}
	key, err := store.key(object.Key)
	if err != nil {
		return nil, artifactstorage.Metadata{}, err
	}
	output, err := store.client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(store.config.Bucket), Key: aws.String(key), VersionId: aws.String(actual.VersionID),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, artifactstorage.Metadata{}, artifactstorage.ErrNotFound
		}
		return nil, artifactstorage.Metadata{}, fmt.Errorf("open S3 artifact version: %w", err)
	}
	return &verifiedReadCloser{body: output.Body, expected: object, onClose: func() error { return output.Body.Close() }}, actual, nil
}

func (store *Store) StatVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (artifactstorage.Metadata, error) {
	if err := store.ready(object); err != nil {
		return artifactstorage.Metadata{}, err
	}
	key, err := store.key(object.Key)
	if err != nil {
		return artifactstorage.Metadata{}, err
	}
	if expected.VersionID == "" || expected.Key != object.Key || expected.BackendInstanceID != store.instanceID {
		return artifactstorage.Metadata{}, artifactstorage.ErrConflict
	}
	output, err := store.client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(store.config.Bucket), Key: aws.String(key), VersionId: aws.String(expected.VersionID),
	})
	if err != nil {
		if isNotFound(err) {
			return artifactstorage.Metadata{}, artifactstorage.ErrNotFound
		}
		return artifactstorage.Metadata{}, fmt.Errorf("stat S3 artifact version: %w", err)
	}
	actual := metadataFromHead(store.instanceID, object.Key, expected.VersionID, output)
	if actual.RuntimeBindingDigest != object.RuntimeBindingDigest || actual.SHA256 != object.SHA256 || actual.Size != object.Size ||
		actual.BackendInstanceID != expected.BackendInstanceID || actual.VersionID != expected.VersionID {
		return artifactstorage.Metadata{}, artifactstorage.ErrConflict
	}
	return actual, nil
}

func (store *Store) Inventory(ctx context.Context, object artifactstorage.Object) ([]artifactstorage.Version, error) {
	if err := store.ready(object); err != nil {
		return nil, err
	}
	key, err := store.key(object.Key)
	if err != nil {
		return nil, err
	}
	paginator := awss3.NewListObjectVersionsPaginator(store.client, &awss3.ListObjectVersionsInput{
		Bucket: aws.String(store.config.Bucket), Prefix: aws.String(key), MaxKeys: aws.Int32(100),
	})
	versions := make([]artifactstorage.Version, 0, 2)
	for paginator.HasMorePages() {
		page, pageErr := paginator.NextPage(ctx)
		if pageErr != nil {
			return nil, fmt.Errorf("inventory S3 artifact versions: %w", pageErr)
		}
		for _, entry := range page.Versions {
			if aws.ToString(entry.Key) != key {
				continue
			}
			version := artifactstorage.Version{VersionID: aws.ToString(entry.VersionId), ETag: strings.Trim(aws.ToString(entry.ETag), `"`), ModifiedAt: aws.ToTime(entry.LastModified)}
			metadata, headErr := store.headVersion(ctx, object, key, version.VersionID)
			if headErr != nil {
				return nil, fmt.Errorf("inventory exact S3 artifact version: %w", headErr)
			}
			version.RuntimeBindingDigest = metadata.RuntimeBindingDigest
			version.Size = metadata.Size
			version.SHA256 = metadata.SHA256
			version.ProviderChecksum = metadata.ProviderChecksum
			versions = append(versions, version)
		}
		for _, marker := range page.DeleteMarkers {
			if aws.ToString(marker.Key) == key {
				versions = append(versions, artifactstorage.Version{VersionID: aws.ToString(marker.VersionId), DeleteMarker: true, ModifiedAt: aws.ToTime(marker.LastModified)})
			}
		}
	}
	return versions, nil
}

func (store *Store) DeleteVersion(ctx context.Context, object artifactstorage.Object, version artifactstorage.Version) error {
	if err := store.ready(object); err != nil {
		return err
	}
	if version.DeleteMarker || version.VersionID == "" {
		return artifactstorage.ErrConflict
	}
	key, err := store.key(object.Key)
	if err != nil {
		return err
	}
	metadata, err := store.headVersion(ctx, object, key, version.VersionID)
	if err != nil {
		return err
	}
	if metadata.RuntimeBindingDigest != object.RuntimeBindingDigest || metadata.SHA256 != object.SHA256 || metadata.Size != object.Size ||
		(version.ETag != "" && metadata.ETag != version.ETag) ||
		(version.ProviderChecksum != "" && metadata.ProviderChecksum != version.ProviderChecksum) {
		return artifactstorage.ErrConflict
	}
	output, err := store.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(key), VersionId: aws.String(version.VersionID)})
	if err != nil {
		return fmt.Errorf("delete exact S3 artifact version: %w", err)
	}
	if aws.ToString(output.VersionId) != "" && aws.ToString(output.VersionId) != version.VersionID {
		return fmt.Errorf("S3 provider deleted an unexpected version: %w", artifactstorage.ErrAmbiguous)
	}
	return nil
}

func (store *Store) ready(object artifactstorage.Object) error {
	if store == nil || store.client == nil {
		return errors.New("S3 artifact store is closed")
	}
	if object.Key == "" || object.RuntimeBindingDigest == "" || object.SHA256 == "" || object.Size < 1 || object.Size > store.maximumBytes {
		return errors.New("S3 artifact object is outside its bounded contract")
	}
	return nil
}

func (store *Store) key(key string) (string, error) {
	if key == "" || strings.ContainsAny(key, "\x00\r\n") || strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return "", errors.New("S3 artifact key is invalid")
	}
	if store.config.Prefix == "" {
		return key, nil
	}
	return store.config.Prefix + "/" + key, nil
}

func (store *Store) sentinelKey() string {
	if store.config.Prefix == "" {
		return sentinelName
	}
	return store.config.Prefix + "/" + sentinelName
}

func (store *Store) headVersion(ctx context.Context, object artifactstorage.Object, key, versionID string) (artifactstorage.Metadata, error) {
	output, err := store.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if err != nil {
		if isNotFound(err) {
			return artifactstorage.Metadata{}, artifactstorage.ErrNotFound
		}
		return artifactstorage.Metadata{}, fmt.Errorf("head S3 artifact version: %w", err)
	}
	return metadataFromHead(store.instanceID, object.Key, versionID, output), nil
}

func (store *Store) deleteOutput(ctx context.Context, key string, versionID *string) error {
	if aws.ToString(versionID) == "" {
		return fmt.Errorf("S3 artifact version is unknown: %w", artifactstorage.ErrAmbiguous)
	}
	_, err := store.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(store.config.Bucket), Key: aws.String(key), VersionId: versionID})
	if err != nil {
		return fmt.Errorf("remove invalid S3 artifact version: %w", err)
	}
	return nil
}

func metadataFromHead(instanceID, key, versionID string, output *awss3.HeadObjectOutput) artifactstorage.Metadata {
	runtimeBinding := ""
	sha := ""
	if output.Metadata != nil {
		runtimeBinding = output.Metadata[runtimeBindingHeader]
		sha = output.Metadata[sha256Header]
	}
	return artifactstorage.Metadata{BackendInstanceID: instanceID, Key: key, VersionID: versionID, RuntimeBindingDigest: runtimeBinding, Size: aws.ToInt64(output.ContentLength), SHA256: sha, ETag: strings.Trim(aws.ToString(output.ETag), `"`), ProviderChecksum: aws.ToString(output.ChecksumSHA256), ModifiedAt: aws.ToTime(output.LastModified)}
}

func isNotFound(err error) bool {
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "NoSuchKey" || code == "NoSuchVersion" || code == "NotFound"
	}
	return false
}

func isPreconditionFailed(err error) bool {
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "PreconditionFailed" || code == "ConditionalRequestConflict"
	}
	return false
}

type boundedDigestReader struct {
	reader         io.Reader
	expected       int64
	expectedSHA256 string
	read           int64
	hash           hash.Hash
	err            error
}

func (reader *boundedDigestReader) Read(p []byte) (int, error) {
	if reader.hash == nil {
		reader.hash = sha256.New()
	}
	n, err := reader.reader.Read(p)
	if n > 0 {
		reader.read += int64(n)
		_, _ = reader.hash.Write(p[:n])
	}
	if err != nil && !errors.Is(err, io.EOF) {
		reader.err = err
	}
	return n, err
}

func (reader *boundedDigestReader) Err() error {
	if reader.err != nil {
		return reader.err
	}
	if reader.read != reader.expected {
		return fmt.Errorf("artifact source size %d does not match expected size %d", reader.read, reader.expected)
	}
	if reader.hash == nil {
		reader.hash = sha256.New()
	}
	if hex.EncodeToString(reader.hash.Sum(nil)) != reader.expectedSHA256 {
		return fmt.Errorf("artifact source digest does not match expected digest")
	}
	return nil
}

type verifiedReadCloser struct {
	body     io.ReadCloser
	expected artifactstorage.Object
	hash     hash.Hash
	read     int64
	complete bool
	onClose  func() error
}

func (reader *verifiedReadCloser) Read(p []byte) (int, error) {
	if reader.hash == nil {
		reader.hash = sha256.New()
	}
	n, err := reader.body.Read(p)
	if n > 0 {
		reader.read += int64(n)
		_, _ = reader.hash.Write(p[:n])
		if reader.read > reader.expected.Size {
			return n, artifactstorage.ErrConflict
		}
	}
	if errors.Is(err, io.EOF) {
		if reader.read != reader.expected.Size || hex.EncodeToString(reader.hash.Sum(nil)) != reader.expected.SHA256 {
			return n, artifactstorage.ErrConflict
		}
		reader.complete = true
	}
	return n, err
}

func (reader *verifiedReadCloser) Close() error {
	closeErr := reader.onClose()
	if !reader.complete {
		return errors.Join(closeErr, artifactstorage.ErrConflict)
	}
	return closeErr
}

var _ artifactstorage.Store = (*Store)(nil)
