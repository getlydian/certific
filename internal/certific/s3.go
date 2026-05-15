package certific

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// ErrNotFound is returned by ObjectStore.Get and ObjectStore.Head when the
// object does not exist. Callers distinguish "first deploy, nothing
// uploaded yet" (tolerated) from "S3 is broken" (loud).
var ErrNotFound = errors.New("object not found")

// ObjectStore is the narrow surface of S3 we depend on. Three operations
// is enough to express the upload/download flows: Head to cheaply detect
// changes by etag, Get to fetch a new object, Put to push one. The
// interface exists purely so uploader/downloader can be tested against an
// in-memory fake — no live AWS in CI.
type ObjectStore interface {
	// Get fetches the object at key. The returned ReadCloser is the
	// object body; callers must Close it. Returns ErrNotFound if the
	// object does not exist.
	Get(ctx context.Context, key string) (body io.ReadCloser, etag string, err error)

	// Put uploads body as the object at key. contentLength must match
	// the number of bytes in body; the SDK requires it for signed
	// uploads and we surface it to make accidental truncation impossible
	// to ignore at the call site.
	Put(ctx context.Context, key string, body io.Reader, contentLength int64) error

	// Head returns the object's etag and last-modified time without
	// fetching the body. Returns ErrNotFound if the object does not
	// exist. The downloader uses this on every poll to avoid
	// re-downloading an unchanged blob.
	Head(ctx context.Context, key string) (etag string, lastModified time.Time, err error)
}

// s3API is the subset of the generated S3 client we use. Declaring it
// lets unit tests stub the SDK without dragging in the full client; the
// production constructor binds it to *s3.Client.
type s3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// S3Store is the production ObjectStore backed by the AWS SDK.
type S3Store struct {
	client s3API
	bucket string
}

// NewS3Store builds an S3Store from the resolved Config. Region is
// optional (the SDK's default chain handles env/profile/IMDS); Endpoint
// is plumbed through for S3-compatible stores (MinIO, Ceph, etc.) and
// forces path-style addressing since vhost-style URLs rarely work
// against non-AWS endpoints.
func NewS3Store(ctx context.Context, cfg Config) (*S3Store, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if cfg.Endpoint != "" {
		endpoint := cfg.Endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		})
	}

	return &S3Store{
		client: s3.NewFromConfig(awsCfg, clientOpts...),
		bucket: cfg.Bucket,
	}, nil
}

func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("s3 get %s/%s: %w", s.bucket, key, err)
	}
	return out.Body, aws.ToString(out.ETag), nil
}

func (s *S3Store) Put(ctx context.Context, key string, body io.Reader, contentLength int64) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(contentLength),
	})
	if err != nil {
		return fmt.Errorf("s3 put %s/%s: %w", s.bucket, key, err)
	}
	return nil
}

func (s *S3Store) Head(ctx context.Context, key string) (string, time.Time, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return "", time.Time{}, ErrNotFound
		}
		return "", time.Time{}, fmt.Errorf("s3 head %s/%s: %w", s.bucket, key, err)
	}
	var lastMod time.Time
	if out.LastModified != nil {
		lastMod = *out.LastModified
	}
	return aws.ToString(out.ETag), lastMod, nil
}

// isNotFound maps the SDK's several flavours of "object missing" to a
// single bool. HeadObject returns a generic smithy.APIError with code
// "NotFound" (no typed *types.NoSuchKey, because Head has no body), while
// GetObject returns *types.NoSuchKey. Both must collapse to ErrNotFound
// so callers can switch on a single sentinel.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}
