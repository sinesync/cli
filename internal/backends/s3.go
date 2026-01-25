package backends

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/miclip/sinesync/internal/config"
)

// S3Provider stores data in S3-compatible storage
// Works with AWS S3, MinIO, Backblaze B2, Cloudflare R2, etc.
type S3Provider struct {
	client *s3.Client
	bucket string
	prefix string
}

func (p *S3Provider) Name() string {
	return "s3"
}

func (p *S3Provider) Init(ctx context.Context, cfg *config.Backend) error {
	if cfg.Bucket == "" {
		return fmt.Errorf("s3 backend requires 'bucket' configuration")
	}

	p.bucket = cfg.Bucket
	p.prefix = "sinesync/" // namespace our data

	// Build AWS config
	var opts []func(*awsconfig.LoadOptions) error

	// Custom endpoint for MinIO, R2, etc.
	if cfg.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:               cfg.Endpoint,
					HostnameImmutable: true,
				}, nil
			})
		opts = append(opts, awsconfig.WithEndpointResolverWithOptions(customResolver))
	}

	// Region
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}

	// Static credentials (for BYOB)
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with path-style for compatibility
	p.client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true // Required for MinIO and some S3-compatible services
	})

	return nil
}

func (p *S3Provider) Push(ctx context.Context, id string, data []byte, meta Metadata) error {
	// Upload encrypted data
	dataKey := p.prefix + "data/" + id + ".enc"
	_, err := p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(dataKey),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload data: %w", err)
	}

	// Upload metadata
	metaKey := p.prefix + "meta/" + id + ".json"
	metaBytes, _ := json.Marshal(meta)
	_, err = p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(metaKey),
		Body:        bytes.NewReader(metaBytes),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload metadata: %w", err)
	}

	return nil
}

func (p *S3Provider) Pull(ctx context.Context, id string) ([]byte, error) {
	dataKey := p.prefix + "data/" + id + ".enc"

	result, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(dataKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	defer result.Body.Close()

	return io.ReadAll(result.Body)
}

func (p *S3Provider) Delete(ctx context.Context, id string) error {
	dataKey := p.prefix + "data/" + id + ".enc"
	metaKey := p.prefix + "meta/" + id + ".json"

	p.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(dataKey),
	})

	p.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(metaKey),
	})

	return nil
}

func (p *S3Provider) GetManifest(ctx context.Context) ([]ManifestItem, error) {
	metaPrefix := p.prefix + "meta/"

	paginator := s3.NewListObjectsV2Paginator(p.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(p.bucket),
		Prefix: aws.String(metaPrefix),
	})

	var items []ManifestItem

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if !strings.HasSuffix(key, ".json") {
				continue
			}

			// Extract ID from key
			id := strings.TrimPrefix(key, metaPrefix)
			id = strings.TrimSuffix(id, ".json")

			meta, err := p.GetMetadata(ctx, id)
			if err != nil {
				continue
			}

			items = append(items, ManifestItem{
				ID:        meta.ID,
				Checksum:  meta.Checksum,
				Size:      meta.Size,
				Project:   meta.Project,
				UpdatedAt: meta.UpdatedAt.Format("2006-01-02T15:04:05Z"),
				DeviceID:  meta.DeviceID,
			})
		}
	}

	return items, nil
}

func (p *S3Provider) GetMetadata(ctx context.Context, id string) (*Metadata, error) {
	metaKey := p.prefix + "meta/" + id + ".json"

	result, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(metaKey),
	})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func (p *S3Provider) Close() error {
	return nil
}
