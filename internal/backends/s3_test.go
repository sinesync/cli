package backends

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sinesync/cli/internal/config"
)

// Custom endpoints are how this backend reaches MinIO, Cloudflare R2 and
// Backblaze B2 — anything that is not AWS itself. They are configured through
// aws.EndpointResolverWithOptions, which the SDK has deprecated in favour of
// per-service EndpointResolverV2, and S3 is one of the services that migrated.
//
// A deprecation compiles silently. If a future bump makes S3 ignore the legacy
// resolver, every self-hosted user's traffic would quietly go to AWS instead of
// their own server, with nothing failing at build time to say so. This test
// asserts the request actually arrives where it was pointed.
func TestS3CustomEndpointIsHonoured(t *testing.T) {
	var (
		mu    sync.Mutex
		hits  int
		paths []string
		hosts []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		paths = append(paths, r.URL.Path)
		hosts = append(hosts, r.Host)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`))
	}))
	defer server.Close()

	p := &S3Provider{}
	err := p.Init(context.Background(), &config.Backend{
		Type:      "s3",
		Bucket:    "test-bucket",
		Endpoint:  server.URL,
		Region:    "us-east-1",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Any call will do; we care where it lands, not what it returns.
	_, _ = p.GetManifest(context.Background())

	mu.Lock()
	defer mu.Unlock()

	if hits == 0 {
		t.Fatal("the custom endpoint received NO requests — the SDK ignored " +
			"WithEndpointResolverWithOptions, so MinIO/R2/B2 users would be " +
			"silently talking to AWS instead of their own server")
	}
	t.Logf("custom endpoint received %d request(s): host=%v path=%v", hits, hosts, paths)

	// Path-style addressing is set explicitly for S3-compatible servers, which
	// mostly cannot do virtual-host style. Bucket in the path, not the hostname.
	for _, path := range paths {
		if !strings.Contains(path, "test-bucket") {
			t.Errorf("request path %q does not contain the bucket; path-style addressing was lost, "+
				"which breaks every S3-compatible server that cannot do virtual-host style", path)
		}
	}
}

// Uploads must keep working against a server that implements plain S3 and
// nothing else.
//
// aws-sdk-go-v2 v1.73 made PutObject send a CRC32 flexible-checksum header by
// default, and S3-compatible servers that predate that reject the request. This
// build does not send one — verified, not assumed — but the default is exactly
// the kind of thing a future bump flips silently, and the failure would land on
// self-hosted users rather than in CI. So assert it, and if it ever changes,
// set RequestChecksumCalculation to WhenRequired rather than deleting the test.
func TestS3PutWorksAgainstAPlainServer(t *testing.T) {
	var (
		mu      sync.Mutex
		puts    []string
		headers []http.Header
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			mu.Lock()
			puts = append(puts, r.URL.Path)
			headers = append(headers, r.Header.Clone())
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := &S3Provider{}
	if err := p.Init(context.Background(), &config.Backend{
		Type: "s3", Bucket: "test-bucket", Endpoint: server.URL,
		Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := p.Push(context.Background(), "obj1", []byte("payload"), Metadata{}); err != nil {
		t.Fatalf("Push failed against a plain S3 server: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(puts) == 0 {
		t.Fatal("no PUT reached the server, so this test proves nothing")
	}

	for i, h := range headers {
		for _, unsupported := range []string{
			"X-Amz-Checksum-Crc32",
			"X-Amz-Checksum-Crc32c",
			"X-Amz-Checksum-Sha256",
			"X-Amz-Sdk-Checksum-Algorithm",
		} {
			if v := h.Get(unsupported); v != "" {
				t.Errorf("PUT %s carries %s=%q. The SDK default changed; older MinIO/B2 "+
					"deployments will reject uploads. Set RequestChecksumCalculation to "+
					"WhenRequired on the client options.", puts[i], unsupported, v)
			}
		}
	}
}
