package httpclient

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseCookieString(t *testing.T) {
	tests := []struct {
		name      string
		cookieStr string
		targetURL string
		wantCount int
		wantNames map[string]string
	}{
		{
			name:      "single cookie",
			cookieStr: "session=abc123",
			targetURL: "https://example.com",
			wantCount: 1,
			wantNames: map[string]string{"session": "abc123"},
		},
		{
			name:      "multiple cookies",
			cookieStr: "session=abc123; token=xyz789; user=john",
			targetURL: "https://example.com",
			wantCount: 3,
			wantNames: map[string]string{"session": "abc123", "token": "xyz789", "user": "john"},
		},
		{
			name:      "cookies with spaces",
			cookieStr: " session=abc123 ; token=xyz789 ",
			targetURL: "https://example.com",
			wantCount: 2,
			wantNames: map[string]string{"session": "abc123", "token": "xyz789"},
		},
		{
			name:      "empty cookie string",
			cookieStr: "",
			targetURL: "https://example.com",
			wantCount: 0,
			wantNames: map[string]string{},
		},
		{
			name:      "cookie with equals in value",
			cookieStr: "data=key=value; session=abc",
			targetURL: "https://example.com",
			wantCount: 2,
			wantNames: map[string]string{"data": "key=value", "session": "abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			cookies := parseCookieString(tt.cookieStr, parsedURL)

			if len(cookies) != tt.wantCount {
				t.Errorf("got %d cookies, want %d", len(cookies), tt.wantCount)
			}

			for _, cookie := range cookies {
				if expectedValue, ok := tt.wantNames[cookie.Name]; ok {
					if cookie.Value != expectedValue {
						t.Errorf("cookie %s: got value %q, want %q", cookie.Name, cookie.Value, expectedValue)
					}
				}
				if cookie.Domain != parsedURL.Hostname() {
					t.Errorf("cookie %s: got domain %q, want %q", cookie.Name, cookie.Domain, parsedURL.Hostname())
				}
				if cookie.Path != "/" {
					t.Errorf("cookie %s: got path %q, want /", cookie.Name, cookie.Path)
				}
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"timeout error", &testError{"request timeout"}, true},
		{"connection refused", &testError{"connection refused"}, true},
		{"no such host", &testError{"no such host"}, true},
		{"reset by peer", &testError{"connection reset by peer"}, true},
		{"non-retryable error", &testError{"404 not found"}, false},
		{"business error", &testError{"already checked in"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableError(tt.err)
			if got != tt.want {
				t.Errorf("isRetryableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestNewClientDefaultHeaders(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	for k, expectedValue := range defaultHeaders {
		if gotValue, ok := client.headers[k]; !ok || gotValue != expectedValue {
			t.Errorf("header %s: got %q, want %q", k, gotValue, expectedValue)
		}
	}

	if client.retries != maxRetries {
		t.Errorf("retries: got %d, want %d", client.retries, maxRetries)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	customHeaders := map[string]string{"X-Custom": "test"}
	customRetries := 5

	client, err := NewClient(
		WithHeaders(customHeaders),
		WithRetries(customRetries),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.headers["X-Custom"] != "test" {
		t.Errorf("custom header: got %q, want test", client.headers["X-Custom"])
	}

	if client.retries != customRetries {
		t.Errorf("retries: got %d, want %d", client.retries, customRetries)
	}
}

func TestClientGetWithTestServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET request, got %s", r.Method)
		}
		if !strings.Contains(r.Header.Get("User-Agent"), "Chrome") {
			t.Errorf("User-Agent should contain Chrome, got: %s", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Accept-Language") == "" {
			t.Error("Accept-Language header should be set")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Replace transport with standard transport for testing
	client.httpClient.Transport = nil

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClientPostWithTestServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", contentType)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient.Transport = nil

	resp, err := client.Post(server.URL, "application/json", strings.NewReader(`{"test": true}`))
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClientPostFormWithTestServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type: got %q, want application/x-www-form-urlencoded", contentType)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	client.httpClient.Transport = nil

	data := url.Values{"key": []string{"value"}, "name": []string{"test"}}
	resp, err := client.PostForm(server.URL, data)
	if err != nil {
		t.Fatalf("PostForm() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
