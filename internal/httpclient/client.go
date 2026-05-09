package httpclient

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	connectTimeout   = 10 * time.Second
	maxRetries       = 3
)

var defaultHeaders = map[string]string{
	"Accept":                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"Accept-Encoding":         "gzip, deflate, br",
	"Accept-Language":         "zh-CN,zh;q=0.9,en;q=0.8",
	"Sec-Ch-Ua":               `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
	"Sec-Ch-Ua-Mobile":        `?0`,
	"Sec-Ch-Ua-Platform":      `"Windows"`,
	"Sec-Fetch-Dest":          "document",
	"Sec-Fetch-Mode":          "navigate",
	"Sec-Fetch-Site":          "none",
	"Sec-Fetch-User":          "?1",
	"Upgrade-Insecure-Requests": "1",
}

type Client struct {
	httpClient *http.Client
	cookieJar  http.CookieJar
	headers    map[string]string
	retries    int
}

type Option func(*Client) error

func WithCookie(cookieValue, targetURL string) Option {
	return func(c *Client) error {
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			return fmt.Errorf("failed to parse target URL: %w", err)
		}

		cookies := parseCookieString(cookieValue, parsedURL)
		c.cookieJar.SetCookies(parsedURL, cookies)
		c.httpClient.Jar = c.cookieJar
		return nil
	}
}

func WithHeaders(headers map[string]string) Option {
	return func(c *Client) error {
		for k, v := range headers {
			c.headers[k] = v
		}
		return nil
	}
}

func WithRetries(retries int) Option {
	return func(c *Client) error {
		if retries > 0 && retries <= 10 {
			c.retries = retries
		}
		return nil
	}
}

func NewClient(options ...Option) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &Client{
		cookieJar: jar,
		headers:   make(map[string]string),
		retries:   maxRetries,
	}

	for k, v := range defaultHeaders {
		client.headers[k] = v
	}

	client.httpClient = &http.Client{
		Timeout:   defaultTimeout,
		Jar:       client.cookieJar,
		Transport: newUTLSTransport(),
	}

	for _, opt := range options {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func newUTLSTransport() http.RoundTripper {
	// We use http2.Transport because uTLS HelloChrome_120 negotiates h2 via ALPN.
	// The standard http.Transport with ForceAttemptHTTP2 fails to detect h2 
	// when DialTLSContext is overridden with uTLS, causing HTTP/1.1 requests 
	// to be sent to an h2 connection, resulting in "malformed HTTP response".
	return &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   connectTimeout,
				KeepAlive: 30 * time.Second,
			}
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}

			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			uconn := utls.UClient(conn, &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: false,
			}, utls.HelloChrome_120)

			if err := uconn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("tls handshake failed: %w", err)
			}
			return uconn, nil
		},
	}
}

func (c *Client) Get(url string) (*http.Response, error) {
	return c.doWithRetry("GET", url, nil)
}

func (c *Client) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return c.doWithRetry("POST", url, body, func(req *http.Request) {
		req.Header.Set("Content-Type", contentType)
	})
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.doWithRetry(req.Method, req.URL.String(), req.Body, func(r *http.Request) {
		for k, v := range req.Header {
			r.Header[k] = v
		}
	})
}

func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	body := bytes.NewBufferString(data.Encode())
	return c.Post(url, "application/x-www-form-urlencoded", body)
}

func (c *Client) doWithRetry(method, url string, body io.Reader, opts ...func(*http.Request)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		resp, err := c.doRequest(method, url, body, opts...)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		if !isRetryableError(err) {
			break
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.retries, lastErr)
}

func (c *Client) doRequest(method, url string, body io.Reader, opts ...func(*http.Request)) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range c.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	resp.Body = &readCloser{
		Reader: newDecompressReader(resp),
		Closer: resp.Body,
	}

	return resp, nil
}

func (c *Client) GetCookies(targetURL string) ([]*http.Cookie, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	return c.cookieJar.Cookies(parsedURL), nil
}

func (c *Client) SetCookies(targetURL string, cookies []*http.Cookie) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	c.cookieJar.SetCookies(parsedURL, cookies)
	return nil
}

func parseCookieString(cookieStr string, targetURL *url.URL) []*http.Cookie {
	var cookies []*http.Cookie

	pairs := strings.Split(cookieStr, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if name == "" {
			continue
		}

		cookies = append(cookies, &http.Cookie{
			Name:   name,
			Value:  value,
			Domain: targetURL.Hostname(),
			Path:   "/",
		})
	}

	return cookies
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "no such host") ||
		strings.Contains(errMsg, "reset by peer")
}

type readCloser struct {
	io.Reader
	io.Closer
}

func newDecompressReader(resp *http.Response) io.Reader {
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return resp.Body
		}
		return reader
	default:
		return resp.Body
	}
}
