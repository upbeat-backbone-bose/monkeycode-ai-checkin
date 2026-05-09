package challenge

import (
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestIsChallengePage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "cloudflare challenge page",
			body: `<html><head><title>Just a moment...</title></head><body>
				<div id="challenge-platform">Checking your browser before accessing...</div>
				<script>var s,t,a=function(){/* challenge code */};</script>
				</body></html>`,
			want: true,
		},
		{
			name: "turnstile challenge",
			body: `<html><body>
				<div class="turnstile-container">
					<script src="https://challenges.cloudflare.com/turnstile/"></script>
				</div>
				</body></html>`,
			want: true,
		},
		{
			name: "jschl challenge",
			body: `<html><body>
				<form id="challenge-form" action="/cdn-cgi/l/chk_jschl" method="get">
					<input type="hidden" name="jschl_answer" value=""/>
					<input type="hidden" name="__cf_chl_jschl_tk__" value="abc123"/>
				</form>
				</body></html>`,
			want: true,
		},
		{
			name: "verify human page",
			body: `<html><body>
				<h1>Verify you are human</h1>
				<p>Please complete the security check to continue.</p>
				</body></html>`,
			want: true,
		},
		{
			name: "normal page",
			body: `<html><body>
				<h1>Welcome to our website</h1>
				<p>This is a normal page without any challenge.</p>
				</body></html>`,
			want: false,
		},
		{
			name: "api response",
			body: `{"success": true, "message": "ok"}`,
			want: false,
		},
		{
			name: "cf_chl_opt pattern",
			body: `<script>window._cf_chl_opt = { cType: "managed", cRay: "abc123" };</script>`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsChallengePage(tt.body)
			if got != tt.want {
				t.Errorf("IsChallengePage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractChallengeJS(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantErr bool
		wantJS  string
	}{
		{
			name: "extract from script block",
			html: `<script>
				var s, t, a = function() {
					var challenge = "test_challenge_token";
					return challenge;
				};
			</script>`,
			wantErr: false,
			wantJS:  `var s, t, a = function() {
					var challenge = "test_challenge_token";
					return challenge;
				};`,
		},
		{
			name: "extract challenge result",
			html: `<script>var challengeResult = "token_12345";</script>`,
			wantErr: false,
			wantJS:  `"token_12345"`,
		},
		{
			name: "extract from document.cookie",
			html: `<script>document.cookie = "cf_clearance=abc123";</script>`,
			wantErr: false,
			wantJS:  `"cf_clearance=abc123"`,
		},
		{
			name:    "no challenge js found",
			html:    `<html><body><p>No scripts here</p></body></html>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractChallengeJS(tt.html)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractChallengeJS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.wantJS {
				t.Errorf("extractChallengeJS() = %v, want %v", got, tt.wantJS)
			}
		})
	}
}

func TestExtractChallengeCookies(t *testing.T) {
	tests := []struct {
		name        string
		html        string
		wantCount   int
		wantCookies map[string]string
	}{
		{
			name: "extract from document.cookie",
			html: `<script>document.cookie = "cf_clearance=abc123";
document.cookie = "session=xyz789";</script>`,
			wantCount: 2,
			wantCookies: map[string]string{
				"cf_clearance": "abc123",
				"session":      "xyz789",
			},
		},
		{
			name:        "no cookies",
			html:        `<html><body>No cookies</body></html>`,
			wantCount:   0,
			wantCookies: map[string]string{},
		},
		{
			name: "extract Set-Cookie headers",
			html: `<html><body>
				<p>Set-Cookie: cf_clearance=def456; Path=/; HttpOnly</p>
				<p>Set-Cookie: session=ghi012; Path=/</p>
				</body></html>`,
			wantCount: 2,
			wantCookies: map[string]string{
				"cf_clearance": "def456",
				"session":      "ghi012",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookies, err := extractChallengeCookies(tt.html)
			if err != nil {
				t.Errorf("extractChallengeCookies() error = %v", err)
				return
			}
			if len(cookies) != tt.wantCount {
				t.Errorf("extractChallengeCookies() got %d cookies, want %d", len(cookies), tt.wantCount)
			}
			for _, cookie := range cookies {
				if expectedValue, ok := tt.wantCookies[cookie.Name]; ok {
					if cookie.Value != expectedValue {
						t.Errorf("cookie %s: got value %q, want %q", cookie.Name, cookie.Value, expectedValue)
					}
				}
			}
		})
	}
}

func TestExtractTokenFromCookie(t *testing.T) {
	tests := []struct {
		name      string
		cookieStr string
		want      string
	}{
		{
			name:      "cf_clearance token",
			cookieStr: "cf_clearance=abc123; Path=/; HttpOnly",
			want:      "abc123",
		},
		{
			name:      "session token",
			cookieStr: "token=xyz789; cf_clearance=def456",
			want:      "xyz789",
		},
		{
			name:      "no token",
			cookieStr: "user=john; lang=en",
			want:      "",
		},
		{
			name:      "challenge cookie",
			cookieStr: "challenge_token=token123",
			want:      "token123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTokenFromCookie(tt.cookieStr)
			if got != tt.want {
				t.Errorf("extractTokenFromCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRedirectURL(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "window.location.href",
			html: `<script>window.location.href = "https://example.com/dashboard";</script>`,
			want: "https://example.com/dashboard",
		},
		{
			name: "window.location",
			html: `<script>window.location = "/checkin";</script>`,
			want: "/checkin",
		},
		{
			name: "meta refresh",
			html: `<meta http-equiv="refresh" content="5; url=https://example.com/checkin">`,
			want: "https://example.com/checkin",
		},
		{
			name: "no redirect",
			html: `<html><body>No redirect</body></html>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRedirectURL(tt.html)
			if got != tt.want {
				t.Errorf("extractRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecuteChallengeJS(t *testing.T) {
	tests := []struct {
		name    string
		jsCode  string
		wantErr bool
		wantToken bool
	}{
		{
			name: "simple token assignment",
			jsCode: `var token = "test_token_123";`,
			wantErr: false,
			wantToken: true,
		},
		{
			name: "challenge result",
			jsCode: `var challengeResult = "challenge_456";`,
			wantErr: false,
			wantToken: true,
		},
		{
			name: "document cookie assignment",
			jsCode: `document.cookie = "cf_clearance=cookie789";`,
			wantErr: false,
			wantToken: true,
		},
		{
			name: "complex challenge",
			jsCode: `
				var a = 1 + 2;
				var b = a * 3;
				var token = "token_" + b;
			`,
			wantErr: false,
			wantToken: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeChallengeJS(tt.jsCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("executeChallengeJS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if tt.wantToken && got == "" {
					t.Error("executeChallengeJS() returned empty token")
				}
			}
		})
	}
}

func TestHandler_HandleChallenge(t *testing.T) {
	mockClient := &mockHTTPClient{
		cookies: make(map[string][]*http.Cookie),
	}

	handler := NewHandler(mockClient, "https://example.com")

	tests := []struct {
		name        string
		responseBody string
		wantPassed  bool
		wantErr     bool
	}{
		{
			name:        "non-challenge page",
			responseBody: `<html><body>Welcome</body></html>`,
			wantPassed:  true,
			wantErr:     false,
		},
		{
			name: "challenge page with token",
			responseBody: `<html>
				<div id="challenge-platform">Checking browser...</div>
				<script>var token = "challenge_passed";</script>
				</html>`,
			wantPassed:  true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := handler.HandleChallenge(tt.responseBody)
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result.Passed != tt.wantPassed {
				t.Errorf("HandleChallenge() result.Passed = %v, want %v", result.Passed, tt.wantPassed)
			}
		})
	}
}

type mockHTTPClient struct {
	cookies map[string][]*http.Cookie
}

func (m *mockHTTPClient) Get(url string) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

func (m *mockHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

func (m *mockHTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

func (m *mockHTTPClient) SetCookies(url string, cookies []*http.Cookie) error {
	m.cookies[url] = cookies
	return nil
}

func (m *mockHTTPClient) GetCookies(url string) ([]*http.Cookie, error) {
	return m.cookies[url], nil
}
