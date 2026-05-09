package challenge

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/robertkrimen/otto"
)

var (
	challengePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)challenge-platform`),
		regexp.MustCompile(`(?i)checking.*browser`),
		regexp.MustCompile(`(?i)cf-chl-bypass`),
		regexp.MustCompile(`(?i)turnstile`),
		regexp.MustCompile(`(?i)jschl-answer`),
		regexp.MustCompile(`(?i)pass.*challenge`),
		regexp.MustCompile(`(?i)verify.*you.*are.*human`),
		regexp.MustCompile(`(?i)__cf_chl_jschl_tk__`),
		regexp.MustCompile(`(?i)window\._cf_chl_opt`),
	}

	jsExtractPatterns = []*regexp.Regexp{
		regexp.MustCompile(`var\s+s,\s*t,\s*a\s*=\s*function\s*\(\s*\)\s*{(.*?)};`),
		regexp.MustCompile(`function\s+solveChallenge\s*\(\s*\)\s*{(.*?)}\s*</script>`),
		regexp.MustCompile(`var\s+challengeResult\s*=\s*(.*?);`),
		regexp.MustCompile(`(?s)<script[^>]*>(.*?)window\.(?:location|location\.href)\s*=\s*(.*?)</script>`),
		regexp.MustCompile(`(?s)document\.(?:cookie|location)\s*=\s*(.*?)\s*;`),
	}
)

type Handler struct {
	client      HTTPClient
	targetURL   string
	maxAttempts int
}

type HTTPClient interface {
	Get(url string) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
	SetCookies(url string, cookies []*http.Cookie) error
	GetCookies(url string) ([]*http.Cookie, error)
}

type Result struct {
	Passed      bool
	Token       string
	Cookies     []*http.Cookie
	RedirectURL string
}

func (r *Result) ToHandleChallengeResult() *HandleChallengeResult {
	return &HandleChallengeResult{
		Passed:      r.Passed,
		Token:       r.Token,
		RedirectURL: r.RedirectURL,
	}
}

type HandleChallengeResult struct {
	Passed      bool
	Token       string
	RedirectURL string
}

func NewHandler(client HTTPClient, targetURL string) *Handler {
	return &Handler{
		client:      client,
		targetURL:   targetURL,
		maxAttempts: 3,
	}
}

func IsChallengePage(body string) bool {
	for _, pattern := range challengePatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

func (h *Handler) HandleChallenge(responseBody string) (*HandleChallengeResult, error) {
	if !IsChallengePage(responseBody) {
		return &HandleChallengeResult{Passed: true}, nil
	}

	jsCode, err := extractChallengeJS(responseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to extract challenge JS: %w", err)
	}

	token, err := executeChallengeJS(jsCode)
	if err != nil {
		return nil, fmt.Errorf("failed to execute challenge JS: %w", err)
	}

	cookies, err := extractChallengeCookies(responseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to extract challenge cookies: %w", err)
	}

	if len(cookies) > 0 {
		if err := h.client.SetCookies(h.targetURL, cookies); err != nil {
			return nil, fmt.Errorf("failed to set challenge cookies: %w", err)
		}
	}

	redirectURL := extractRedirectURL(responseBody)

	return &HandleChallengeResult{
		Passed:      true,
		Token:       token,
		RedirectURL: redirectURL,
	}, nil
}

func extractChallengeJS(html string) (string, error) {
	for _, pattern := range jsExtractPatterns {
		matches := pattern.FindStringSubmatch(html)
		if len(matches) > 1 {
			js := strings.TrimSpace(matches[1])
			if js != "" {
				return js, nil
			}
		}
	}

	scriptBlocks := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`).FindAllStringSubmatch(html, -1)
	for _, block := range scriptBlocks {
		if len(block) > 1 {
			js := strings.TrimSpace(block[1])
			if strings.Contains(js, "challenge") ||
				strings.Contains(js, "solve") ||
				strings.Contains(js, "token") ||
				strings.Contains(js, "document.cookie") {
				return js, nil
			}
		}
	}

	return "", fmt.Errorf("no challenge JS code found in response")
}

func executeChallengeJS(jsCode string) (string, error) {
	vm := otto.New()

	sandboxSetup := `
		var document = {
			cookie: "",
			location: { href: "", reload: function() {} },
			createElement: function() { return { setAttribute: function() {}, appendChild: function() {} }; },
			getElementsByTagName: function() { return []; },
			getElementById: function() { return null; }
		};
		var window = {
			location: { href: "", reload: function() {} },
			setTimeout: function() {},
			setInterval: function() {},
			_cf_chl_opt: {},
			_cf_chl_ctx: {}
		};
		var navigator = {
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			platform: "Win32",
			language: "zh-CN"
		};
		var location = window.location;
		var console = { log: function() {}, error: function() {}, warn: function() {} };
		var Date = function() { return new Date(); };
		Date.now = function() { return 0; };
		var Math = {
			random: function() { return 0.5; },
			floor: function(x) { return x; },
			round: function(x) { return x; },
			abs: function(x) { return x; },
			pow: function(x, y) { return Math.pow(x, y); },
			sqrt: function(x) { return x; },
			max: function() { return 0; },
			min: function() { return 0; }
		};
		var screen = { width: 1920, height: 1080, colorDepth: 24 };
		var performance = { now: function() { return 0; } };
	`

	if _, err := vm.Run(sandboxSetup); err != nil {
		return "", fmt.Errorf("failed to setup sandbox: %w", err)
	}

	if _, err := vm.Run(jsCode); err != nil {
		return "", fmt.Errorf("JS execution failed: %w", err)
	}

	if val, err := vm.Get("token"); err == nil {
		if str, err := val.ToString(); err == nil && str != "" {
			return str, nil
		}
	}

	if val, err := vm.Get("challengeResult"); err == nil {
		if str, err := val.ToString(); err == nil && str != "" {
			return str, nil
		}
	}

	if val, err := vm.Get("document.cookie"); err == nil {
		if str, err := val.ToString(); err == nil && str != "" {
			if token := extractTokenFromCookie(str); token != "" {
				return token, nil
			}
		}
	}

	return "", fmt.Errorf("challenge token not found after JS execution")
}

func extractChallengeCookies(html string) ([]*http.Cookie, error) {
	var cookies []*http.Cookie

	cookiePattern := regexp.MustCompile(`document\.cookie\s*=\s*["']([^"']+)["']`)
	matches := cookiePattern.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			cookieStr := match[1]
			parts := strings.SplitN(cookieStr, "=", 2)
			if len(parts) == 2 {
				cookies = append(cookies, &http.Cookie{
					Name:  strings.TrimSpace(parts[0]),
					Value: strings.TrimSpace(parts[1]),
					Path:  "/",
				})
			}
		}
	}

	setCookiePattern := regexp.MustCompile(`Set-Cookie:\s*([^;]+)=([^;]+)`)
	cookieMatches := setCookiePattern.FindAllStringSubmatch(html, -1)
	for _, match := range cookieMatches {
		if len(match) > 2 {
			cookies = append(cookies, &http.Cookie{
				Name:  strings.TrimSpace(match[1]),
				Value: strings.TrimSpace(match[2]),
				Path:  "/",
			})
		}
	}

	return cookies, nil
}

func extractTokenFromCookie(cookieStr string) string {
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "token") ||
			strings.Contains(part, "cf_clearance") ||
			strings.Contains(part, "challenge") {
			if idx := strings.Index(part, "="); idx != -1 {
				return strings.TrimSpace(part[idx+1:])
			}
		}
	}
	return ""
}

func extractRedirectURL(html string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`window\.location\.href\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`window\.location\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`document\.location\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`<meta[^>]+http-equiv=["']refresh["'][^>]+content=["']\d+;\s*url=([^"']+)["']`),
		regexp.MustCompile(`href=["'](https?://[^"']+)["'][^>]*redirect`),
	}

	for _, pattern := range patterns {
		match := pattern.FindStringSubmatch(html)
		if len(match) > 1 {
			return match[1]
		}
	}

	return ""
}
