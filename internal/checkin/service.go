package checkin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/monkeycode-ai/checkin/internal/challenge"
)

type ErrorType string

const (
	ErrNetwork      ErrorType = "NETWORK_ERROR"
	ErrTLSFingerprint ErrorType = "TLS_FINGERPRINT"
	ErrChallenge    ErrorType = "CHALLENGE_FAILED"
	ErrAuth         ErrorType = "AUTH_EXPIRED"
	ErrBusiness     ErrorType = "BUSINESS_ERROR"
	ErrWAF          ErrorType = "WAF_BLOCKED"
	ErrAPIChange    ErrorType = "API_CHANGED"
)

type CheckinError struct {
	Type    ErrorType
	Message string
	Err     error
}

func (e *CheckinError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

func (e *CheckinError) Unwrap() error {
	return e.Err
}

type CheckinResult struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	Points       int       `json:"points"`
	PointsGained int       `json:"points_gained"`
	StreakDays   int       `json:"streak_days"`
	Timestamp    time.Time `json:"timestamp"`
}

type Service struct {
	httpClient  HTTPClient
	challenge   ChallengeHandler
	targetURL   string
	checkinPath string
}

type HTTPClient interface {
	Get(url string) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}

type ChallengeHandler interface {
	HandleChallenge(responseBody string) (*challenge.HandleChallengeResult, error)
}

func NewService(httpClient HTTPClient, challenge ChallengeHandler, targetURL string) *Service {
	return &Service{
		httpClient:  httpClient,
		challenge:   challenge,
		targetURL:   targetURL,
		checkinPath: "/api/checkin",
	}
}

func (s *Service) DoCheckin() (*CheckinResult, error) {
	homeURL := s.targetURL
	if homeURL[len(homeURL)-1] != '/' {
		homeURL += "/"
	}

	resp, err := s.httpClient.Get(homeURL)
	if err != nil {
		return nil, &CheckinError{
			Type:    ErrNetwork,
			Message: "failed to access homepage",
			Err:     err,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: "failed to read response body",
			Err:     err,
		}
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, &CheckinError{
			Type:    ErrWAF,
			Message: "access forbidden by WAF",
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusFound {
		return nil, &CheckinError{
			Type:    ErrAuth,
			Message: "cookie may have expired, please update MONKEYCODE_COOKIE",
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		time.Sleep(60 * time.Second)
		resp, err = s.httpClient.Get(homeURL)
		if err != nil {
			return nil, &CheckinError{
				Type:    ErrNetwork,
				Message: "retry after 429 failed",
				Err:     err,
			}
		}
		defer resp.Body.Close()
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, &CheckinError{
				Type:    ErrAPIChange,
				Message: "failed to read retry response body",
				Err:     err,
			}
		}
	}

	bodyStr := string(body)
	if s.isChallengePage(bodyStr) {
		result, err := s.challenge.HandleChallenge(bodyStr)
		if err != nil {
			return nil, &CheckinError{
				Type:    ErrChallenge,
				Message: "failed to pass challenge",
				Err:     err,
			}
		}
		if !result.Passed {
			return nil, &CheckinError{
				Type:    ErrChallenge,
				Message: "challenge verification failed",
			}
		}

		if result.RedirectURL != "" {
			redirectURL := result.RedirectURL
			if redirectURL[0] == '/' {
				redirectURL = s.targetURL + redirectURL
			}
			resp, err = s.httpClient.Get(redirectURL)
			if err != nil {
				return nil, &CheckinError{
					Type:    ErrNetwork,
					Message: "failed to follow challenge redirect",
					Err:     err,
				}
			}
			defer resp.Body.Close()
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, &CheckinError{
					Type:    ErrAPIChange,
					Message: "failed to read redirect response body",
					Err:     err,
				}
			}
			bodyStr = string(body)
		}
	}

	checkinURL := s.targetURL + s.checkinPath
	if checkinURL[len(s.targetURL)-1] != '/' && s.checkinPath[0] != '/' {
		checkinURL = s.targetURL + "/" + s.checkinPath
	}

	resp, err = s.httpClient.Post(checkinURL, "application/json", nil)
	if err != nil {
		return nil, &CheckinError{
			Type:    ErrNetwork,
			Message: "failed to call checkin API",
			Err:     err,
		}
	}
	defer resp.Body.Close()

	checkinBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: "failed to read checkin response",
			Err:     err,
		}
	}

	result, err := s.parseCheckinResponse(resp.StatusCode, checkinBody)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *Service) parseCheckinResponse(statusCode int, body []byte) (*CheckinResult, error) {
	if statusCode != http.StatusOK {
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: fmt.Sprintf("unexpected status code: %d", statusCode),
		}
	}

	var response struct {
		Success  bool   `json:"success"`
		Message  string `json:"message"`
		Data     *struct {
			Points       int `json:"points"`
			PointsGained int `json:"points_gained"`
			StreakDays   int `json:"streak_days"`
		} `json:"data"`
		Code       int    `json:"code"`
		ErrorMessage string `json:"error_message"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		if s.isAlreadyCheckedIn(string(body)) {
			return &CheckinResult{
				Success:   true,
				Message:   "already checked in today",
				Timestamp: time.Now(),
			}, nil
		}
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: "failed to parse checkin response",
			Err:     err,
		}
	}

	if !response.Success {
		msg := response.Message
		if msg == "" {
			msg = response.ErrorMessage
		}
		if msg == "" {
			msg = "checkin failed"
		}

		if s.isAlreadyCheckedIn(string(body)) {
			return &CheckinResult{
				Success:   true,
				Message:   "already checked in today",
				Timestamp: time.Now(),
			}, nil
		}

		return nil, &CheckinError{
			Type:    ErrBusiness,
			Message: msg,
		}
	}

	result := &CheckinResult{
		Success:   true,
		Message:   "checkin successful",
		Timestamp: time.Now(),
	}

	if response.Data != nil {
		result.Points = response.Data.Points
		result.PointsGained = response.Data.PointsGained
		result.StreakDays = response.Data.StreakDays
	}

	return result, nil
}

func (s *Service) isChallengePage(body string) bool {
	return containsAny(body,
		"challenge-platform",
		"checking.*browser",
		"cf-chl-bypass",
		"turnstile",
		"jschl-answer",
		"pass.*challenge",
		"verify.*you.*are.*human",
		"__cf_chl_jschl_tk__",
		"window._cf_chl_opt",
	)
}

func (s *Service) isAlreadyCheckedIn(body string) bool {
	return containsAny(body,
		"already checked in",
		"已签到",
		"签到成功",
		"checkin.*success",
		"today.*checkin",
	)
}

func containsAny(s string, substrings ...string) bool {
	for _, substr := range substrings {
		if len(substr) > 0 && s != "" {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
