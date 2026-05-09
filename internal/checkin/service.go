package checkin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	targetURL   string
	checkinPath string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

func NewService(httpClient HTTPClient, targetURL string) *Service {
	return &Service{
		httpClient:  httpClient,
		targetURL:   strings.TrimRight(targetURL, "/"),
		checkinPath: "/api/v1/users/wallet/checkin",
	}
}

func (s *Service) DoCheckin(captchaToken string) (*CheckinResult, error) {
	checkinURL := s.targetURL + s.checkinPath
	reqBody := fmt.Sprintf(`{"captcha_token":"%s"}`, captchaToken)
	
	req, err := http.NewRequest("POST", checkinURL, strings.NewReader(reqBody))
	if err != nil {
		return nil, &CheckinError{Type: ErrNetwork, Message: "failed to create request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, &CheckinError{Type: ErrNetwork, Message: "failed to call checkin API", Err: err}
	}
	defer resp.Body.Close()

	checkinBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &CheckinError{Type: ErrAPIChange, Message: "failed to read checkin response", Err: err}
	}

	return s.parseCheckinResponse(resp.StatusCode, checkinBody)
}

func (s *Service) parseCheckinResponse(statusCode int, body []byte) (*CheckinResult, error) {
	if statusCode != http.StatusOK {
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: fmt.Sprintf("unexpected status code: %d, body: %s", statusCode, string(body)),
		}
	}

	var response struct {
		Success      bool   `json:"success"`
		Message      string `json:"message"`
		Data         *struct {
			Points       int `json:"points"`
			PointsGained int `json:"points_gained"`
			StreakDays   int `json:"streak_days"`
		} `json:"data"`
		Code         int    `json:"code"`
		ErrorMessage string `json:"error_message"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, &CheckinError{
			Type:    ErrAPIChange,
			Message: fmt.Sprintf("failed to parse checkin response: %s", string(body)),
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
		return nil, &CheckinError{
			Type:    ErrBusiness,
			Message: fmt.Sprintf("%s (response: %s)", msg, string(body)),
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
