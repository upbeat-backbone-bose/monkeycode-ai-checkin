package checkin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/monkeycode-ai/checkin/internal/challenge"
)

type mockHTTPClient struct {
	getHandler    func(url string) (*http.Response, error)
	postHandler   func(url string, contentType string, body io.Reader) (*http.Response, error)
	postFormHandler func(url string, data map[string][]string) (*http.Response, error)
}

func (m *mockHTTPClient) Get(url string) (*http.Response, error) {
	if m.getHandler != nil {
		return m.getHandler(url)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(nil)}, nil
}

func (m *mockHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	if m.postHandler != nil {
		return m.postHandler(url, contentType, body)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(nil)}, nil
}

func (m *mockHTTPClient) PostForm(url string, data url.Values) (*http.Response, error) {
	if m.postFormHandler != nil {
		return m.postFormHandler(url, data)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(nil)}, nil
}

type mockChallengeHandler struct {
	result *challenge.HandleChallengeResult
	err    error
}

func (m *mockChallengeHandler) HandleChallenge(responseBody string) (*challenge.HandleChallengeResult, error) {
	return m.result, m.err
}

func TestCheckinResult_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Welcome</body></html>`))
			return
		}
		if r.URL.Path == "/api/checkin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "签到成功",
				"data": map[string]interface{}{
					"points":        1500,
					"points_gained": 100,
					"streak_days":   7,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &mockHTTPClient{
		getHandler: func(url string) (*http.Response, error) {
			return http.Get(url)
		},
		postHandler: func(url string, contentType string, body io.Reader) (*http.Response, error) {
			return http.Post(url, contentType, body)
		},
	}

	svc := NewService(client, &mockChallengeHandler{result: &challenge.HandleChallengeResult{Passed: true}}, server.URL)

	result, err := svc.DoCheckin()
	if err != nil {
		t.Fatalf("DoCheckin() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure")
	}
	if result.Points != 1500 {
		t.Errorf("Points: got %d, want 1500", result.Points)
	}
	if result.PointsGained != 100 {
		t.Errorf("PointsGained: got %d, want 100", result.PointsGained)
	}
	if result.StreakDays != 7 {
		t.Errorf("StreakDays: got %d, want 7", result.StreakDays)
	}
}

func TestCheckinResult_AlreadyCheckedIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>Welcome</body></html>`))
			return
		}
		if r.URL.Path == "/api/checkin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "already checked in",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &mockHTTPClient{
		getHandler: func(url string) (*http.Response, error) {
			return http.Get(url)
		},
		postHandler: func(url string, contentType string, body io.Reader) (*http.Response, error) {
			return http.Post(url, contentType, body)
		},
	}

	svc := NewService(client, &mockChallengeHandler{result: &challenge.HandleChallengeResult{Passed: true}}, server.URL)

	result, err := svc.DoCheckin()
	if err != nil {
		t.Fatalf("DoCheckin() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure")
	}
}

func TestCheckinResult_AuthExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &mockHTTPClient{
		getHandler: func(url string) (*http.Response, error) {
			return http.Get(url)
		},
	}

	svc := NewService(client, &mockChallengeHandler{result: &challenge.HandleChallengeResult{Passed: true}}, server.URL)

	_, err := svc.DoCheckin()
	if err == nil {
		t.Fatal("Expected error for expired auth")
	}

	checkinErr, ok := err.(*CheckinError)
	if !ok {
		t.Fatalf("Expected CheckinError, got %T", err)
	}

	if checkinErr.Type != ErrAuth {
		t.Errorf("Error type: got %v, want %v", checkinErr.Type, ErrAuth)
	}
}

func TestCheckinResult_WAFBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`Access Denied`))
	}))
	defer server.Close()

	client := &mockHTTPClient{
		getHandler: func(url string) (*http.Response, error) {
			return http.Get(url)
		},
	}

	svc := NewService(client, &mockChallengeHandler{result: &challenge.HandleChallengeResult{Passed: true}}, server.URL)

	_, err := svc.DoCheckin()
	if err == nil {
		t.Fatal("Expected error for WAF blocked")
	}

	checkinErr, ok := err.(*CheckinError)
	if !ok {
		t.Fatalf("Expected CheckinError, got %T", err)
	}

	if checkinErr.Type != ErrWAF {
		t.Errorf("Error type: got %v, want %v", checkinErr.Type, ErrWAF)
	}
}

func TestCheckinError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *CheckinError
		want string
	}{
		{
			name: "with underlying error",
			err: &CheckinError{
				Type:    ErrNetwork,
				Message: "connection failed",
				Err:     &testError{"timeout"},
			},
			want: "[NETWORK_ERROR] connection failed: timeout",
		},
		{
			name: "without underlying error",
			err: &CheckinError{
				Type:    ErrAuth,
				Message: "cookie expired",
			},
			want: "[AUTH_EXPIRED] cookie expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckinError_Unwrap(t *testing.T) {
	underlying := &testError{"test error"}
	err := &CheckinError{
		Type:    ErrNetwork,
		Message: "test",
		Err:     underlying,
	}

	if err.Unwrap() != underlying {
		t.Errorf("Unwrap() did not return underlying error")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
