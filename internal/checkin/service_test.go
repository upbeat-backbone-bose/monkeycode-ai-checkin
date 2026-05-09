package checkin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockHTTPClient struct {
	getHandler    func(url string) (*http.Response, error)
	postHandler   func(url string, contentType string, body io.Reader) (*http.Response, error)
	doHandler     func(req *http.Request) (*http.Response, error)
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

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.doHandler != nil {
		return m.doHandler(req)
	}
	if m.postHandler != nil {
		return m.postHandler(req.URL.String(), req.Header.Get("Content-Type"), req.Body)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(nil)}, nil
}

func TestCheckinResult_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/wallet/checkin" {
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

	svc := NewService(&http.Client{Transport: serverTransport(server)}, server.URL)

	result, err := svc.DoCheckin("test_token:123456")
	if err != nil {
		t.Fatalf("DoCheckin() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure")
	}
	if result.Points != 1500 {
		t.Errorf("Points: got %d, want 1500", result.Points)
	}
}

func TestCheckinResult_BusinessError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/wallet/checkin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       false,
				"error_message": "Checkin failed",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	svc := NewService(&http.Client{Transport: serverTransport(server)}, server.URL)

	_, err := svc.DoCheckin("test_token:123")
	if err == nil {
		t.Fatal("Expected error for business failure")
	}

	checkinErr, ok := err.(*CheckinError)
	if !ok {
		t.Fatalf("Expected CheckinError, got %T", err)
	}

	if checkinErr.Type != ErrBusiness {
		t.Errorf("Error type: got %v, want %v", checkinErr.Type, ErrBusiness)
	}
}

func TestCheckinResult_AuthExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	svc := NewService(&http.Client{Transport: serverTransport(server)}, server.URL)

	_, err := svc.DoCheckin("test_token:123")
	if err == nil {
		t.Fatal("Expected error for expired auth")
	}

	checkinErr, ok := err.(*CheckinError)
	if !ok {
		t.Fatalf("Expected CheckinError, got %T", err)
	}

	if checkinErr.Type != ErrAPIChange {
		t.Errorf("Error type: got %v, want %v", checkinErr.Type, ErrAPIChange)
	}
}

func serverTransport(s *httptest.Server) http.RoundTripper {
	return http.DefaultTransport
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

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestDoCheckin_SendsCorrectToken(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users/wallet/checkin" {
			buf := new(strings.Builder)
			io.Copy(buf, r.Body)
			receivedBody = buf.String()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true}`))
			return
		}
	}))
	defer server.Close()

	svc := NewService(&http.Client{Transport: serverTransport(server)}, server.URL)
	svc.DoCheckin("my_captcha_token:123456")

	expected := `{"captcha_token":"my_captcha_token:123456"}`
	if receivedBody != expected {
		t.Errorf("Request body = %v, want %v", receivedBody, expected)
	}
}
