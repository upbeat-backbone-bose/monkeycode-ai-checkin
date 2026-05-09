package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDetectWebhookType(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want WebhookType
	}{
		{"dingtalk", "https://oapi.dingtalk.com/robot/send?access_token=xxx", WebhookDingTalk},
		{"wecom", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx", WebhookWeCom},
		{"feishu", "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", WebhookFeishu},
		{"generic", "https://example.com/webhook", WebhookGeneric},
		{"empty", "", WebhookGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectWebhookType(tt.url)
			if got != tt.want {
				t.Errorf("detectWebhookType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildDingTalkPayload(t *testing.T) {
	msg := Message{
		Title:        "Test Title",
		ErrorType:    "AUTH_EXPIRED",
		ErrorMessage: "Cookie expired",
		Suggestion:   "Update cookie",
		Timestamp:    time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC),
	}

	payload, err := buildDingTalkPayload(msg)
	if err != nil {
		t.Fatalf("buildDingTalkPayload() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if result["msgtype"] != "markdown" {
		t.Errorf("msgtype: got %v, want markdown", result["msgtype"])
	}

	markdown, ok := result["markdown"].(map[string]interface{})
	if !ok {
		t.Fatal("markdown field is not a map")
	}

	if markdown["title"] != "Test Title" {
		t.Errorf("title: got %v, want Test Title", markdown["title"])
	}

	content, ok := markdown["content"].(string)
	if !ok {
		t.Fatal("content field is not a string")
	}

	if !containsStr(content, "AUTH_EXPIRED") {
		t.Error("content should contain error type")
	}
	if !containsStr(content, "Cookie expired") {
		t.Error("content should contain error message")
	}
	if !containsStr(content, "Update cookie") {
		t.Error("content should contain suggestion")
	}
}

func TestBuildWeComPayload(t *testing.T) {
	msg := Message{
		Title:        "Test Title",
		ErrorType:    "WAF_BLOCKED",
		ErrorMessage: "Access denied",
		Suggestion:   "Check IP",
		Timestamp:    time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC),
	}

	payload, err := buildWeComPayload(msg)
	if err != nil {
		t.Fatalf("buildWeComPayload() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if result["msgtype"] != "markdown" {
		t.Errorf("msgtype: got %v, want markdown", result["msgtype"])
	}

	markdown, ok := result["markdown"].(map[string]interface{})
	if !ok {
		t.Fatal("markdown field is not a map")
	}

	content, ok := markdown["content"].(string)
	if !ok {
		t.Fatal("content field is not a string")
	}

	if !containsStr(content, "WAF_BLOCKED") {
		t.Error("content should contain error type")
	}
}

func TestBuildFeishuPayload(t *testing.T) {
	msg := Message{
		Title:        "Test Title",
		ErrorType:    "NETWORK_ERROR",
		ErrorMessage: "Connection timeout",
		Suggestion:   "Check network",
		Timestamp:    time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC),
	}

	payload, err := buildFeishuPayload(msg)
	if err != nil {
		t.Fatalf("buildFeishuPayload() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if result["msg_type"] != "interactive" {
		t.Errorf("msg_type: got %v, want interactive", result["msg_type"])
	}

	card, ok := result["card"].(map[string]interface{})
	if !ok {
		t.Fatal("card field is not a map")
	}

	header, ok := card["header"].(map[string]interface{})
	if !ok {
		t.Fatal("header field is not a map")
	}

	titleMap, ok := header["title"].(map[string]interface{})
	if !ok {
		t.Fatal("title field is not a map")
	}

	if titleMap["content"] != "Test Title" {
		t.Errorf("title content: got %v, want Test Title", titleMap["content"])
	}
}

func TestBuildGenericPayload(t *testing.T) {
	msg := Message{
		Title:        "Test Title",
		ErrorType:    "API_CHANGED",
		ErrorMessage: "API structure changed",
		Suggestion:   "Check API docs",
		Timestamp:    time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC),
	}

	payload, err := buildGenericPayload(msg)
	if err != nil {
		t.Fatalf("buildGenericPayload() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if result["title"] != "Test Title" {
		t.Errorf("title: got %v, want Test Title", result["title"])
	}
	if result["error_type"] != "API_CHANGED" {
		t.Errorf("error_type: got %v, want API_CHANGED", result["error_type"])
	}
	if result["error_message"] != "API structure changed" {
		t.Errorf("error_message: got %v, want API structure changed", result["error_message"])
	}
	if result["suggestion"] != "Check API docs" {
		t.Errorf("suggestion: got %v, want Check API docs", result["suggestion"])
	}
}

func TestNotifier_Send_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	notifier := NewNotifier(server.URL, WebhookGeneric)

	msg := Message{
		Title:        "Test",
		ErrorType:    "TEST",
		ErrorMessage: "Test error",
		Suggestion:   "Test suggestion",
		Timestamp:    time.Now(),
	}

	err := notifier.Send(msg)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestNotifier_Send_EmptyURL(t *testing.T) {
	notifier := NewNotifier("", WebhookGeneric)

	msg := Message{
		Title:        "Test",
		ErrorType:    "TEST",
		ErrorMessage: "Test error",
		Suggestion:   "Test suggestion",
		Timestamp:    time.Now(),
	}

	err := notifier.Send(msg)
	if err != nil {
		t.Fatalf("Send() with empty URL should not error, got = %v", err)
	}
}

func TestNotifier_Send_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewNotifier(server.URL, WebhookGeneric)

	msg := Message{
		Title:        "Test",
		ErrorType:    "TEST",
		ErrorMessage: "Test error",
		Suggestion:   "Test suggestion",
		Timestamp:    time.Now(),
	}

	err := notifier.Send(msg)
	if err == nil {
		t.Fatal("Expected error for server failure")
	}

	if !containsStr(err.Error(), "non-200 status") {
		t.Errorf("Error message should mention non-200 status, got: %v", err)
	}
}

func TestNotifier_AutoDetectType(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		expectedType WebhookType
	}{
		{"dingtalk auto", "https://oapi.dingtalk.com/robot/send?access_token=xxx", WebhookDingTalk},
		{"wecom auto", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx", WebhookWeCom},
		{"feishu auto", "https://open.feishu.cn/open-apis/bot/v2/hook/xxx", WebhookFeishu},
		{"generic auto", "https://example.com/hook", WebhookGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewNotifier(tt.url, "")
			if notifier.webhookType != tt.expectedType {
				t.Errorf("webhookType: got %v, want %v", notifier.webhookType, tt.expectedType)
			}
		})
	}
}
