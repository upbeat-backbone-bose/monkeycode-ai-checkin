package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookType string

const (
	WebhookDingTalk  WebhookType = "dingtalk"
	WebhookWeCom     WebhookType = "wecom"
	WebhookFeishu    WebhookType = "feishu"
	WebhookGeneric   WebhookType = "generic"
)

const defaultTimeout = 10 * time.Second

func Now() time.Time {
	return time.Now()
}

type Message struct {
	Title       string
	ErrorType   string
	ErrorMessage string
	Suggestion  string
	Timestamp   time.Time
}

type Notifier struct {
	webhookURL string
	webhookType WebhookType
	httpClient *http.Client
}

func NewNotifier(webhookURL string, webhookType WebhookType) *Notifier {
	if webhookType == "" {
		webhookType = detectWebhookType(webhookURL)
	}

	return &Notifier{
		webhookURL: webhookURL,
		webhookType: webhookType,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

func (n *Notifier) Send(msg Message) error {
	if n.webhookURL == "" {
		return nil
	}

	payload, err := n.buildPayload(msg)
	if err != nil {
		return fmt.Errorf("failed to build webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", n.webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

func (n *Notifier) buildPayload(msg Message) ([]byte, error) {
	switch n.webhookType {
	case WebhookDingTalk:
		return buildDingTalkPayload(msg)
	case WebhookWeCom:
		return buildWeComPayload(msg)
	case WebhookFeishu:
		return buildFeishuPayload(msg)
	default:
		return buildGenericPayload(msg)
	}
}

func buildDingTalkPayload(msg Message) ([]byte, error) {
	content := fmt.Sprintf("## Monkeycode 签到失败通知\n\n"+
		"**时间**: %s\n\n"+
		"**错误类型**: %s\n\n"+
		"**错误详情**: %s\n\n"+
		"**建议操作**: %s",
		msg.Timestamp.Format("2006-01-02 15:04:05"),
		msg.ErrorType,
		msg.ErrorMessage,
		msg.Suggestion,
	)

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title":   msg.Title,
			"content": content,
		},
	}

	return json.Marshal(payload)
}

func buildWeComPayload(msg Message) ([]byte, error) {
	content := fmt.Sprintf("## Monkeycode 签到失败通知\n"+
		"> 时间：%s\n"+
		"> 错误类型：%s\n"+
		"> 错误详情：%s\n"+
		"> 建议操作：%s",
		msg.Timestamp.Format("2006-01-02 15:04:05"),
		msg.ErrorType,
		msg.ErrorMessage,
		msg.Suggestion,
	)

	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content,
		},
	}

	return json.Marshal(payload)
}

func buildFeishuPayload(msg Message) ([]byte, error) {
	content := fmt.Sprintf("## Monkeycode 签到失败通知\n\n"+
		"**时间**: %s\n\n"+
		"**错误类型**: %s\n\n"+
		"**错误详情**: %s\n\n"+
		"**建议操作**: %s",
		msg.Timestamp.Format("2006-01-02 15:04:05"),
		msg.ErrorType,
		msg.ErrorMessage,
		msg.Suggestion,
	)

	payload := map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"header": map[string]interface{}{
				"title": map[string]interface{}{
					"tag":     "plain_text",
					"content": msg.Title,
				},
			},
			"elements": []map[string]interface{}{
				{
					"tag": "markdown",
					"content": content,
				},
			},
		},
	}

	return json.Marshal(payload)
}

func buildGenericPayload(msg Message) ([]byte, error) {
	payload := map[string]interface{}{
		"title":        msg.Title,
		"error_type":   msg.ErrorType,
		"error_message": msg.ErrorMessage,
		"suggestion":   msg.Suggestion,
		"timestamp":    msg.Timestamp.Format(time.RFC3339),
	}

	return json.Marshal(payload)
}

func detectWebhookType(url string) WebhookType {
	if url == "" {
		return WebhookGeneric
	}

	if containsStr(url, "oapi.dingtalk.com") || containsStr(url, "dingtalk") {
		return WebhookDingTalk
	}
	if containsStr(url, "qyapi.weixin.qq.com") || containsStr(url, "wecom") || containsStr(url, "wechat") {
		return WebhookWeCom
	}
	if containsStr(url, "open.feishu.cn") || containsStr(url, "feishu") || containsStr(url, "larksuite") {
		return WebhookFeishu
	}

	return WebhookGeneric
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
