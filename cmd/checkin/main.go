package main

import (
	"fmt"
	"log"
	"os"

	"github.com/monkeycode-ai/checkin/internal/captcha"
	"github.com/monkeycode-ai/checkin/internal/checkin"
	"github.com/monkeycode-ai/checkin/internal/httpclient"
	"github.com/monkeycode-ai/checkin/internal/notify"
)

func main() {
	targetURL := getEnv("MONKEYCODE_URL", "https://monkeycode-ai.com")
	cookie := getEnv("MONKEYCODE_COOKIE", "")
	webhookURL := getEnv("WEBHOOK_URL", "")

	if cookie == "" {
		log.Fatal("MONKEYCODE_COOKIE environment variable is required")
	}

	// Initialize HTTP Client with Cookie
	client, err := httpclient.NewClient(
		httpclient.WithCookie(cookie, targetURL),
	)
	if err != nil {
		sendFailureWebhook(webhookURL, "HTTP Client Error", "Failed to create HTTP client", err.Error(), "Check MONKEYCODE_COOKIE format")
		log.Fatalf("Failed to create HTTP client: %v", err)
	}

	// 1. Solve Captcha
	solver := captcha.NewSolver(client, targetURL)
	captchaToken, err := solver.GetToken()
	if err != nil {
		sendFailureWebhook(webhookURL, "Captcha Error", "Failed to solve captcha", err.Error(), "Check network connectivity or captcha API changes")
		log.Fatalf("Failed to solve captcha: %v", err)
	}

	// 2. Perform Checkin
	checkinSvc := checkin.NewService(client, targetURL)
	result, err := checkinSvc.DoCheckin(captchaToken)
	if err != nil {
		var checkinErr *checkin.CheckinError
		var errorType, suggestion string
		if ok := checkin.AsCheckinError(err, &checkinErr); ok {
			errorType = string(checkinErr.Type)
		} else {
			errorType = "UNKNOWN"
		}
		suggestion = getSuggestion(errorType)
		sendFailureWebhook(webhookURL, "Checkin Error", errorType, err.Error(), suggestion)
		log.Fatalf("Checkin failed: %v", err)
	}

	if result.Success {
		log.Println("Checkin successful!")
		if result.StreakDays > 0 {
			log.Printf("Streak: %d days", result.StreakDays)
		}
		if result.PointsGained > 0 {
			log.Printf("Points gained: %d", result.PointsGained)
		}
	} else {
		log.Printf("Checkin result: %s", result.Message)
	}
}

func sendFailureWebhook(webhookURL, errorType, errorMessage, errorDetail, suggestion string) {
	if webhookURL == "" {
		return
	}

	notifier := notify.NewNotifier(webhookURL, "")
	_ = notifier.Send(notify.Message{
		Title:        "Monkeycode Checkin Failed",
		ErrorType:    errorType,
		ErrorMessage: errorMessage,
		Suggestion:   suggestion,
		Timestamp:    notify.Now(),
	})
}

func getSuggestion(errorType string) string {
	switch errorType {
	case "NETWORK_ERROR":
		return "检查网络连接是否正常"
	case "TLS_FINGERPRINT":
		return "TLS 指纹可能被识别，尝试更新 uTLS 配置"
	case "CHALLENGE_FAILED":
		return "验证码挑战失败，可能需要更新算法"
	case "AUTH_EXPIRED":
		return "Cookie 已过期，请更新 MONKEYCODE_COOKIE"
	case "BUSINESS_ERROR":
		return "业务逻辑错误，检查账号状态"
	case "WAF_BLOCKED":
		return "被 WAF 拦截，尝试更换 IP 或调整请求频率"
	case "API_CHANGED":
		return "API 可能已变更，检查接口是否更新"
	default:
		return "检查日志并排查具体错误原因"
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func init() {
	// Suppress wazero logs if needed, but default is usually fine
	_ = fmt.Sprint
}
