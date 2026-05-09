package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/monkeycode-ai/checkin/internal/checkin"
	"github.com/monkeycode-ai/checkin/internal/challenge"
	"github.com/monkeycode-ai/checkin/internal/httpclient"
	"github.com/monkeycode-ai/checkin/internal/notify"
)

const (
	defaultTargetURL = "https://monkeycode-ai.com"
)

type Config struct {
	Cookie     string
	WebhookURL string
	TargetURL  string
}

func loadConfig() (*Config, error) {
	cookie := os.Getenv("MONKEYCODE_COOKIE")
	if cookie == "" {
		return nil, fmt.Errorf("MONKEYCODE_COOKIE environment variable is required")
	}

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = defaultTargetURL
	}

	return &Config{
		Cookie:     cookie,
		WebhookURL: os.Getenv("WEBHOOK_URL"),
		TargetURL:  targetURL,
	}, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Starting checkin for %s", cfg.TargetURL)

	client, err := httpclient.NewClient(
		httpclient.WithCookie(cfg.Cookie, cfg.TargetURL),
	)
	if err != nil {
		log.Fatalf("Failed to create HTTP client: %v", err)
	}

	challengeHandler := challenge.NewHandler(client, cfg.TargetURL)
	svc := checkin.NewService(client, challengeHandler, cfg.TargetURL)

	result, err := svc.DoCheckin()
	if err != nil {
		log.Printf("Checkin failed: %v", err)

		if cfg.WebhookURL != "" {
			checkinErr, ok := err.(*checkin.CheckinError)
			if !ok {
				checkinErr = &checkin.CheckinError{
					Type:    checkin.ErrNetwork,
					Message: err.Error(),
				}
			}

			notifier := notify.NewNotifier(cfg.WebhookURL, "")
			notifyErr := notifier.Send(notify.Message{
				Title:        "Monkeycode 签到失败",
				ErrorType:    string(checkinErr.Type),
				ErrorMessage: checkinErr.Message,
				Suggestion:   getSuggestion(checkinErr.Type),
				Timestamp:    time.Now(),
			})
			if notifyErr != nil {
				log.Printf("Failed to send webhook notification: %v", notifyErr)
			}
		}

		os.Exit(1)
	}

	log.Printf("Checkin successful: %s", result.Message)
	if result.PointsGained > 0 {
		log.Printf("Points gained: %d, Total points: %d, Streak: %d days",
			result.PointsGained, result.Points, result.StreakDays)
	}
}

func getSuggestion(errType checkin.ErrorType) string {
	switch errType {
	case checkin.ErrAuth:
		return "Cookie 可能已过期，请在浏览器中重新登录并更新 MONKEYCODE_COOKIE Secret"
	case checkin.ErrWAF:
		return "可能被 WAF 封禁，请检查 IP 状态或等待后重试"
	case checkin.ErrChallenge:
		return "Challenge 验证失败，WAF 规则可能已更新，请检查 challenge 处理逻辑"
	case checkin.ErrAPIChange:
		return "API 响应结构可能已变更，请检查 Monkeycode 平台接口是否更新"
	case checkin.ErrNetwork:
		return "网络请求失败，请检查 GitHub Actions 网络连通性"
	case checkin.ErrBusiness:
		return "业务错误，请查看错误详情并手动检查平台状态"
	default:
		return "未知错误，请查看日志排查问题"
	}
}
