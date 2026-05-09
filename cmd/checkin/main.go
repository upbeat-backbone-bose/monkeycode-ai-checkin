package main

import (
	"fmt"
	"log"
	"os"

	"github.com/monkeycode-ai/checkin/internal/captcha"
	"github.com/monkeycode-ai/checkin/internal/checkin"
	"github.com/monkeycode-ai/checkin/internal/httpclient"
)

func main() {
	targetURL := getEnv("MONKEYCODE_URL", "https://monkeycode-ai.com")
	cookie := getEnv("MONKEYCODE_COOKIE", "")

	if cookie == "" {
		log.Fatal("MONKEYCODE_COOKIE environment variable is required")
	}

	// Initialize HTTP Client with Cookie
	client, err := httpclient.NewClient(
		httpclient.WithCookie(cookie, targetURL),
	)
	if err != nil {
		log.Fatalf("Failed to create HTTP client: %v", err)
	}

	// 1. Solve Captcha
	solver := captcha.NewSolver(client, targetURL)
	captchaToken, err := solver.GetToken()
	if err != nil {
		log.Fatalf("Failed to solve captcha: %v", err)
	}

	// 2. Perform Checkin
	checkinSvc := checkin.NewService(client, targetURL)
	result, err := checkinSvc.DoCheckin(captchaToken)
	if err != nil {
		log.Fatalf("Checkin failed: %v", err)
	}

	if result.Success {
		log.Println("✅ Checkin successful!")
		if result.StreakDays > 0 {
			log.Printf("🔥 Streak: %d days", result.StreakDays)
		}
		if result.PointsGained > 0 {
			log.Printf("💰 Points gained: %d", result.PointsGained)
		}
	} else {
		log.Printf("Checkin result: %s", result.Message)
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
