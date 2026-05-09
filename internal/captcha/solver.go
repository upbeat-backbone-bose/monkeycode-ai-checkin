package captcha

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// generateHexSeed implements the JS function i(u, l):
// FNV-1a hash -> xorshift32 PRNG -> hex string of length l
func generateHexSeed(input string, length int) string {
	var c uint32 = 2166136261 // FNV-1a offset basis
	for i := 0; i < len(input); i++ {
		c ^= uint32(input[i])
		c += (c << 1) + (c << 4) + (c << 7) + (c << 8) + (c << 24)
	}

	var result strings.Builder
	for result.Len() < length {
		c ^= c << 13
		c ^= c >> 17
		c ^= c << 5
		result.WriteString(fmt.Sprintf("%08x", c))
	}

	s := result.String()
	if len(s) > length {
		s = s[:length]
	}
	return s
}

type ChallengeResponse struct {
	Challenge json.RawMessage `json:"challenge"`
	Expires   int64           `json:"expires"`
	Token     string          `json:"token"`
}

type ChallengeParams struct {
	Count     int `json:"c"`
	SaltLen   int `json:"s"`
	TargetLen int `json:"d"`
}

type RedeemRequest struct {
	Token     string   `json:"token"`
	Solutions []string `json:"solutions"`
}

type RedeemResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
}

type challengePair struct {
	Salt   string
	Target string
}

type Solver struct {
	client       HTTPClient
	challengeURL string
	redeemURL    string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

func NewSolver(client HTTPClient, targetURL string) *Solver {
	baseURL := strings.TrimRight(targetURL, "/")
	return &Solver{
		client:       client,
		challengeURL: baseURL + "/api/v1/public/captcha/challenge",
		redeemURL:    baseURL + "/api/v1/public/captcha/redeem",
	}
}

func (s *Solver) GetToken() (string, error) {
	// 1. Fetch Challenge
	challenge, err := s.fetchChallenge()
	if err != nil {
		return "", fmt.Errorf("failed to fetch challenge: %w", err)
	}

	// 2. Parse challenge params
	var params ChallengeParams
	if err := json.Unmarshal(challenge.Challenge, &params); err != nil {
		return "", fmt.Errorf("failed to parse challenge params: %w", err)
	}

	log.Printf("Challenge: count=%d, saltLen=%d, targetLen=%d", params.Count, params.SaltLen, params.TargetLen)

	// 3. Generate all (salt, target) pairs
	pairs := make([]challengePair, params.Count)
	for idx := 0; idx < params.Count; idx++ {
		counter := idx + 1
		pairs[idx] = challengePair{
			Salt:   generateHexSeed(challenge.Token+fmt.Sprintf("%d", counter), params.SaltLen),
			Target: generateHexSeed(challenge.Token+fmt.Sprintf("%d", counter)+"d", params.TargetLen),
		}
	}

	// 4. Solve all challenges in parallel
	solutions, err := s.solveAll(pairs)
	if err != nil {
		return "", fmt.Errorf("failed to solve challenges: %w", err)
	}

	// 5. Redeem solutions for final token
	finalToken, err := s.redeem(challenge.Token, solutions)
	if err != nil {
		return "", fmt.Errorf("failed to redeem: %w", err)
	}

	return finalToken, nil
}

func (s *Solver) fetchChallenge() (*ChallengeResponse, error) {
	req, err := http.NewRequest("POST", s.challengeURL, strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("challenge request failed with status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge body: %w", err)
	}

	var result ChallengeResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse challenge: %s: %w", string(bodyBytes), err)
	}

	return &result, nil
}

// solvePow finds a nonce such that:
// SHA-256(salt + nonce_as_decimal_string)[0:n] == targetBytes[0:n]
// where n = floor(len(target_hex) / 2)
//
// This matches the JS fallback solver in the captcha worker.
func solvePow(salt, target string) (uint64, error) {
	// JS uses: const n = Math.floor(target.length / 2)
	// "ec0" (3 chars) => n = 1 byte; "abcd" (4 chars) => n = 2 bytes
	n := len(target) / 2
	if n == 0 {
		n = 1
	}

	// Decode target - take first 2*n chars (even length)
	targetHex := target
	if len(targetHex)%2 != 0 {
		targetHex = targetHex[:len(targetHex)-1]
	}
	targetBytes, err := hex.DecodeString(targetHex)
	if err != nil {
		return 0, fmt.Errorf("decode target %q: %w", target, err)
	}

	saltBytes := []byte(salt)
	hasher := sha256.New()

	// Brute-force: try nonce = 0, 1, 2, ...
	var nonce uint64
	for nonce = 0; nonce < 10_000_000; nonce++ {
		nonceStr := fmt.Sprintf("%d", nonce)
		combined := append(saltBytes, []byte(nonceStr)...)

		hasher.Reset()
		hasher.Write(combined)
		digest := hasher.Sum(nil)

		if bytes.Equal(digest[:n], targetBytes[:n]) {
			return nonce, nil
		}
	}

	return 0, fmt.Errorf("no solution found after 10M attempts")
}

func (s *Solver) solveAll(pairs []challengePair) ([]string, error) {
	workerCount := 8
	if len(pairs) < workerCount {
		workerCount = len(pairs)
	}

	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	solutions := make([]string, len(pairs))
	var solErr error
	var solMu sync.Mutex

	for i, pair := range pairs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p challengePair) {
			defer wg.Done()
			defer func() { <-sem }()

			nonce, err := solvePow(p.Salt, p.Target)
			solMu.Lock()
			defer solMu.Unlock()
			if err != nil {
				solErr = fmt.Errorf("challenge %d (salt=%s, target=%s) failed: %w", idx+1, p.Salt, p.Target, err)
				return
			}
			solutions[idx] = fmt.Sprintf("%x", nonce)
			log.Printf("Challenge %d/%d solved: nonce=%s", idx+1, len(pairs), solutions[idx])
		}(i, pair)
	}

	wg.Wait()
	if solErr != nil {
		return nil, solErr
	}

	return solutions, nil
}

func (s *Solver) redeem(token string, solutions []string) (string, error) {
	reqBody := RedeemRequest{
		Token:     token,
		Solutions: solutions,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	log.Printf("Redeem request body: %s", string(bodyBytes))

	req, err := http.NewRequest("POST", s.redeemURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read redeem response: %w", err)
	}

	log.Printf("Redeem response: status=%d, body=%s", resp.StatusCode, string(respBody))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("redeem failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var redeemResp RedeemResponse
	if err := json.Unmarshal(respBody, &redeemResp); err != nil {
		return "", fmt.Errorf("failed to parse redeem response: %w", err)
	}

	if !redeemResp.Success {
		return "", fmt.Errorf("redeem unsuccessful: %s", string(respBody))
	}

	log.Printf("Redeem successful, final token: %s", redeemResp.Token)
	return redeemResp.Token, nil
}
