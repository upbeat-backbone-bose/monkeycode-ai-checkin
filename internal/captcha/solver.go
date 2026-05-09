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
	Solutions []uint64 `json:"solutions"`
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
// SHA-256(salt + nonce_decimal_string) matches target at bit level
func solvePow(salt, target string) (uint64, error) {
	targetBytes := parseHexTarget(target)
	targetBits := len(target) * 4

	saltBytes := []byte(salt)
	hasher := sha256.New()
	nonceBuf := make([]byte, 20) // u64::MAX has at most 20 digits

	var nonce uint64
	for nonce = 0; nonce < 10_000_000; nonce++ {
		nonceLen := writeU64ToBuffer(nonce, nonceBuf)
		nonceBytes := nonceBuf[:nonceLen]

		combined := append(saltBytes, nonceBytes...)

		hasher.Reset()
		hasher.Write(combined)
		digest := hasher.Sum(nil)

		if hashMatchesTarget(digest[:], targetBytes, targetBits) {
			return nonce, nil
		}
	}

	return 0, fmt.Errorf("no solution found after 10M attempts")
}

// parseHexTarget decodes hex string, padding with '0' at end if odd length
// Matches Rust: if padded_target.len() % 2 != 0 { padded_target.push('0'); }
func parseHexTarget(target string) []byte {
	padded := target
	if len(padded)%2 != 0 {
		padded += "0"
	}
	result := make([]byte, len(padded)/2)
	for i := 0; i < len(padded); i += 2 {
		b, _ := hex.DecodeString(padded[i : i+2])
		result[i/2] = b[0]
	}
	return result
}

// writeU64ToBuffer converts u64 to decimal ASCII string
// Matches Rust: buffer[i] = (value % 10) as u8 + b'0'
func writeU64ToBuffer(value uint64, buffer []byte) int {
	if value == 0 {
		buffer[0] = '0'
		return 1
	}

	len := 0
	temp := value
	for temp > 0 {
		len++
		temp /= 10
	}

	for i := len - 1; i >= 0; i-- {
		buffer[i] = byte(value%10) + '0'
		value /= 10
	}

	return len
}

// hashMatchesTarget compares hash against target at bit level
// Matches Rust: full_bytes = target_bits / 8, remaining_bits = target_bits % 8
func hashMatchesTarget(hash, targetBytes []byte, targetBits int) bool {
	fullBytes := targetBits / 8
	remainingBits := targetBits % 8

	if !bytes.Equal(hash[:fullBytes], targetBytes[:fullBytes]) {
		return false
	}

	if remainingBits > 0 && fullBytes < len(targetBytes) {
		mask := byte(0xFF << (8 - remainingBits))
		if (hash[fullBytes] & mask) != (targetBytes[fullBytes] & mask) {
			return false
		}
	}

	return true
}

func (s *Solver) solveAll(pairs []challengePair) ([]uint64, error) {
	workerCount := 8
	if len(pairs) < workerCount {
		workerCount = len(pairs)
	}

	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	solutions := make([]uint64, len(pairs))
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
			solutions[idx] = nonce
			log.Printf("Challenge %d/%d solved: nonce=%d", idx+1, len(pairs), nonce)
		}(i, pair)
	}

	wg.Wait()
	if solErr != nil {
		return nil, solErr
	}

	return solutions, nil
}

func (s *Solver) redeem(token string, solutions []uint64) (string, error) {
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
