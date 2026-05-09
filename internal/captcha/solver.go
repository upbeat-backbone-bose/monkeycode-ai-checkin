package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// FNV-1a hash followed by xorshift PRNG to generate hex strings
// Matches the JS function: function i(u, l) { ... }
func generateHexSeed(input string, length int) string {
	// FNV-1a hash
	var c uint32 = 2166136261
	for i := 0; i < len(input); i++ {
		c ^= uint32(input[i])
		c += (c << 1) + (c << 4) + (c << 7) + (c << 8) + (c << 24)
	}

	var result strings.Builder
	for result.Len() < length {
		// xorshift32
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
	Count int `json:"c"`
	SaltLen int `json:"s"`
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
	targetURL    string
	wasmURL      string
	challengeURL string
	redeemURL    string
	tempDir      string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

func NewSolver(client HTTPClient, targetURL string) *Solver {
	return &Solver{
		client:       client,
		targetURL:    strings.TrimRight(targetURL, "/"),
		wasmURL:      targetURL + "/captcha/cap_wasm_bg.wasm",
		challengeURL: targetURL + "/api/v1/public/captcha/challenge",
		redeemURL:    targetURL + "/api/v1/public/captcha/redeem",
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
		// Maybe it's already an array
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

	// 4. Solve all challenges in parallel using workers
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

func (s *Solver) solveAll(pairs []challengePair) ([]uint64, error) {
	// Prepare temp directory
	if s.tempDir == "" {
		dir, err := os.MkdirTemp("", "monkeycode-captcha")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		s.tempDir = dir
	}

	// Fetch Wasm once
	wasmPath := filepath.Join(s.tempDir, "cap_wasm_bg.wasm")
	if _, err := os.Stat(wasmPath); os.IsNotExist(err) {
		wasmBytes, err := s.fetchWasm()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
			return nil, err
		}
	}

	// Fetch JS glue code once
	jsGluePath := filepath.Join(s.tempDir, "cap_wasm.mjs")
	if _, err := os.Stat(jsGluePath); os.IsNotExist(err) {
		jsGlueBytes, err := s.fetchWasmJS()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(jsGluePath, jsGlueBytes, 0644); err != nil {
			return nil, err
		}
	}

	// Write runner script (solves one pair)
	runnerJS := `
import { initSync, solve_pow } from './cap_wasm.mjs';
import { readFileSync } from 'fs';

const salt = process.argv[2];
const target = process.argv[3];
const wasmPath = process.argv[4];

const wasmBytes = readFileSync(wasmPath);
initSync({ module: wasmBytes });

const result = solve_pow(salt, target);
console.log(result.toString(16));
`

	runnerPath := filepath.Join(s.tempDir, "runner.mjs")
	if err := os.WriteFile(runnerPath, []byte(runnerJS), 0644); err != nil {
		return nil, err
	}

	// Solve all challenges with bounded concurrency (use number of workers like the browser)
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
		sem <- struct{}{} // acquire semaphore
		go func(idx int, p challengePair) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore

			nonce, err := s.solveOne(runnerPath, p.Salt, p.Target, wasmPath)
			solMu.Lock()
			defer solMu.Unlock()
			if err != nil {
				solErr = fmt.Errorf("challenge %d failed: %w", idx+1, err)
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

func (s *Solver) solveOne(runnerPath, salt, target, wasmPath string) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", runnerPath, salt, target, wasmPath)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("node failed: %w", err)
	}

	result := strings.TrimSpace(string(out))
	if result == "" {
		return 0, fmt.Errorf("empty result")
	}

	var nonce uint64
	if _, err := fmt.Sscanf(result, "%x", &nonce); err != nil {
		return 0, fmt.Errorf("parse nonce %q: %w", result, err)
	}

	return nonce, nil
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

func (s *Solver) fetchWasm() ([]byte, error) {
	req, err := http.NewRequest("GET", s.wasmURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/wasm")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasm fetch failed with status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 || data[0] != 0x00 || data[1] != 0x61 || data[2] != 0x73 || data[3] != 0x6D {
		return nil, fmt.Errorf("invalid wasm file: magic number mismatch")
	}

	return data, nil
}

func (s *Solver) fetchWasmJS() ([]byte, error) {
	jsURL := s.targetURL + "/captcha/cap_wasm.js"
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/javascript")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasm JS fetch failed with status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Printf("Downloaded JS glue code, size: %d", len(data))
	return data, nil
}
