package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type Solver struct {
	client      HTTPClient
	targetURL   string
	wasmURL     string
	challengeURL string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

type ChallengeResponse struct {
	Challenge json.RawMessage `json:"challenge"`
	Expires   int64           `json:"expires"`
	Token     string          `json:"token"`
}

func NewSolver(client HTTPClient, targetURL string) *Solver {
	return &Solver{
		client:      client,
		targetURL:   targetURL,
		wasmURL:     targetURL + "/captcha/cap_wasm_bg.wasm",
		challengeURL: targetURL + "/api/v1/public/captcha/challenge",
	}
}

func (s *Solver) GetToken() (string, error) {
	// 1. Fetch Challenge
	challenge, err := s.fetchChallenge()
	if err != nil {
		return "", fmt.Errorf("failed to fetch challenge: %w", err)
	}

	// 2. Solve PoW using Wasm
	proof, err := s.solvePoW(challenge.Token, string(challenge.Challenge))
	if err != nil {
		return "", fmt.Errorf("failed to solve PoW: %w", err)
	}

	// 3. Format token: salt:hex_proof
	return fmt.Sprintf("%s:%x", challenge.Token, proof), nil
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("challenge request failed with status: %d", resp.StatusCode)
	}

	var result ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *Solver) solvePoW(salt, target string) (uint64, error) {
	// 1. Fetch Wasm
	wasmBytes, err := s.fetchWasm()
	if err != nil {
		return 0, err
	}

	// 2. Setup Runtime
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	// 3. Instantiate Module
	mod, err := r.Instantiate(ctx, wasmBytes)
	if err != nil {
		return 0, fmt.Errorf("wasm instantiate failed: %w", err)
	}

	// Initialize wbindgen if present
	if start := mod.ExportedFunction("__wbindgen_start"); start != nil {
		if _, err := start.Call(ctx); err != nil {
			return 0, fmt.Errorf("wasm __wbindgen_start failed: %w", err)
		}
	}

	// 4. Find solve_pow function
	solvePow := mod.ExportedFunction("solve_pow")
	if solvePow == nil {
		return 0, fmt.Errorf("function solve_pow not found in wasm module")
	}

	// 5. Prepare arguments
	// solve_pow takes two string pointers (offset, length) pairs?
	// Actually, looking at the JS:
	// const n=passStringToWasm0(e, ...) -> returns offset
	// const i=WASM_VECTOR_LEN -> length
	// So it expects 4 arguments: offset1, len1, offset2, len2
	
	ptr1, len1, err := s.writeStringToMemory(mod, salt)
	if err != nil {
		return 0, err
	}
	
	ptr2, len2, err := s.writeStringToMemory(mod, target)
	if err != nil {
		return 0, err
	}

	// 6. Call function
	results, err := solvePow.Call(ctx, ptr1, len1, ptr2, len2)
	if err != nil {
		return 0, err
	}

	if len(results) == 0 {
		return 0, fmt.Errorf("solve_pow returned no results")
	}

	// The JS wrapper does: return BigInt.asUintN(64, a)
	// And wasm returns a single u64 (or two u32s). 
	// Usually returns [low, high] for i64 in wazero if not treated as u64 directly, 
	// but wazero usually handles u64 as a single uint64 value.
	return uint64(results[0]), nil
}

func (s *Solver) fetchWasm() ([]byte, error) {
	resp, err := s.client.Get(s.wasmURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasm fetch failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// writeStringToMemory allocates memory in Wasm and writes the string, returning (offset, length).
// This mimics the passStringToWasm0 logic roughly, but simplified since wazero handles memory allocation.
func (s *Solver) writeStringToMemory(mod api.Module, str string) (uint64, uint64, error) {
	// We need to call __wbindgen_malloc
	malloc := mod.ExportedFunction("__wbindgen_malloc")
	if malloc == nil {
		// Fallback: some wasm modules expose memory directly, but cap_wasm uses malloc
		// If malloc is missing, we might need to inspect exports more closely.
		// However, based on the JS, it uses wasm.__wbindgen_malloc
		return 0, 0, fmt.Errorf("__wbindgen_malloc not found")
	}

	length := uint64(len(str))
	// malloc takes (len, alignment)
	// Alignment is usually 1 for strings
	res, err := malloc.Call(context.Background(), length, 1)
	if err != nil {
		return 0, 0, err
	}
	ptr := res[0]

	// Write bytes to memory
	mem := mod.Memory()
	if !mem.Write(uint32(ptr), []byte(str)) {
		return 0, 0, fmt.Errorf("failed to write string to wasm memory")
	}

	return ptr, length, nil
}
