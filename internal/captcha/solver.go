package captcha

import (
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
)

type ChallengeResponse struct {
	Challenge json.RawMessage `json:"challenge"`
	Expires   int64           `json:"expires"`
	Token     string          `json:"token"`
}

const solverJS = `const fs = require('fs');
async function run() {
    const salt = process.argv[2];
    const target = process.argv[3];
    const wasmPath = process.argv[4];
    const wasmBytes = fs.readFileSync(wasmPath);
    
    let exports = null;
    const imports = {
        wbg: {
            __wbindgen_init_externref_table: function() {
                if (!exports) throw new Error("Instance not ready");
                const table = exports.__wbindgen_export_0;
                if (table) {
                    const t = table.grow(4);
                    table.set(0, undefined);
                    table.set(t + 0, undefined);
                    table.set(t + 1, null);
                    table.set(t + 2, true);
                    table.set(t + 3, false);
                }
            }
        }
    };

    const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
    exports = instance.exports;
    if (exports.__wbindgen_start) exports.__wbindgen_start();

    let WASM_VECTOR_LEN = 0;
    const mem = new Uint8Array(exports.memory.buffer);
    function passStringToWasm0(str) {
        const len = str.length;
        let ptr = exports.__wbindgen_malloc(len, 1);
        for (let i = 0; i < len; i++) mem[ptr + i] = str.charCodeAt(i);
        WASM_VECTOR_LEN = len;
        return ptr;
    }

    const ptr1 = passStringToWasm0(salt);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(target);
    const len2 = WASM_VECTOR_LEN;

    const res = exports.solve_pow(ptr1, len1, ptr2, len2);
    console.log(BigInt.asUintN(64, res).toString(16));
}
run().catch(e => { console.error(e.message); process.exit(1); });`

type Solver struct {
	client      HTTPClient
	targetURL   string
	wasmURL     string
	challengeURL string
	tempDir     string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

func NewSolver(client HTTPClient, targetURL string) *Solver {
	return &Solver{
		client:      client,
		targetURL:   strings.TrimRight(targetURL, "/"),
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

	// 2. Solve PoW using Node.js
	proof, err := s.solvePoWWithNode(challenge.Token, string(challenge.Challenge))
	if err != nil {
		return "", fmt.Errorf("failed to solve PoW: %w", err)
	}

	// 3. Format token: salt:hex_proof
	return fmt.Sprintf("%s:%s", challenge.Token, proof), nil
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

	var result ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *Solver) solvePoWWithNode(salt, target string) (string, error) {
	// Prepare temp directory
	if s.tempDir == "" {
		dir, err := os.MkdirTemp("", "monkeycode-captcha")
		if err != nil {
			return "", fmt.Errorf("failed to create temp dir: %w", err)
		}
		s.tempDir = dir
	}

	// Fetch Wasm
	wasmPath := filepath.Join(s.tempDir, "cap_wasm_bg.wasm")
	if _, err := os.Stat(wasmPath); os.IsNotExist(err) {
		wasmBytes, err := s.fetchWasm()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
			return "", err
		}
	}

	// Fetch JS glue code
	jsGluePath := filepath.Join(s.tempDir, "cap_wasm.mjs")
	if _, err := os.Stat(jsGluePath); os.IsNotExist(err) {
		jsGlueBytes, err := s.fetchWasmJS()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(jsGluePath, jsGlueBytes, 0644); err != nil {
			return "", err
		}
	}

	// Write runner script
	runnerJS := `
import init, { solve_pow } from './cap_wasm.mjs';
import { readFileSync } from 'fs';

async function run() {
    const salt = process.argv[2];
    const target = process.argv[3];
    const wasmPath = process.argv[4];
    
    const wasmBytes = readFileSync(wasmPath);
    await init(wasmBytes); 
    
    const result = solve_pow(salt, target);
    console.log(result.toString(16));
}
run().catch(e => { console.error(e.message); process.exit(1); });
`

	runnerPath := filepath.Join(s.tempDir, "runner.mjs")
	if err := os.WriteFile(runnerPath, []byte(runnerJS), 0644); err != nil {
		return "", err
	}

	// Execute Node.js
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "node", runnerPath, salt, target, wasmPath)
	cmd.Stderr = os.Stderr // Print stderr for debugging if it fails
	
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("node failed: %s", string(exitErr.Stderr))
		}
		return "", err
	}

	result := strings.TrimSpace(string(out))
	if result == "" {
		return "", fmt.Errorf("node solver returned empty result")
	}

	log.Printf("PoW solved successfully, result: %s", result)
	return result, nil
}

func (s *Solver) fetchWasmJS() ([]byte, error) {
	jsURL := s.targetURL + "/captcha/cap_wasm.js"
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasm JS fetch failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (s *Solver) fetchWasm() ([]byte, error) {
	req, err := http.NewRequest("GET", s.wasmURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasm fetch failed with status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
