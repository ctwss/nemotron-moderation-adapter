package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type NVIDIAClient struct {
	baseURL    string
	apiKeys    []string
	nextKey    atomic.Uint64
	httpClient *http.Client
}

func NewNVIDIAClient(baseURL string, apiKeys []string, timeout time.Duration) *NVIDIAClient {
	return &NVIDIAClient{
		baseURL: baseURL,
		apiKeys: append([]string(nil), apiKeys...),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *NVIDIAClient) Moderate(ctx context.Context, apiKey string, messages []NVIDIAMessage) (ParsedSafety, error) {
	started := time.Now()
	body := NVIDIARequest{
		Model:       NVIDIAModel,
		Messages:    messages,
		MaxTokens:   512,
		Temperature: 0.20,
		TopP:        0.70,
		Stream:      false,
		ChatTemplateKwargs: map[string]interface{}{
			"request_categories": "/categories",
			"enable_thinking":    true,
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return ParsedSafety{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return ParsedSafety{}, err
	}
	if apiKey == "" {
		var err error
		apiKey, err = c.apiKey()
		if err != nil {
			return ParsedSafety{}, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("nvidia request elapsed_ms=%d err=%v", time.Since(started).Milliseconds(), err)
		return ParsedSafety{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ParsedSafety{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("nvidia request elapsed_ms=%d status=%d body=%q", time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 4096))
		return ParsedSafety{}, fmt.Errorf("nvidia request failed: status=%d", resp.StatusCode)
	}

	var parsed NVIDIAResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return ParsedSafety{}, err
	}
	if len(parsed.Choices) == 0 {
		return ParsedSafety{}, fmt.Errorf("nvidia response contained no choices")
	}

	content, ok := parsed.Choices[0].Message.Content.(string)
	if !ok {
		return ParsedSafety{}, fmt.Errorf("nvidia response message content was not a string")
	}
	parsedSafety := ParseSafetyOutput(content)
	log.Printf("nvidia request elapsed_ms=%d status=%d unsafe=%t parse_degraded=%t categories=%q", time.Since(started).Milliseconds(), resp.StatusCode, parsedSafety.Unsafe, parsedSafety.ParseDegraded, parsedSafety.Categories)
	return parsedSafety, nil
}

func (c *NVIDIAClient) apiKey() (string, error) {
	if len(c.apiKeys) == 0 {
		return "", errors.New("no NVIDIA API keys configured")
	}
	index := c.nextKey.Add(1) - 1
	return c.apiKeys[index%uint64(len(c.apiKeys))], nil
}

func (c *NVIDIAClient) HasFallbackAPIKey() bool {
	return len(c.apiKeys) > 0
}
