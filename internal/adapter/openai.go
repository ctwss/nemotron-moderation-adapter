package adapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type OpenAIClient struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
	cache      *openAIRecheckCache
	disabled   atomic.Bool
}

func NewOpenAIClient(baseURL string, apiKey string, model string, timeout time.Duration, cacheTTL time.Duration, cacheMaxEntries int) *OpenAIClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultOpenAIBaseURL
	}
	if model == "" {
		model = OpenAIModel
	}
	return &OpenAIClient{
		baseURL: baseURL,
		apiKey:  strings.TrimSpace(apiKey),
		model:   model,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		cache: newOpenAIRecheckCache(cacheTTL, cacheMaxEntries),
	}
}

type openAIRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"`
}

type openAIResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []ModerationResult `json:"results"`
}

func (c *OpenAIClient) Recheck(ctx context.Context, input interface{}, inputTypes []string) OpenAIRecheckOutcome {
	if c == nil || c.apiKey == "" {
		return OpenAIRecheckOutcome{SkippedReason: "missing_openai_api_key"}
	}
	if c.disabled.Load() {
		return OpenAIRecheckOutcome{SkippedReason: "openai_api_key_disabled"}
	}

	requestBody := openAIRequest{Model: c.model, Input: input}
	cacheKey, err := openAICacheKey(requestBody)
	if err != nil {
		return OpenAIRecheckOutcome{SkippedReason: "cache_key_error", Err: err}
	}
	if cached, ok := c.cache.Get(cacheKey); ok {
		cached.CacheHit = true
		return cached
	}

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return OpenAIRecheckOutcome{SkippedReason: "marshal_error", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/moderations", bytes.NewReader(payload))
	if err != nil {
		return OpenAIRecheckOutcome{SkippedReason: "request_build_error", Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	started := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("openai recheck request elapsed_ms=%d err=%v", time.Since(started).Milliseconds(), err)
		return OpenAIRecheckOutcome{SkippedReason: "request_error", Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OpenAIRecheckOutcome{Status: resp.StatusCode, SkippedReason: "response_read_error", Err: err}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.disabled.Store(true)
		log.Printf("openai recheck request elapsed_ms=%d status=%d disabled_key=true body=%q", time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 2048))
		return OpenAIRecheckOutcome{Status: resp.StatusCode, SkippedReason: "invalid_openai_api_key"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("openai recheck request elapsed_ms=%d status=%d body=%q", time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 2048))
		return OpenAIRecheckOutcome{Status: resp.StatusCode, SkippedReason: fmt.Sprintf("openai_status_%d", resp.StatusCode)}
	}

	var parsed openAIResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return OpenAIRecheckOutcome{Status: resp.StatusCode, SkippedReason: "invalid_json", Err: err}
	}
	if len(parsed.Results) == 0 {
		return OpenAIRecheckOutcome{Status: resp.StatusCode, SkippedReason: "empty_results"}
	}

	outcome := OpenAIRecheckOutcome{
		Applied: true,
		ID:      parsed.ID,
		Status:  resp.StatusCode,
		Result:  normalizeModerationResult(parsed.Results[0], inputTypes),
	}
	c.cache.Set(cacheKey, outcome)
	log.Printf("openai recheck request elapsed_ms=%d status=%d id=%q flagged=%t", time.Since(started).Milliseconds(), resp.StatusCode, outcome.ID, outcome.Result.Flagged)
	return outcome
}

func normalizeModerationResult(result ModerationResult, inputTypes []string) ModerationResult {
	appliedInputTypes := normalizeInputTypes(inputTypes)
	categories := make(map[string]bool, len(OpenAICategories))
	scores := make(map[string]float64, len(OpenAICategories))
	applied := make(map[string][]string, len(OpenAICategories))
	for _, category := range OpenAICategories {
		if result.Categories != nil {
			categories[category] = result.Categories[category]
		}
		if result.CategoryScores != nil {
			scores[category] = result.CategoryScores[category]
		}
		if result.CategoryAppliedInputTypes != nil && len(result.CategoryAppliedInputTypes[category]) > 0 {
			applied[category] = append([]string(nil), result.CategoryAppliedInputTypes[category]...)
		} else {
			applied[category] = append([]string(nil), appliedInputTypes...)
		}
	}
	return ModerationResult{
		Flagged:                   result.Flagged || anyCategoryTrue(categories),
		Categories:                categories,
		CategoryScores:            scores,
		CategoryAppliedInputTypes: applied,
	}
}

func openAICacheKey(request openAIRequest) (string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type openAIRecheckCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	items      map[string]openAIRecheckCacheItem
	order      []string
}

type openAIRecheckCacheItem struct {
	outcome   OpenAIRecheckOutcome
	expiresAt time.Time
}

func newOpenAIRecheckCache(ttl time.Duration, maxEntries int) *openAIRecheckCache {
	if ttl <= 0 || maxEntries <= 0 {
		return &openAIRecheckCache{}
	}
	return &openAIRecheckCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		items:      make(map[string]openAIRecheckCacheItem),
	}
}

func (c *openAIRecheckCache) Get(key string) (OpenAIRecheckOutcome, bool) {
	if c == nil || c.ttl <= 0 || c.maxEntries <= 0 {
		return OpenAIRecheckOutcome{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	item, ok := c.items[key]
	if !ok {
		return OpenAIRecheckOutcome{}, false
	}
	if time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return OpenAIRecheckOutcome{}, false
	}
	outcome := item.outcome
	outcome.Err = nil
	return outcome, true
}

func (c *openAIRecheckCache) Set(key string, outcome OpenAIRecheckOutcome) {
	if c == nil || c.ttl <= 0 || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[key]; !exists {
		c.order = append(c.order, key)
	}
	c.items[key] = openAIRecheckCacheItem{
		outcome:   outcome,
		expiresAt: time.Now().Add(c.ttl),
	}
	for len(c.items) > c.maxEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}
