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
	"strings"
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

func (c *NVIDIAClient) Moderate(ctx context.Context, apiKey string, model string, messages []NVIDIAMessage) (ParsedSafety, error) {
	started := time.Now()
	if model == "" {
		model = DefaultNVIDIATextModel
	}
	body := NVIDIARequest{
		Model:              model,
		Messages:           messages,
		MaxTokens:          512,
		Temperature:        0,
		TopP:               0.70,
		Stream:             false,
		ChatTemplateKwargs: chatTemplateKwargs(model),
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
		log.Printf("nvidia request model=%q elapsed_ms=%d err=%v", model, time.Since(started).Milliseconds(), err)
		return ParsedSafety{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ParsedSafety{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("nvidia request model=%q elapsed_ms=%d status=%d body=%q", model, time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 4096))
		return ParsedSafety{}, fmt.Errorf("nvidia request failed: status=%d", resp.StatusCode)
	}

	var parsed NVIDIAResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return ParsedSafety{}, err
	}
	if len(parsed.Choices) == 0 {
		return ParsedSafety{}, fmt.Errorf("nvidia response contained no choices")
	}

	content, err := messageContentString(parsed.Choices[0].Message.Content)
	if err != nil {
		log.Printf("nvidia request model=%q elapsed_ms=%d status=%d invalid_content=%q err=%v", model, time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 4096), err)
		return ParsedSafety{}, err
	}
	parsedSafety := ParseSafetyOutput(content)
	log.Printf("nvidia request model=%q elapsed_ms=%d status=%d unsafe=%t parse_degraded=%t categories=%q", model, time.Since(started).Milliseconds(), resp.StatusCode, parsedSafety.Unsafe, parsedSafety.ParseDegraded, parsedSafety.Categories)
	return parsedSafety, nil
}

func (c *NVIDIAClient) Adjudicate(ctx context.Context, apiKey string, model string, input AdjudicationInput) (AdjudicationResult, error) {
	started := time.Now()
	if model == "" {
		model = DefaultNVIDIAAdjudicatorModel
	}
	body := NVIDIARequest{
		Model:       model,
		Messages:    buildAdjudicationMessages(input),
		MaxTokens:   256,
		Temperature: 0,
		TopP:        0.70,
		Stream:      false,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return AdjudicationResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return AdjudicationResult{}, err
	}
	if apiKey == "" {
		var err error
		apiKey, err = c.apiKey()
		if err != nil {
			return AdjudicationResult{}, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("nvidia adjudication request model=%q elapsed_ms=%d err=%v", model, time.Since(started).Milliseconds(), err)
		return AdjudicationResult{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return AdjudicationResult{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("nvidia adjudication request model=%q elapsed_ms=%d status=%d body=%q", model, time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 4096))
		return AdjudicationResult{}, fmt.Errorf("nvidia adjudication request failed: status=%d", resp.StatusCode)
	}

	var parsed NVIDIAResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return AdjudicationResult{}, err
	}
	if len(parsed.Choices) == 0 {
		return AdjudicationResult{}, fmt.Errorf("nvidia adjudication response contained no choices")
	}

	content, err := messageContentString(parsed.Choices[0].Message.Content)
	if err != nil {
		log.Printf("nvidia adjudication request model=%q elapsed_ms=%d status=%d invalid_content=%q err=%v", model, time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(string(respBody), 4096), err)
		return AdjudicationResult{}, err
	}
	result, err := ParseAdjudicationOutput(content)
	if err != nil {
		log.Printf("nvidia adjudication request model=%q elapsed_ms=%d status=%d invalid_json=%q err=%v", model, time.Since(started).Milliseconds(), resp.StatusCode, truncateForLog(content, 4096), err)
		return AdjudicationResult{}, err
	}
	log.Printf("nvidia adjudication request model=%q elapsed_ms=%d status=%d decision=%q risk_level=%q categories=%q", model, time.Since(started).Milliseconds(), resp.StatusCode, result.Decision, result.RiskLevel, result.Categories)
	return result, nil
}

func chatTemplateKwargs(model string) map[string]interface{} {
	if model != DefaultNVIDIAMultimodalModel {
		return nil
	}
	return map[string]interface{}{
		"request_categories": "/categories",
		"enable_thinking":    true,
	}
}

func buildAdjudicationMessages(input AdjudicationInput) []NVIDIAMessage {
	payload := map[string]interface{}{
		"user_text":          truncateForLog(input.UserText, 4000),
		"has_image":          input.HasImage,
		"primary_raw_output": truncateForLog(input.PrimaryRawOutput, 4000),
		"primary_categories": input.PrimaryCategories,
		"business_context":   input.BusinessContext,
		"allowed_context":    "Benign software development, server operations, payment configuration migration, OAuth/login/callback setup, pricing configuration, and UI/style review are allowed when the text asks for implementation or migration help without theft, fraud, credential exfiltration, malware, or bypassing authorization.",
		"block_policy":       "Block only if the user is asking to commit fraud, steal money or credentials, bypass authorization, deploy malware, exploit systems, evade detection, doxx, self-harm, threaten violence, or create sexual content involving minors.",
		"output_requirement": `Return only JSON: {"decision":"allow|block","risk_level":"none|low|medium|high","reason":"short reason","categories":["..."]}`,
	}
	payloadBytes, _ := json.Marshal(payload)
	user := strings.Join([]string{
		"Adjudicate whether the primary content-safety result should be enforced.",
		"Use the supplied policy. Prefer allow for benign business/development/operations text.",
		"Return only the required JSON object.",
		string(payloadBytes),
	}, "\n")
	return []NVIDIAMessage{
		{
			Role:    "system",
			Content: "You are a content safety adjudicator. Return strict JSON only and do not include markdown.",
		},
		{
			Role:    "user",
			Content: user,
		},
	}
}

func messageContentString(content interface{}) (string, error) {
	switch value := content.(type) {
	case string:
		return value, nil
	case []interface{}:
		var out bytes.Buffer
		for _, part := range value {
			switch p := part.(type) {
			case string:
				out.WriteString(p)
			case map[string]interface{}:
				if text, ok := p["text"].(string); ok {
					out.WriteString(text)
					continue
				}
				if text, ok := p["content"].(string); ok {
					out.WriteString(text)
					continue
				}
				encoded, _ := json.Marshal(p)
				out.Write(encoded)
			default:
				encoded, _ := json.Marshal(p)
				out.Write(encoded)
			}
		}
		if out.Len() == 0 {
			return "", fmt.Errorf("nvidia response message content was empty")
		}
		return out.String(), nil
	case map[string]interface{}:
		if text, ok := value["text"].(string); ok {
			return text, nil
		}
		if text, ok := value["content"].(string); ok {
			return text, nil
		}
		encoded, _ := json.Marshal(value)
		return string(encoded), nil
	default:
		return "", fmt.Errorf("nvidia response message content had unsupported type %T", content)
	}
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
