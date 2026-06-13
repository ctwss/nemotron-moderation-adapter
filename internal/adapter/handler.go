package adapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type ModerationClient interface {
	Moderate(ctx context.Context, apiKey string, messages []NVIDIAMessage) (ParsedSafety, error)
	HasFallbackAPIKey() bool
}

type Handler struct {
	client ModerationClient
}

func NewHandler(client ModerationClient) *Handler {
	return &Handler{client: client}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := "modr-" + randomHex(16)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	log.Printf("moderation request start id=%s remote=%s method=%s path=%s content_length=%d user_agent=%q", requestID, r.RemoteAddr, r.Method, r.URL.Path, r.ContentLength, r.UserAgent())

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		log.Printf("moderation request read_error id=%s remote=%s elapsed_ms=%d err=%v", requestID, r.RemoteAddr, time.Since(started).Milliseconds(), err)
		writeError(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}
	log.Printf("moderation request id=%s remote=%s bytes=%d body=%q", requestID, r.RemoteAddr, len(body), truncateForLog(string(body), 65536))

	var req ModerationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	apiKey := bearerToken(r.Header.Get("Authorization"))
	if apiKey == "" && !h.client.HasFallbackAPIKey() {
		writeError(w, http.StatusUnauthorized, "missing Authorization bearer token")
		return
	}

	items, err := buildModerationItems(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("moderation input id=%s summary=%q", requestID, inputSummary(req.Input, len(items)))

	results := make([]ModerationResult, 0, len(items))
	for i, item := range items {
		itemStarted := time.Now()
		parsed, err := h.client.Moderate(r.Context(), apiKey, item.Messages)
		log.Printf("moderation upstream id=%s item=%d elapsed_ms=%d unsafe=%t categories=%q err=%v", requestID, i, time.Since(itemStarted).Milliseconds(), parsed.Unsafe, parsed.Categories, err)
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream moderation request failed")
			return
		}
		result, audit := MapSafetyWithAudit(parsed)
		log.Printf("moderation audit id=%s item=%d raw_output=%q parsed_unsafe=%t parse_degraded=%t aegis_categories=%q openai_categories=%s openai_scores=%s mappings=%s weak_mappings=%s unknown_categories=%q fallback_category=%t",
			requestID,
			i,
			truncateForLog(parsed.RawOutput, 4096),
			parsed.Unsafe,
			parsed.ParseDegraded,
			parsed.Categories,
			jsonForLog(result.Categories),
			jsonForLog(result.CategoryScores),
			jsonForLog(audit.Mappings),
			jsonForLog(audit.WeakMappings),
			audit.UnknownCategories,
			audit.FallbackCategory,
		)
		results = append(results, result)
	}

	writeJSON(w, http.StatusOK, ModerationResponse{
		ID:      requestID,
		Model:   OpenAIModel,
		Results: results,
	})
	log.Printf("moderation response id=%s items=%d elapsed_ms=%d", requestID, len(items), time.Since(started).Milliseconds())
}

type moderationItem struct {
	Messages []NVIDIAMessage
}

func buildModerationItems(req ModerationRequest) ([]moderationItem, error) {
	if len(req.Input) == 0 {
		return nil, errors.New("input is required")
	}

	output, err := parseOptionalString(req.Output)
	if err != nil {
		return nil, fmt.Errorf("output must be a string when provided")
	}

	var inputString string
	if err := json.Unmarshal(req.Input, &inputString); err == nil {
		return []moderationItem{{
			Messages: appendOutput([]NVIDIAMessage{{Role: "user", Content: inputString}}, output),
		}}, nil
	}

	var rawItems []json.RawMessage
	if err := json.Unmarshal(req.Input, &rawItems); err == nil {
		return buildArrayModerationItems(rawItems, output)
	}

	return nil, errors.New("input must be a string, string array, or content part array")
}

func buildArrayModerationItems(rawItems []json.RawMessage, output string) ([]moderationItem, error) {
	if len(rawItems) == 0 {
		return nil, errors.New("input array must not be empty")
	}

	if parts, ok, err := parseContentPartObjectArray(rawItems); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return buildFromTopLevelContentParts(parts, output)
	}

	items := make([]moderationItem, 0, len(rawItems))
	for _, raw := range rawItems {
		if item, ok, err := buildSingleArrayItem(raw, output); ok || err != nil {
			if err != nil {
				return nil, err
			}
			items = append(items, item)
			continue
		}
		return nil, errors.New("input array items must be strings, content parts, or content part arrays")
	}
	return items, nil
}

func parseContentPartObjectArray(rawItems []json.RawMessage) ([]OpenAIContentPart, bool, error) {
	parts := make([]OpenAIContentPart, 0, len(rawItems))
	for _, raw := range rawItems {
		var part OpenAIContentPart
		if err := json.Unmarshal(raw, &part); err != nil || part.Type == "" {
			return nil, false, nil
		}
		parts = append(parts, part)
	}
	return parts, true, nil
}

func buildFromTopLevelContentParts(parts []OpenAIContentPart, output string) ([]moderationItem, error) {
	if hasImagePart(parts) || len(parts) == 1 {
		contentParts, err := convertContentParts(parts)
		if err != nil {
			return nil, err
		}
		return []moderationItem{{
			Messages: appendOutput([]NVIDIAMessage{{Role: "user", Content: contentParts}}, output),
		}}, nil
	}

	items := make([]moderationItem, 0, len(parts))
	for _, part := range parts {
		if part.Type != "text" {
			return nil, fmt.Errorf("unsupported input content part type %q", part.Type)
		}
		text := strings.TrimSpace(part.Text)
		if text == "" {
			return nil, errors.New("text content part requires non-empty text")
		}
		items = append(items, moderationItem{
			Messages: appendOutput([]NVIDIAMessage{{Role: "user", Content: part.Text}}, output),
		})
	}
	return items, nil
}

func buildSingleArrayItem(raw json.RawMessage, output string) (moderationItem, bool, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return moderationItem{
			Messages: appendOutput([]NVIDIAMessage{{Role: "user", Content: text}}, output),
		}, true, nil
	}

	var parts []OpenAIContentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		contentParts, err := convertContentParts(parts)
		if err != nil {
			return moderationItem{}, true, err
		}
		return moderationItem{
			Messages: appendOutput([]NVIDIAMessage{{Role: "user", Content: contentParts}}, output),
		}, true, nil
	}

	return moderationItem{}, false, nil
}

func parseOptionalString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func convertContentParts(parts []OpenAIContentPart) ([]NVIDIAContentPart, error) {
	if len(parts) == 0 {
		return nil, errors.New("input content part array must not be empty")
	}

	converted := make([]NVIDIAContentPart, 0, len(parts))
	for _, part := range parts {
		switch part.Type {
		case "text":
			if strings.TrimSpace(part.Text) == "" {
				return nil, errors.New("text content part requires non-empty text")
			}
			converted = append(converted, NVIDIAContentPart{Type: "text", Text: part.Text})
		case "image_url":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, errors.New("image_url content part requires image_url.url")
			}
			converted = append(converted, NVIDIAContentPart{
				Type:     "image_url",
				ImageURL: &NVIDIAImageURLPart{URL: part.ImageURL.URL},
			})
		default:
			return nil, fmt.Errorf("unsupported input content part type %q", part.Type)
		}
	}
	return converted, nil
}

func hasImagePart(parts []OpenAIContentPart) bool {
	for _, part := range parts {
		if part.Type == "image_url" {
			return true
		}
	}
	return false
}

func appendOutput(messages []NVIDIAMessage, output string) []NVIDIAMessage {
	if output == "" {
		return messages
	}
	return append(messages, NVIDIAMessage{Role: "assistant", Content: output})
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"message": message,
			"type":    "invalid_request_error",
		},
	})
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(buf)
}

func truncateForLog(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "...<truncated>"
}

func jsonForLog(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "null"
	}
	return string(data)
}

func inputSummary(raw json.RawMessage, itemCount int) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return fmt.Sprintf("type=string chars=%d items=%d", len(text), itemCount)
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err == nil {
		return fmt.Sprintf("type=array raw_items=%d moderation_items=%d bytes=%d", len(items), itemCount, len(raw))
	}

	return fmt.Sprintf("type=unknown moderation_items=%d bytes=%d", itemCount, len(raw))
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
