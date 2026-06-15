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
	Moderate(ctx context.Context, apiKey string, model string, messages []NVIDIAMessage) (ParsedSafety, error)
	Adjudicate(ctx context.Context, apiKey string, model string, input AdjudicationInput) (AdjudicationResult, error)
	HasFallbackAPIKey() bool
}

type OpenAIRecheckClient interface {
	Recheck(ctx context.Context, input interface{}, inputTypes []string) OpenAIRecheckOutcome
}

type Handler struct {
	client              ModerationClient
	openAIRecheck       OpenAIRecheckClient
	mappingOptions      MappingOptions
	textModel           string
	multimodalModel     string
	adjudicatorModel    string
	enableAdjudication  bool
	enableOpenAIRecheck bool
	maxBodyBytes        int64
}

func NewHandler(client ModerationClient) *Handler {
	return NewHandlerWithOptions(client, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		EnableOpenAIRecheck: true,
	})
}

func NewHandlerWithMappingOptions(client ModerationClient, mappingOptions MappingOptions) *Handler {
	return NewHandlerWithOptions(client, HandlerOptions{
		MappingOptions:      mappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		EnableOpenAIRecheck: true,
	})
}

type HandlerOptions struct {
	MappingOptions      MappingOptions
	TextModel           string
	MultimodalModel     string
	AdjudicatorModel    string
	EnableAdjudication  bool
	OpenAIRecheck       OpenAIRecheckClient
	EnableOpenAIRecheck bool
	MaxBodyBytes        int64
}

func NewHandlerWithOptions(client ModerationClient, options HandlerOptions) *Handler {
	if options.TextModel == "" {
		options.TextModel = DefaultNVIDIATextModel
	}
	if options.MultimodalModel == "" {
		options.MultimodalModel = DefaultNVIDIAMultimodalModel
	}
	if options.AdjudicatorModel == "" {
		options.AdjudicatorModel = DefaultNVIDIAAdjudicatorModel
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = 20 << 20
	}
	return &Handler{
		client:              client,
		openAIRecheck:       options.OpenAIRecheck,
		mappingOptions:      options.MappingOptions,
		textModel:           options.TextModel,
		multimodalModel:     options.MultimodalModel,
		adjudicatorModel:    options.AdjudicatorModel,
		enableAdjudication:  options.EnableAdjudication,
		enableOpenAIRecheck: options.EnableOpenAIRecheck,
		maxBodyBytes:        options.MaxBodyBytes,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := "modr-" + randomHex(16)
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	log.Printf("moderation request start id=%s remote=%s method=%s path=%s content_length=%d user_agent=%q", requestID, r.RemoteAddr, r.Method, r.URL.Path, r.ContentLength, r.UserAgent())

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
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
		model := h.modelForItem(item)
		parsed, err := h.client.Moderate(r.Context(), apiKey, model, item.Messages)
		log.Printf("moderation upstream id=%s item=%d model=%q elapsed_ms=%d unsafe=%t categories=%q err=%v", requestID, i, model, time.Since(itemStarted).Milliseconds(), parsed.Unsafe, parsed.Categories, err)
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream moderation request failed")
			return
		}
		result, audit := MapSafetyWithAuditInputTypes(parsed, h.mappingOptions, item.InputTypes)
		audit.BusinessContext = hasBusinessContext(item.UserText)
		primaryRiskLevel := audit.RiskLevel
		adjudicationTriggered := shouldAdjudicate(parsed, audit, item, h.enableAdjudication)
		var adjudication AdjudicationResult
		var adjudicationErr error
		if adjudicationTriggered {
			adjudication, adjudicationErr = h.client.Adjudicate(r.Context(), apiKey, h.adjudicatorModel, AdjudicationInput{
				UserText:          item.UserText,
				HasImage:          item.HasImage,
				PrimaryRawOutput:  parsed.RawOutput,
				PrimaryCategories: parsed.Categories,
				BusinessContext:   audit.BusinessContext,
			})
			if adjudicationErr == nil && adjudication.Decision == "allow" {
				result, audit = suppressAdjudicatedResult(result, audit)
			}
		} else if !h.enableAdjudication && audit.BusinessContext {
			result, audit = suppressBusinessContextIfEligible(result, audit)
		}
		openAIOutcome := h.recheckWithOpenAIIfNeeded(r.Context(), result, item)
		finalSource := "nvidia"
		if openAIOutcome.Applied {
			result = openAIOutcome.Result
			finalSource = "openai"
		}
		log.Printf("moderation audit id=%s item=%d review_target=%q raw_output=%q parsed_unsafe=%t parse_degraded=%t aegis_categories=%q openai_categories=%s openai_scores=%s mappings=%s weak_mappings=%s unknown_categories=%q fallback_category=%t primary_risk_level=%q final_risk_level=%q blocked_by=%q business_context=%t suppressed_business_context=%t unknown_category_policy=%q suppressed_unknown_category=%t adjudication_enabled=%t adjudication_triggered=%t adjudication_model=%q adjudication_decision=%q adjudication_risk_level=%q adjudication_reason=%q adjudication_err=%v openai_recheck_enabled=%t openai_recheck_triggered=%t openai_cache_hit=%t openai_skipped_reason=%q openai_status=%d openai_id=%q openai_flagged=%t openai_err=%v final_source=%q",
			requestID,
			i,
			item.ReviewTarget,
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
			primaryRiskLevel,
			audit.RiskLevel,
			audit.BlockedBy,
			audit.BusinessContext,
			audit.SuppressedBusinessContext,
			audit.UnknownCategoryPolicy,
			audit.SuppressedUnknownCategory,
			h.enableAdjudication,
			adjudicationTriggered,
			h.adjudicatorModel,
			adjudication.Decision,
			adjudication.RiskLevel,
			truncateForLog(adjudication.Reason, 512),
			adjudicationErr,
			h.enableOpenAIRecheck && h.openAIRecheck != nil,
			openAIOutcome.Applied || openAIOutcome.SkippedReason != "not_flagged",
			openAIOutcome.CacheHit,
			openAIOutcome.SkippedReason,
			openAIOutcome.Status,
			openAIOutcome.ID,
			openAIOutcome.Result.Flagged,
			openAIOutcome.Err,
			finalSource,
		)
		results = append(results, result)
	}

	response := ModerationResponse{
		ID:      requestID,
		Model:   OpenAIModel,
		Results: results,
	}
	writeJSON(w, http.StatusOK, response)
	log.Printf("moderation response_body id=%s body=%s", requestID, jsonForLog(response))
	log.Printf("moderation response id=%s items=%d elapsed_ms=%d", requestID, len(items), time.Since(started).Milliseconds())
}

type moderationItem struct {
	Messages     []NVIDIAMessage
	AuditText    string
	UserText     string
	ReviewTarget string
	OpenAIInput  interface{}
	HasText      bool
	HasImage     bool
	InputTypes   []string
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
		return []moderationItem{newTextModerationItem(inputString, output)}, nil
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
		contentParts, openAIInput, userText, reviewTarget, err := convertContentParts(parts, output)
		if err != nil {
			return nil, err
		}
		return []moderationItem{{
			Messages:     appendOutput([]NVIDIAMessage{{Role: "user", Content: contentParts}}, output),
			AuditText:    auditTextFromContentParts(parts),
			UserText:     userText,
			ReviewTarget: reviewTarget,
			OpenAIInput:  openAIInput,
			HasText:      strings.TrimSpace(userText) != "",
			HasImage:     hasImagePart(parts),
			InputTypes:   inputTypesFromContentParts(parts),
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
		items = append(items, newTextModerationItem(part.Text, output))
	}
	return items, nil
}

func buildSingleArrayItem(raw json.RawMessage, output string) (moderationItem, bool, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return newTextModerationItem(text, output), true, nil
	}

	var parts []OpenAIContentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		contentParts, openAIInput, userText, reviewTarget, err := convertContentParts(parts, output)
		if err != nil {
			return moderationItem{}, true, err
		}
		return moderationItem{
			Messages:     appendOutput([]NVIDIAMessage{{Role: "user", Content: contentParts}}, output),
			AuditText:    auditTextFromContentParts(parts),
			UserText:     userText,
			ReviewTarget: reviewTarget,
			OpenAIInput:  openAIInput,
			HasText:      strings.TrimSpace(userText) != "",
			HasImage:     hasImagePart(parts),
			InputTypes:   inputTypesFromContentParts(parts),
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

func newTextModerationItem(text string, output string) moderationItem {
	reviewText, reviewTarget := moderationReviewText(text)
	return moderationItem{
		Messages:     appendOutput([]NVIDIAMessage{{Role: "user", Content: reviewText}}, output),
		AuditText:    text,
		UserText:     reviewText,
		ReviewTarget: reviewTarget,
		OpenAIInput:  appendOutputToOpenAIInput(reviewText, output),
		HasText:      strings.TrimSpace(reviewText) != "",
		InputTypes:   []string{"text"},
	}
}

func convertContentParts(parts []OpenAIContentPart, output string) ([]NVIDIAContentPart, interface{}, string, string, error) {
	if len(parts) == 0 {
		return nil, nil, "", "", errors.New("input content part array must not be empty")
	}

	converted := make([]NVIDIAContentPart, 0, len(parts))
	openAIParts := make([]OpenAIContentPart, 0, len(parts))
	var textValues []string
	reviewTarget := "input"
	hasImage := false
	for _, part := range parts {
		switch part.Type {
		case "text":
			if strings.TrimSpace(part.Text) == "" {
				return nil, nil, "", "", errors.New("text content part requires non-empty text")
			}
			reviewText, target := moderationReviewText(part.Text)
			if target != "input" {
				reviewTarget = target
			}
			textValues = append(textValues, reviewText)
			converted = append(converted, NVIDIAContentPart{Type: "text", Text: reviewText})
			openAIParts = append(openAIParts, OpenAIContentPart{Type: "text", Text: reviewText})
		case "image_url":
			if part.ImageURL == nil || strings.TrimSpace(part.ImageURL.URL) == "" {
				return nil, nil, "", "", errors.New("image_url content part requires image_url.url")
			}
			imageURL, _, err := optimizeImageURL(part.ImageURL.URL)
			if err != nil {
				return nil, nil, "", "", err
			}
			converted = append(converted, NVIDIAContentPart{
				Type:     "image_url",
				ImageURL: &NVIDIAImageURLPart{URL: imageURL},
			})
			openAIParts = append(openAIParts, OpenAIContentPart{
				Type:     "image_url",
				ImageURL: &ImageURLPart{URL: imageURL},
			})
			hasImage = true
		default:
			return nil, nil, "", "", fmt.Errorf("unsupported input content part type %q", part.Type)
		}
	}
	openAIInput := interface{}(openAIParts)
	if !hasImage && len(openAIParts) == 1 && openAIParts[0].Type == "text" {
		openAIInput = openAIParts[0].Text
	}
	openAIInput = appendOutputToOpenAIInput(openAIInput, output)
	return converted, openAIInput, strings.Join(textValues, "\n"), reviewTarget, nil
}

func moderationReviewText(text string) (string, string) {
	if candidates, ok := extractAmbientSuggestionCandidates(text); ok {
		return candidates, "ambient_suggestion_candidates"
	}
	return text, "input"
}

func extractAmbientSuggestionCandidates(text string) (string, bool) {
	normalized := strings.ToLower(text)
	if !strings.Contains(normalized, "ambient suggestion candidates") ||
		!strings.Contains(normalized, "suggestion_id") ||
		(!strings.Contains(normalized, "upholding safety and compliance standards") &&
			!strings.Contains(normalized, "policies to always exclude")) {
		return "", false
	}

	marker := "ambient suggestion candidates"
	start := strings.Index(normalized, marker)
	if start < 0 {
		return "", false
	}
	candidateSection := text[start:]
	candidateSectionLower := normalized[start:]

	if fenceStart := strings.Index(candidateSection, "```"); fenceStart >= 0 {
		contentStart := fenceStart + len("```")
		if lineBreak := strings.IndexAny(candidateSection[contentStart:], "\r\n"); lineBreak >= 0 {
			contentStart += lineBreak + 1
		}
		if fenceEnd := strings.Index(candidateSection[contentStart:], "```"); fenceEnd >= 0 {
			candidates := strings.TrimSpace(candidateSection[contentStart : contentStart+fenceEnd])
			if candidates != "" {
				return candidates, true
			}
		}
	}

	contentEnd := len(candidateSection)
	if outputFormat := strings.Index(candidateSectionLower, "# output format"); outputFormat > 0 {
		contentEnd = outputFormat
	}
	candidates := strings.TrimSpace(candidateSection[:contentEnd])
	if candidates == "" {
		return "", false
	}
	return candidates, true
}

func hasImagePart(parts []OpenAIContentPart) bool {
	for _, part := range parts {
		if part.Type == "image_url" {
			return true
		}
	}
	return false
}

func hasTextPart(parts []OpenAIContentPart) bool {
	return strings.TrimSpace(textFromContentParts(parts)) != ""
}

func textFromContentParts(parts []OpenAIContentPart) string {
	var values []string
	for _, part := range parts {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			values = append(values, part.Text)
		}
	}
	return strings.Join(values, "\n")
}

func inputTypesFromContentParts(parts []OpenAIContentPart) []string {
	var inputTypes []string
	for _, part := range parts {
		switch part.Type {
		case "text":
			inputTypes = append(inputTypes, "text")
		case "image_url":
			inputTypes = append(inputTypes, "image")
		}
	}
	return normalizeInputTypes(inputTypes)
}

func shouldAdjudicate(parsed ParsedSafety, audit ModerationAudit, item moderationItem, enabled bool) bool {
	if !enabled || !parsed.Unsafe || !audit.BusinessContext || !item.HasText || len(parsed.Categories) == 0 {
		return false
	}
	for _, category := range parsed.Categories {
		if !isAdjudicationCategory(category) {
			return false
		}
	}
	return true
}

func isAdjudicationCategory(category string) bool {
	switch normalizeCategory(category) {
	case "fraud/deception", "criminal planning/confessions", "illegal activity", "pii/privacy", "manipulation":
		return true
	default:
		return false
	}
}

func suppressAdjudicatedResult(result ModerationResult, audit ModerationAudit) (ModerationResult, ModerationAudit) {
	result = clearModerationResult(result)
	audit.RiskLevel = RiskLevelAdjudicationAllowed
	audit.SuppressedBusinessContext = true
	return result, audit
}

func (h *Handler) recheckWithOpenAIIfNeeded(ctx context.Context, result ModerationResult, item moderationItem) OpenAIRecheckOutcome {
	if !result.Flagged {
		return OpenAIRecheckOutcome{SkippedReason: "not_flagged"}
	}
	if !h.enableOpenAIRecheck {
		return OpenAIRecheckOutcome{SkippedReason: "disabled"}
	}
	if h.openAIRecheck == nil {
		return OpenAIRecheckOutcome{SkippedReason: "missing_openai_client"}
	}
	return h.openAIRecheck.Recheck(ctx, item.OpenAIInput, item.InputTypes)
}

func appendOutput(messages []NVIDIAMessage, output string) []NVIDIAMessage {
	if output == "" {
		return messages
	}
	return append(messages, NVIDIAMessage{Role: "assistant", Content: output})
}

func appendOutputToOpenAIInput(input interface{}, output string) interface{} {
	if strings.TrimSpace(output) == "" {
		return input
	}
	outputText := "\n\nAssistant output:\n" + output
	switch value := input.(type) {
	case string:
		return value + outputText
	case []OpenAIContentPart:
		parts := append([]OpenAIContentPart(nil), value...)
		parts = append(parts, OpenAIContentPart{Type: "text", Text: strings.TrimSpace(outputText)})
		return parts
	default:
		return input
	}
}

func (h *Handler) modelForItem(item moderationItem) string {
	if item.HasImage {
		return h.multimodalModel
	}
	return h.textModel
}

func auditTextFromContentParts(parts []OpenAIContentPart) string {
	var values []string
	for _, part := range parts {
		switch part.Type {
		case "text":
			values = append(values, part.Text)
		case "image_url":
			if part.ImageURL != nil {
				values = append(values, part.ImageURL.URL)
			}
		}
	}
	return strings.Join(values, "\n")
}

func hasBusinessContext(text string) bool {
	normalized := strings.ToLower(text)
	keywords := []string{
		"oauth",
		"openid",
		"wechat",
		"callback",
		"redirect_uri",
		"redirect url",
		"sql",
		"api",
		"currency inflation",
		"change every price",
		"pricing",
		"payment config",
		"payment parameters",
		"container",
		"server",
		"微信授权",
		"微信登录",
		"微信支付",
		"支付参数",
		"登录地址",
		"授权地址",
		"回调地址",
		"域名跳转",
		"实现方案",
		"参考项目",
		"价格配置",
		"货币膨胀",
		"改价",
		"容器",
		"服务器",
		"站点",
	}
	for _, keyword := range keywords {
		if strings.Contains(normalized, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func suppressBusinessContextIfEligible(result ModerationResult, audit ModerationAudit) (ModerationResult, ModerationAudit) {
	if !result.Flagged || len(audit.Mappings) == 0 {
		return result, audit
	}
	for _, mapping := range audit.Mappings {
		if !isBusinessSuppressibleCategory(mapping.AegisCategory) {
			return result, audit
		}
	}
	result = clearModerationResult(result)
	audit.RiskLevel = RiskLevelBusinessSuppressed
	audit.SuppressedBusinessContext = true
	return result, audit
}

func clearModerationResult(result ModerationResult) ModerationResult {
	for _, category := range OpenAICategories {
		result.Categories[category] = false
		result.CategoryScores[category] = SafeCategoryScore
	}
	result.Flagged = false
	return result
}

func isBusinessSuppressibleCategory(category string) bool {
	switch normalizeCategory(category) {
	case "fraud/deception", "criminal planning/confessions", "illegal activity":
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"id":      "",
		"model":   OpenAIModel,
		"results": []ModerationResult{},
		"error": map[string]string{
			"message": message,
			"type":    "invalid_request_error",
		},
	})
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
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
