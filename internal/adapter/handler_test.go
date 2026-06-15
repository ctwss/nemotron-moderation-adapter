package adapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeModerationClient struct {
	results             []ParsedSafety
	err                 error
	calls               [][]NVIDIAMessage
	models              []string
	adjudicationResults []AdjudicationResult
	adjudicationErr     error
	adjudicationCalls   []AdjudicationInput
	adjudicationModels  []string
}

func (f *fakeModerationClient) HasFallbackAPIKey() bool {
	return true
}

func (f *fakeModerationClient) Moderate(_ context.Context, apiKey string, model string, messages []NVIDIAMessage) (ParsedSafety, error) {
	f.models = append(f.models, model)
	f.calls = append(f.calls, messages)
	if f.err != nil {
		return ParsedSafety{}, f.err
	}
	if len(f.results) >= len(f.calls) {
		return f.results[len(f.calls)-1], nil
	}
	return ParsedSafety{}, nil
}

func (f *fakeModerationClient) Adjudicate(_ context.Context, _ string, model string, input AdjudicationInput) (AdjudicationResult, error) {
	f.adjudicationModels = append(f.adjudicationModels, model)
	f.adjudicationCalls = append(f.adjudicationCalls, input)
	if f.adjudicationErr != nil {
		return AdjudicationResult{}, f.adjudicationErr
	}
	if len(f.adjudicationResults) >= len(f.adjudicationCalls) {
		return f.adjudicationResults[len(f.adjudicationCalls)-1], nil
	}
	return AdjudicationResult{Decision: "block", RiskLevel: "medium", Reason: "default fake block"}, nil
}

type fakeOpenAIRecheckClient struct {
	outcomes   []OpenAIRecheckOutcome
	calls      []interface{}
	inputTypes [][]string
}

func (f *fakeOpenAIRecheckClient) Recheck(_ context.Context, input interface{}, inputTypes []string) OpenAIRecheckOutcome {
	f.calls = append(f.calls, input)
	f.inputTypes = append(f.inputTypes, append([]string(nil), inputTypes...))
	if len(f.outcomes) >= len(f.calls) {
		return f.outcomes[len(f.calls)-1]
	}
	return OpenAIRecheckOutcome{SkippedReason: "fake_no_outcome"}
}

func TestHandlerUsesAuthorizationBearerToken(t *testing.T) {
	fake := &capturingModerationClient{}
	req := httptest.NewRequest(http.MethodPost, "/v1/moderations", bytes.NewBufferString(`{"input":"hello"}`))
	req.Header.Set("Authorization", "Bearer request-token")
	rec := httptest.NewRecorder()

	NewHandler(fake).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.apiKey != "request-token" {
		t.Fatalf("expected request token, got %q", fake.apiKey)
	}
}

type capturingModerationClient struct {
	apiKey string
}

func (c *capturingModerationClient) HasFallbackAPIKey() bool {
	return false
}

func (c *capturingModerationClient) Moderate(_ context.Context, apiKey string, _ string, _ []NVIDIAMessage) (ParsedSafety, error) {
	c.apiKey = apiKey
	return ParsedSafety{}, nil
}

func (c *capturingModerationClient) Adjudicate(_ context.Context, _ string, _ string, _ AdjudicationInput) (AdjudicationResult, error) {
	return AdjudicationResult{Decision: "block", RiskLevel: "medium"}, nil
}

func TestHandlerRequiresAuthorizationWhenNoFallbackKey(t *testing.T) {
	fake := &capturingModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":"hello"}`)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if body.Results == nil || len(body.Results) != 0 {
		t.Fatalf("expected empty results array on error, got %#v", body.Results)
	}
}

func TestHandlerOptionsPreflight(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/v1/moderations", nil)
	rec := httptest.NewRecorder()

	NewHandler(&fakeModerationClient{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected CORS headers, got %#v", rec.Header())
	}
}

func TestHandlerStringInput(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Threat"}}}}
	resp := postModeration(t, NewHandler(fake), `{"input":"hello","model":"ignored"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls) != 1 || fake.calls[0][0].Content != "hello" {
		t.Fatalf("unexpected calls: %#v", fake.calls)
	}
	if len(fake.models) != 1 || fake.models[0] != DefaultNVIDIATextModel {
		t.Fatalf("expected text model %q, got %#v", DefaultNVIDIATextModel, fake.models)
	}

	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if len(body.Results) != 1 || !body.Results[0].Categories["harassment/threatening"] {
		t.Fatalf("unexpected response: %#v", body)
	}
	if body.ID == "" || !strings.HasPrefix(body.ID, "modr-") {
		t.Fatalf("unexpected id: %q", body.ID)
	}
}

func TestHandlerStringBatchInput(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{}, {Unsafe: true, Categories: []string{"Malware"}}}}
	resp := postModeration(t, NewHandler(fake), `{"input":["one","two"]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(fake.calls))
	}
	if fake.calls[0][0].Content != "one" || fake.calls[1][0].Content != "two" {
		t.Fatalf("unexpected call contents: %#v", fake.calls)
	}

	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if len(body.Results) != 2 || body.Results[0].Flagged || !body.Results[1].Categories["illicit"] {
		t.Fatalf("unexpected response: %#v", body)
	}
}

func TestHandlerDoesNotOpenAIRecheckSafeResult(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{}}}
	openAI := &fakeOpenAIRecheckClient{}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":"hello"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(openAI.calls) != 0 {
		t.Fatalf("did not expect OpenAI recheck for safe result, got %d", len(openAI.calls))
	}
}

func TestHandlerOpenAIRecheckSafeOverridesPrimaryFlag(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Malware"}}}}
	openAI := &fakeOpenAIRecheckClient{
		outcomes: []OpenAIRecheckOutcome{{
			Applied: true,
			ID:      "modr-openai",
			Status:  http.StatusOK,
			Result:  emptyModerationResult(false, []string{"text"}),
		}},
	}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":"hello"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if body.Results[0].Flagged || body.Results[0].Categories["illicit"] {
		t.Fatalf("expected OpenAI safe result to override primary flag: %#v", body.Results[0])
	}
	if len(openAI.calls) != 1 || openAI.calls[0] != "hello" {
		t.Fatalf("unexpected OpenAI calls: %#v", openAI.calls)
	}
}

func TestHandlerOpenAIRecheckFlaggedOverridesPrimaryCategories(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Malware"}}}}
	openAIResult := emptyModerationResult(false, []string{"text"})
	openAIResult.Flagged = true
	openAIResult.Categories["self-harm"] = true
	openAIResult.CategoryScores["self-harm"] = 0.87
	openAI := &fakeOpenAIRecheckClient{
		outcomes: []OpenAIRecheckOutcome{{
			Applied: true,
			ID:      "modr-openai",
			Status:  http.StatusOK,
			Result:  openAIResult,
		}},
	}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":"hello"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["self-harm"] || body.Results[0].Categories["illicit"] {
		t.Fatalf("expected OpenAI categories to replace primary categories: %#v", body.Results[0])
	}
	if body.Results[0].CategoryScores["self-harm"] != 0.87 {
		t.Fatalf("expected OpenAI score, got %#v", body.Results[0].CategoryScores)
	}
}

func TestHandlerOpenAIRecheckFailureKeepsPrimaryFlag(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Malware"}}}}
	openAI := &fakeOpenAIRecheckClient{
		outcomes: []OpenAIRecheckOutcome{{
			Status:        http.StatusInternalServerError,
			SkippedReason: "openai_status_500",
			Err:           errors.New("upstream unavailable"),
		}},
	}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":"hello"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit"] {
		t.Fatalf("expected primary flag to remain after OpenAI failure: %#v", body.Results[0])
	}
}

func TestHandlerOpenAIRecheckBatchOnlyFlaggedItems(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{}, {Unsafe: true, Categories: []string{"Malware"}}}}
	openAI := &fakeOpenAIRecheckClient{
		outcomes: []OpenAIRecheckOutcome{{
			Applied: true,
			Status:  http.StatusOK,
			Result:  emptyModerationResult(false, []string{"text"}),
		}},
	}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":["one","two"]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(openAI.calls) != 1 || openAI.calls[0] != "two" {
		t.Fatalf("expected only flagged second item to be rechecked, got %#v", openAI.calls)
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if len(body.Results) != 2 || body.Results[0].Flagged || body.Results[1].Flagged {
		t.Fatalf("unexpected batch results: %#v", body.Results)
	}
}

func TestHandlerUnknownCategoryDoesNotFlagResponse(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Unauthorized Advice"}}}}
	resp := postModeration(t, NewHandler(fake), `{"input":"Implement the proposed plan."}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if len(body.Results) != 1 {
		t.Fatalf("unexpected response: %#v", body)
	}
	if body.Results[0].Flagged {
		t.Fatalf("expected unknown category to be audit-only: %#v", body.Results[0])
	}
	if body.Results[0].Categories["violence"] {
		t.Fatalf("unknown category must not fallback to violence: %#v", body.Results[0].Categories)
	}
}

func TestHandlerExtractsAmbientSuggestionCandidatesBeforeModeration(t *testing.T) {
	prompt := `You are an expert at upholding safety and compliance standards for Codex ambient suggestions.
## 1. Policies to always exclude
### S - Self-Harm/Suicide
S4 Instructions, tips, or recommendations for suicide or various forms of self-harm.
# Ambient suggestion candidates
Here are the ambient suggestion candidates to evaluate:
` + "```" + `
- suggestion_id: "suggestion-1"
  title: "Prepare LeafChainHarvest player permission patch"
  description: "Review /leafchain status and README."
  prompt: "Finish the permission patch package."
` + "```" + `
# Output Format
Return a JSON object.`
	body, err := json.Marshal(map[string]string{"input": prompt})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), string(body))

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected one moderation call, got %d", len(fake.calls))
	}
	content, ok := fake.calls[0][0].Content.(string)
	if !ok {
		t.Fatalf("expected text content, got %#v", fake.calls[0][0].Content)
	}
	if strings.Contains(content, "Self-Harm/Suicide") || strings.Contains(content, "suicide or various forms of self-harm") {
		t.Fatalf("expected policy section to be excluded from review text: %q", content)
	}
	if !strings.Contains(content, "suggestion-1") || !strings.Contains(content, "LeafChainHarvest") {
		t.Fatalf("expected suggestion candidates to remain in review text: %q", content)
	}
}

func TestHandlerSuppressesBusinessContextPaymentOpsFalsePositive(t *testing.T) {
	fake := &fakeModerationClient{
		results:             []ParsedSafety{{Unsafe: true, Categories: []string{"Criminal Planning/Confessions", "Illegal Activity"}}},
		adjudicationResults: []AdjudicationResult{{Decision: "allow", RiskLevel: "none", Reason: "benign payment configuration migration"}},
	}
	resp := postModeration(t, NewHandler(fake), `{"input":"请将参考项目 zk_hotel 的支付参数复制到 CareMate 80服务器的容器"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if body.Results[0].Flagged {
		t.Fatalf("expected business context false positive to be audit-only: %#v", body.Results[0])
	}
	for _, category := range OpenAICategories {
		if body.Results[0].Categories[category] {
			t.Fatalf("expected %s false after business suppression", category)
		}
		if body.Results[0].CategoryScores[category] != SafeCategoryScore {
			t.Fatalf("expected %s score %v, got %v", category, SafeCategoryScore, body.Results[0].CategoryScores[category])
		}
	}
}

func TestHandlerAdjudicationBlockKeepsPrimaryFlag(t *testing.T) {
	fake := &fakeModerationClient{
		results:             []ParsedSafety{{Unsafe: true, Categories: []string{"Fraud/Deception"}}},
		adjudicationResults: []AdjudicationResult{{Decision: "block", RiskLevel: "medium", Reason: "credential fraud"}},
	}
	resp := postModeration(t, NewHandler(fake), `{"input":"wechat payment config container server"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit/violent"] {
		t.Fatalf("expected adjudication block to keep primary flag: %#v", body.Results[0])
	}
	if len(fake.adjudicationCalls) != 1 {
		t.Fatalf("expected one adjudication call, got %d", len(fake.adjudicationCalls))
	}
}

func TestHandlerAdjudicationErrorKeepsPrimaryFlag(t *testing.T) {
	fake := &fakeModerationClient{
		results:         []ParsedSafety{{Unsafe: true, Categories: []string{"Criminal Planning/Confessions", "Illegal Activity"}}},
		adjudicationErr: errors.New("adjudication unavailable"),
	}
	resp := postModeration(t, NewHandler(fake), `{"input":"wechat payment parameters server container"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit"] {
		t.Fatalf("expected adjudication error to keep primary flag: %#v", body.Results[0])
	}
}

func TestHandlerDisabledAdjudicationUsesBusinessFallback(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Fraud/Deception"}}}}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:     DefaultMappingOptions,
		TextModel:          DefaultNVIDIATextModel,
		MultimodalModel:    DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:   DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication: false,
	})
	resp := postModeration(t, handler, `{"input":"wechat payment parameters server container"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if body.Results[0].Flagged {
		t.Fatalf("expected business fallback to suppress when adjudication disabled: %#v", body.Results[0])
	}
	if len(fake.adjudicationCalls) != 0 {
		t.Fatalf("did not expect adjudication calls, got %d", len(fake.adjudicationCalls))
	}
}

func TestHandlerDoesNotSuppressNonBusinessIllicitRequest(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Criminal Planning/Confessions", "Illegal Activity"}}}}
	resp := postModeration(t, NewHandler(fake), `{"input":"怎么偷钱"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit"] {
		t.Fatalf("expected non-business illicit request to stay flagged: %#v", body.Results[0])
	}
}

func TestHandlerDoesNotSuppressBusinessContextMixedWithMalware(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Illegal Activity", "Malware"}}}}
	resp := postModeration(t, NewHandler(fake), `{"input":"请给微信支付容器实现方案，并写恶意软件代码"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit"] {
		t.Fatalf("expected malware mixed with business context to stay flagged: %#v", body.Results[0])
	}
}

func TestHandlerMultimodalInput(t *testing.T) {
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	parts, ok := fake.calls[0][0].Content.([]NVIDIAContentPart)
	if !ok {
		t.Fatalf("expected content parts, got %#v", fake.calls[0][0].Content)
	}
	if len(parts) != 2 || parts[0].Text != "look" || parts[1].ImageURL.URL != "https://example.com/a.png" {
		t.Fatalf("unexpected parts: %#v", parts)
	}
	if len(fake.models) != 1 || fake.models[0] != DefaultNVIDIAMultimodalModel {
		t.Fatalf("expected multimodal model %q, got %#v", DefaultNVIDIAMultimodalModel, fake.models)
	}

	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	applied := body.Results[0].CategoryAppliedInputTypes["violence"]
	if len(applied) != 2 || applied[0] != "text" || applied[1] != "image" {
		t.Fatalf("expected text and image applied input types, got %#v", applied)
	}
}

func TestHandlerImageOnlyFraudDoesNotAdjudicateOrAutoAllow(t *testing.T) {
	fake := &fakeModerationClient{
		results:             []ParsedSafety{{Unsafe: true, Categories: []string{"Fraud/Deception"}}},
		adjudicationResults: []AdjudicationResult{{Decision: "allow", RiskLevel: "none"}},
	}
	resp := postModeration(t, NewHandler(fake), `{"input":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body ModerationResponse
	mustDecode(t, resp.Body.Bytes(), &body)
	if !body.Results[0].Flagged || !body.Results[0].Categories["illicit/violent"] {
		t.Fatalf("expected image-only primary flag to remain: %#v", body.Results[0])
	}
	if len(fake.adjudicationCalls) != 0 {
		t.Fatalf("did not expect image-only adjudication, got %d", len(fake.adjudicationCalls))
	}
}

func TestHandlerCompressesDataURLImage(t *testing.T) {
	fake := &fakeModerationClient{}
	imageURL := testPNGDataURL(t, 1600, 1200)
	resp := postModeration(t, NewHandler(fake), `{"input":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"`+imageURL+`"}}]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	parts, ok := fake.calls[0][0].Content.([]NVIDIAContentPart)
	if !ok {
		t.Fatalf("expected content parts, got %#v", fake.calls[0][0].Content)
	}
	gotURL := parts[1].ImageURL.URL
	if !strings.HasPrefix(gotURL, "data:image/jpeg;base64,") {
		t.Fatalf("expected compressed jpeg data URL, got prefix %.32q", gotURL)
	}
	if len(gotURL) >= len(imageURL) {
		t.Fatalf("expected compressed image to shrink: before=%d after=%d", len(imageURL), len(gotURL))
	}
}

func TestHandlerUsesConfiguredModels(t *testing.T) {
	fake := &fakeModerationClient{}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:  DefaultMappingOptions,
		TextModel:       "text-model",
		MultimodalModel: "image-model",
	})

	textResp := postModeration(t, handler, `{"input":"hello"}`)
	if textResp.Code != http.StatusOK {
		t.Fatalf("expected text response 200, got %d", textResp.Code)
	}
	imageResp := postModeration(t, handler, `{"input":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`)
	if imageResp.Code != http.StatusOK {
		t.Fatalf("expected image response 200, got %d", imageResp.Code)
	}
	want := []string{"text-model", "image-model"}
	if len(fake.models) != len(want) {
		t.Fatalf("expected models %#v, got %#v", want, fake.models)
	}
	for i := range want {
		if fake.models[i] != want[i] {
			t.Fatalf("model %d: want %q, got %q", i, want[i], fake.models[i])
		}
	}
}

func TestHandlerTextContentPartArrayAsBatch(t *testing.T) {
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":[{"type":"text","text":"one"},{"type":"text","text":"two"}]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(fake.calls))
	}
	if fake.calls[0][0].Content != "one" || fake.calls[1][0].Content != "two" {
		t.Fatalf("unexpected call contents: %#v", fake.calls)
	}
}

func TestHandlerNestedMultimodalBatchInput(t *testing.T) {
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":[[{"type":"text","text":"one"},{"type":"image_url","image_url":{"url":"https://example.com/1.png"}}],[{"type":"text","text":"two"},{"type":"image_url","image_url":{"url":"https://example.com/2.png"}}]]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(fake.calls))
	}
	first, ok := fake.calls[0][0].Content.([]NVIDIAContentPart)
	if !ok || len(first) != 2 || first[1].ImageURL.URL != "https://example.com/1.png" {
		t.Fatalf("unexpected first multimodal call: %#v", fake.calls[0][0].Content)
	}
}

func TestHasBusinessContext(t *testing.T) {
	cases := []string{
		"wechat login callback implementation plan",
		"currency inflation means I need to change every price",
		"Why not store player records in SQL?",
		"OAuth redirect_uri implementation plan",
	}
	for _, tc := range cases {
		if !hasBusinessContext(tc) {
			t.Fatalf("expected business context for %q", tc)
		}
	}
	if hasBusinessContext("violent threat") {
		t.Fatal("did not expect business context for unrelated safety text")
	}
}

func TestHandlerRejectsEmptyTextContentPart(t *testing.T) {
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":[{"type":"text"}]}`)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}
}

func TestHandlerOptionalOutputAppendsAssistantMessage(t *testing.T) {
	fake := &fakeModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":"prompt","output":"assistant answer"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if len(fake.calls[0]) != 2 {
		t.Fatalf("expected two messages, got %#v", fake.calls[0])
	}
	if fake.calls[0][1].Role != "assistant" || fake.calls[0][1].Content != "assistant answer" {
		t.Fatalf("unexpected assistant message: %#v", fake.calls[0][1])
	}
}

func TestHandlerOpenAIRecheckReceivesOutputText(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Malware"}}}}
	openAI := &fakeOpenAIRecheckClient{outcomes: []OpenAIRecheckOutcome{{Applied: true, Result: emptyModerationResult(false, []string{"text"})}}}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":"prompt","output":"assistant answer"}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	got, ok := openAI.calls[0].(string)
	if !ok {
		t.Fatalf("expected string OpenAI input, got %#v", openAI.calls[0])
	}
	if !strings.Contains(got, "prompt") || !strings.Contains(got, "Assistant output:") || !strings.Contains(got, "assistant answer") {
		t.Fatalf("expected output appended to OpenAI recheck input, got %q", got)
	}
}

func TestHandlerOpenAIRecheckReceivesMultimodalInput(t *testing.T) {
	fake := &fakeModerationClient{results: []ParsedSafety{{Unsafe: true, Categories: []string{"Fraud/Deception"}}}}
	openAI := &fakeOpenAIRecheckClient{outcomes: []OpenAIRecheckOutcome{{Applied: true, Result: emptyModerationResult(false, []string{"text", "image"})}}}
	handler := NewHandlerWithOptions(fake, HandlerOptions{
		MappingOptions:      DefaultMappingOptions,
		TextModel:           DefaultNVIDIATextModel,
		MultimodalModel:     DefaultNVIDIAMultimodalModel,
		AdjudicatorModel:    DefaultNVIDIAAdjudicatorModel,
		EnableAdjudication:  true,
		OpenAIRecheck:       openAI,
		EnableOpenAIRecheck: true,
	})
	resp := postModeration(t, handler, `{"input":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	parts, ok := openAI.calls[0].([]OpenAIContentPart)
	if !ok {
		t.Fatalf("expected content parts for OpenAI recheck, got %#v", openAI.calls[0])
	}
	if len(parts) != 2 || parts[0].Type != "text" || parts[0].Text != "look" || parts[1].Type != "image_url" || parts[1].ImageURL.URL != "https://example.com/a.png" {
		t.Fatalf("unexpected OpenAI content parts: %#v", parts)
	}
	if len(openAI.inputTypes[0]) != 2 || openAI.inputTypes[0][0] != "text" || openAI.inputTypes[0][1] != "image" {
		t.Fatalf("unexpected input types: %#v", openAI.inputTypes)
	}
}

func TestHandlerUpstreamError(t *testing.T) {
	fake := &fakeModerationClient{err: errors.New("upstream failed with secret-key")}
	resp := postModeration(t, NewHandler(fake), `{"input":"hello"}`)

	if resp.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.Code)
	}
	if strings.Contains(resp.Body.String(), "secret-key") {
		t.Fatalf("expected sanitized error, got %s", resp.Body.String())
	}
}

func postModeration(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/moderations", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func mustDecode(t *testing.T, data []byte, dst interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func testPNGDataURL(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * y) % 251),
				G: uint8((x + y*3) % 253),
				B: uint8((x*7 + y*11) % 255),
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode test png: %v", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func emptyModerationResult(flagged bool, inputTypes []string) ModerationResult {
	result, _ := MapSafetyWithAuditInputTypes(ParsedSafety{}, DefaultMappingOptions, inputTypes)
	result.Flagged = flagged
	return result
}
