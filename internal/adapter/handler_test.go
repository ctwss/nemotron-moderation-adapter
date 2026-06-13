package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeModerationClient struct {
	results []ParsedSafety
	err     error
	calls   [][]NVIDIAMessage
}

func (f *fakeModerationClient) HasFallbackAPIKey() bool {
	return true
}

func (f *fakeModerationClient) Moderate(_ context.Context, apiKey string, messages []NVIDIAMessage) (ParsedSafety, error) {
	f.calls = append(f.calls, messages)
	if f.err != nil {
		return ParsedSafety{}, f.err
	}
	if len(f.results) >= len(f.calls) {
		return f.results[len(f.calls)-1], nil
	}
	return ParsedSafety{}, nil
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

func (c *capturingModerationClient) Moderate(_ context.Context, apiKey string, _ []NVIDIAMessage) (ParsedSafety, error) {
	c.apiKey = apiKey
	return ParsedSafety{}, nil
}

func TestHandlerRequiresAuthorizationWhenNoFallbackKey(t *testing.T) {
	fake := &capturingModerationClient{}
	resp := postModeration(t, NewHandler(fake), `{"input":"hello"}`)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", resp.Code, resp.Body.String())
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
