package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNVIDIAClientRotatesAPIKeys(t *testing.T) {
	var authHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: "User Safety: safe\nSafety Categories: none"},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a", "key-b"}, time.Second)
	for i := 0; i < 3; i++ {
		if _, err := client.Moderate(context.Background(), "", DefaultNVIDIATextModel, []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
			t.Fatalf("moderate call %d: %v", i, err)
		}
	}

	want := []string{"Bearer key-a", "Bearer key-b", "Bearer key-a"}
	for i := range want {
		if authHeaders[i] != want[i] {
			t.Fatalf("header %d: want %q, got %q", i, want[i], authHeaders[i])
		}
	}
}

func TestNVIDIAClientSanitizesUpstreamErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret body", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	_, err := client.Moderate(context.Background(), "", DefaultNVIDIATextModel, []NVIDIAMessage{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "nvidia request failed: status=401" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNVIDIAClientUsesRequestAPIKeyBeforeFallback(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: "User Safety: safe\nSafety Categories: none"},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"fallback-key"}, time.Second)
	if _, err := client.Moderate(context.Background(), "request-key", DefaultNVIDIATextModel, []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if authHeader != "Bearer request-key" {
		t.Fatalf("expected request key, got %q", authHeader)
	}
}

func TestNVIDIAClientUsesDeterministicSamplingParameters(t *testing.T) {
	var request NVIDIARequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: "User Safety: safe\nSafety Categories: none"},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	if _, err := client.Moderate(context.Background(), "", "custom-text-model", []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if request.Model != "custom-text-model" {
		t.Fatalf("expected custom model, got %q", request.Model)
	}
	if request.Temperature != 0 {
		t.Fatalf("expected temperature 0, got %v", request.Temperature)
	}
	if request.TopP != 0.70 {
		t.Fatalf("expected top_p 0.70, got %v", request.TopP)
	}
}

func TestNVIDIAClientOmitsChatTemplateKwargsForTextSafetyGuard(t *testing.T) {
	var request NVIDIARequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: `{"User Safety":"safe","Safety Categories":[]}`},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	if _, err := client.Moderate(context.Background(), "", DefaultNVIDIATextModel, []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if request.Model != "nvidia/llama-3.1-nemotron-safety-guard-8b-v3" {
		t.Fatalf("unexpected text model: %q", request.Model)
	}
	if request.ChatTemplateKwargs != nil {
		t.Fatalf("expected no chat_template_kwargs for text model, got %#v", request.ChatTemplateKwargs)
	}
}

func TestNVIDIAClientSendsChatTemplateKwargsForMultimodalModel(t *testing.T) {
	var request NVIDIARequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: "User Safety: safe"},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	if _, err := client.Moderate(context.Background(), "", DefaultNVIDIAMultimodalModel, []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if request.ChatTemplateKwargs["request_categories"] != "/categories" {
		t.Fatalf("unexpected chat template kwargs: %#v", request.ChatTemplateKwargs)
	}
}

func TestNVIDIAClientParsesArrayMessageContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{
				"message": {
					"role": "assistant",
					"content": [{"type":"text","text":"User Safety: safe"}]
				}
			}]
		}`))
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	got, err := client.Moderate(context.Background(), "", DefaultNVIDIATextModel, []NVIDIAMessage{{Role: "user", Content: "hello"}})
	if err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if got.Unsafe {
		t.Fatalf("expected safe, got %#v", got)
	}
	if got.RawOutput != "User Safety: safe" {
		t.Fatalf("unexpected raw output: %q", got.RawOutput)
	}
}

func TestNVIDIAClientAdjudicateUsesConfiguredModelAndParsesJSON(t *testing.T) {
	var request NVIDIARequest
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: `{"decision":"allow","risk_level":"none","reason":"benign ops","categories":[]}`},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	got, err := client.Adjudicate(context.Background(), "", "adjudicator-model", AdjudicationInput{
		UserText:          "wechat payment parameters server container",
		HasImage:          true,
		PrimaryRawOutput:  "User Safety: unsafe\nSafety Categories: Fraud/Deception",
		PrimaryCategories: []string{"Fraud/Deception"},
		BusinessContext:   true,
	})
	if err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	if request.Model != "adjudicator-model" {
		t.Fatalf("expected adjudicator model, got %q", request.Model)
	}
	if request.Temperature != 0 || request.Stream {
		t.Fatalf("unexpected adjudication sampling settings: %#v", request)
	}
	if request.ChatTemplateKwargs != nil {
		t.Fatalf("expected no adjudication chat_template_kwargs, got %#v", request.ChatTemplateKwargs)
	}
	if authHeader != "Bearer key-a" {
		t.Fatalf("expected fallback auth header, got %q", authHeader)
	}
	if got.Decision != "allow" || got.RiskLevel != "none" || got.Reason != "benign ops" {
		t.Fatalf("unexpected adjudication result: %#v", got)
	}
}

func TestNVIDIAClientAdjudicateInvalidJSONReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NVIDIAResponse{
			Choices: []NVIDIAChoice{{
				Message: NVIDIAMessage{Role: "assistant", Content: "not json"},
			}},
		})
	}))
	defer server.Close()

	client := NewNVIDIAClient(server.URL, []string{"key-a"}, time.Second)
	if _, err := client.Adjudicate(context.Background(), "", DefaultNVIDIAAdjudicatorModel, AdjudicationInput{UserText: "hello"}); err == nil {
		t.Fatal("expected invalid adjudication JSON error")
	}
}
