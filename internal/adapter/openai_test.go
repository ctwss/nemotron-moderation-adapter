package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOpenAIClientRecheckSendsModerationRequestAndCaches(t *testing.T) {
	var calls int
	var request openAIRequest
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		result := emptyModerationResult(false, []string{"text"})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(openAIResponse{
			ID:      "modr-openai",
			Model:   OpenAIModel,
			Results: []ModerationResult{result},
		})
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "openai-key", OpenAIModel, time.Second, time.Hour, 16)
	first := client.Recheck(context.Background(), "hello", []string{"text"})
	second := client.Recheck(context.Background(), "hello", []string{"text"})

	if !first.Applied || first.CacheHit || first.ID != "modr-openai" || first.Result.Flagged {
		t.Fatalf("unexpected first outcome: %#v", first)
	}
	if !second.Applied || !second.CacheHit || second.ID != "modr-openai" {
		t.Fatalf("unexpected cached outcome: %#v", second)
	}
	if calls != 1 {
		t.Fatalf("expected one upstream call due to cache, got %d", calls)
	}
	if authHeader != "Bearer openai-key" {
		t.Fatalf("unexpected auth header: %q", authHeader)
	}
	if request.Model != OpenAIModel || request.Input != "hello" {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestOpenAIClientCacheExpires(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(openAIResponse{
			ID:      "modr-openai",
			Model:   OpenAIModel,
			Results: []ModerationResult{emptyModerationResult(false, []string{"text"})},
		})
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "openai-key", OpenAIModel, time.Second, 10*time.Millisecond, 16)
	if got := client.Recheck(context.Background(), "hello", []string{"text"}); !got.Applied {
		t.Fatalf("first recheck not applied: %#v", got)
	}
	time.Sleep(20 * time.Millisecond)
	if got := client.Recheck(context.Background(), "hello", []string{"text"}); !got.Applied || got.CacheHit {
		t.Fatalf("expected cache miss after TTL expiry: %#v", got)
	}
	if calls != 2 {
		t.Fatalf("expected two upstream calls after expiry, got %d", calls)
	}
}

func TestOpenAIClientInvalidKeyDisablesFutureRechecks(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "invalid key", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "bad-key", OpenAIModel, time.Second, time.Hour, 16)
	first := client.Recheck(context.Background(), "hello", []string{"text"})
	second := client.Recheck(context.Background(), "hello", []string{"text"})

	if first.Applied || first.Status != http.StatusUnauthorized || first.SkippedReason != "invalid_openai_api_key" {
		t.Fatalf("unexpected first outcome: %#v", first)
	}
	if second.Applied || second.SkippedReason != "openai_api_key_disabled" {
		t.Fatalf("unexpected disabled outcome: %#v", second)
	}
	if calls != 1 {
		t.Fatalf("expected only one upstream call after invalid key, got %d", calls)
	}
}

func TestOpenAIClientMissingKeySkips(t *testing.T) {
	client := NewOpenAIClient("http://127.0.0.1:1", "", OpenAIModel, time.Second, time.Hour, 16)
	got := client.Recheck(context.Background(), "hello", []string{"text"})

	if got.Applied || got.SkippedReason != "missing_openai_api_key" {
		t.Fatalf("unexpected outcome: %#v", got)
	}
}

func TestOpenAIClientNon2xxFailsOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "openai-key", OpenAIModel, time.Second, time.Hour, 16)
	got := client.Recheck(context.Background(), "hello", []string{"text"})

	if got.Applied || got.Status != http.StatusTooManyRequests || got.SkippedReason != "openai_status_429" {
		t.Fatalf("unexpected outcome: %#v", got)
	}
}

func TestOpenAIClientNormalizesMissingAppliedInputTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := emptyModerationResult(false, []string{"text"})
		result.CategoryAppliedInputTypes = nil
		_ = json.NewEncoder(w).Encode(openAIResponse{
			ID:      "modr-openai",
			Model:   OpenAIModel,
			Results: []ModerationResult{result},
		})
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "openai-key", OpenAIModel, time.Second, time.Hour, 16)
	got := client.Recheck(context.Background(), []OpenAIContentPart{
		{Type: "text", Text: "look"},
		{Type: "image_url", ImageURL: &ImageURLPart{URL: "https://example.com/a.png"}},
	}, []string{"text", "image"})

	if !got.Applied {
		t.Fatalf("expected applied outcome: %#v", got)
	}
	applied := got.Result.CategoryAppliedInputTypes["violence"]
	if len(applied) != 2 || applied[0] != "text" || applied[1] != "image" {
		t.Fatalf("unexpected applied input types: %#v", got.Result.CategoryAppliedInputTypes)
	}
}
