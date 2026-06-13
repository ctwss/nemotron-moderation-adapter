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
		if _, err := client.Moderate(context.Background(), "", []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
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
	_, err := client.Moderate(context.Background(), "", []NVIDIAMessage{{Role: "user", Content: "hello"}})
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
	if _, err := client.Moderate(context.Background(), "request-key", []NVIDIAMessage{{Role: "user", Content: "hello"}}); err != nil {
		t.Fatalf("moderate: %v", err)
	}
	if authHeader != "Bearer request-key" {
		t.Fatalf("expected request key, got %q", authHeader)
	}
}
