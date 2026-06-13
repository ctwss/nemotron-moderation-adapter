package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nemotron-moderation-adapter/internal/adapter"
	appserver "nemotron-moderation-adapter/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	client := adapter.NewNVIDIAClient(cfg.NVIDIABaseURL, cfg.NVIDIAAPIKeys, cfg.Timeout)
	handler := adapter.NewHandler(client)
	srv := appserver.New(":"+cfg.ListenPort, handler)

	log.Printf("listening on :%s", cfg.ListenPort)
	if err := srv.ListenAndServe(context.Background()); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	NVIDIAAPIKeys []string
	NVIDIABaseURL string
	ListenPort    string
	Timeout       time.Duration
}

func loadConfig() (config, error) {
	apiKeys := parseAPIKeys(os.Getenv("NVIDIA_API_KEYS"))
	if len(apiKeys) == 0 {
		apiKeys = parseAPIKeys(os.Getenv("NVIDIA_API_KEY"))
	}
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("NVIDIA_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "https://integrate.api.nvidia.com"
	}

	port := strings.TrimSpace(os.Getenv("LISTEN_PORT"))
	if port == "" {
		port = "8080"
	}

	timeoutSec := 30
	if raw := strings.TrimSpace(os.Getenv("TIMEOUT_SEC")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return config{}, fmt.Errorf("TIMEOUT_SEC must be a positive integer")
		}
		timeoutSec = parsed
	}

	return config{
		NVIDIAAPIKeys: apiKeys,
		NVIDIABaseURL: baseURL,
		ListenPort:    port,
		Timeout:       time.Duration(timeoutSec) * time.Second,
	}, nil
}

func parseAPIKeys(raw string) []string {
	var keys []string
	for _, part := range strings.Split(raw, ",") {
		key := strings.TrimSpace(part)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func runHealthcheck() error {
	port := strings.TrimSpace(os.Getenv("LISTEN_PORT"))
	if port == "" {
		port = "8080"
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned %s", resp.Status)
	}
	return nil
}
