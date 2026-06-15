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
	var openAIRecheck adapter.OpenAIRecheckClient
	if cfg.EnableOpenAIRecheck {
		openAIRecheck = adapter.NewOpenAIClient(cfg.OpenAIBaseURL, cfg.OpenAIAPIKey, cfg.OpenAIModel, cfg.Timeout, cfg.OpenAICacheTTL, cfg.OpenAICacheMaxEntries)
	}
	handler := adapter.NewHandlerWithOptions(client, adapter.HandlerOptions{
		MappingOptions: adapter.MappingOptions{
			FallbackUnsafeWithoutCategories: cfg.FallbackUnsafeWithoutCategories,
		},
		TextModel:           cfg.NVIDIAModel,
		MultimodalModel:     cfg.NVIDIAMultimodalModel,
		AdjudicatorModel:    cfg.NVIDIAAdjudicatorModel,
		EnableAdjudication:  cfg.EnableAdjudication,
		OpenAIRecheck:       openAIRecheck,
		EnableOpenAIRecheck: cfg.EnableOpenAIRecheck,
	})
	srv := appserver.New(":"+cfg.ListenPort, handler)

	log.Printf("listening on :%s", cfg.ListenPort)
	if err := srv.ListenAndServe(context.Background()); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	NVIDIAAPIKeys                   []string
	NVIDIABaseURL                   string
	NVIDIAModel                     string
	NVIDIAMultimodalModel           string
	NVIDIAAdjudicatorModel          string
	OpenAIAPIKey                    string
	OpenAIBaseURL                   string
	OpenAIModel                     string
	OpenAICacheTTL                  time.Duration
	OpenAICacheMaxEntries           int
	ListenPort                      string
	Timeout                         time.Duration
	FallbackUnsafeWithoutCategories bool
	EnableAdjudication              bool
	EnableOpenAIRecheck             bool
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
	model := strings.TrimSpace(os.Getenv("NVIDIA_MODEL"))
	if model == "" {
		model = adapter.DefaultNVIDIATextModel
	}
	multimodalModel := strings.TrimSpace(os.Getenv("NVIDIA_MULTIMODAL_MODEL"))
	if multimodalModel == "" {
		multimodalModel = adapter.DefaultNVIDIAMultimodalModel
	}
	adjudicatorModel := strings.TrimSpace(os.Getenv("NVIDIA_ADJUDICATOR_MODEL"))
	if adjudicatorModel == "" {
		adjudicatorModel = adapter.DefaultNVIDIAAdjudicatorModel
	}
	openAIAPIKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	openAIBaseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("OPENAI_BASE_URL")), "/")
	if openAIBaseURL == "" {
		openAIBaseURL = adapter.DefaultOpenAIBaseURL
	}
	openAIModel := strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
	if openAIModel == "" {
		openAIModel = adapter.OpenAIModel
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

	fallbackUnsafeWithoutCategories, err := parseBoolEnv("UNSAFE_NO_CATEGORY_FALLBACK", true)
	if err != nil {
		return config{}, err
	}
	enableAdjudication, err := parseBoolEnv("ENABLE_ADJUDICATION", true)
	if err != nil {
		return config{}, err
	}
	enableOpenAIRecheck, err := parseBoolEnv("ENABLE_OPENAI_RECHECK", true)
	if err != nil {
		return config{}, err
	}
	openAICacheTTLSec, err := parsePositiveIntEnv("OPENAI_CACHE_TTL_SEC", 3600)
	if err != nil {
		return config{}, err
	}
	openAICacheMaxEntries, err := parsePositiveIntEnv("OPENAI_CACHE_MAX_ENTRIES", 2048)
	if err != nil {
		return config{}, err
	}

	return config{
		NVIDIAAPIKeys:                   apiKeys,
		NVIDIABaseURL:                   baseURL,
		NVIDIAModel:                     model,
		NVIDIAMultimodalModel:           multimodalModel,
		NVIDIAAdjudicatorModel:          adjudicatorModel,
		OpenAIAPIKey:                    openAIAPIKey,
		OpenAIBaseURL:                   openAIBaseURL,
		OpenAIModel:                     openAIModel,
		OpenAICacheTTL:                  time.Duration(openAICacheTTLSec) * time.Second,
		OpenAICacheMaxEntries:           openAICacheMaxEntries,
		ListenPort:                      port,
		Timeout:                         time.Duration(timeoutSec) * time.Second,
		FallbackUnsafeWithoutCategories: fallbackUnsafeWithoutCategories,
		EnableAdjudication:              enableAdjudication,
		EnableOpenAIRecheck:             enableOpenAIRecheck,
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

func parseBoolEnv(name string, defaultValue bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func parsePositiveIntEnv(name string, defaultValue int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
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
