package adapter

import "encoding/json"

const (
	NVIDIAModel = "nvidia/nemotron-3.5-content-safety"
	OpenAIModel = "omni-moderation-latest"
)

var OpenAICategories = []string{
	"harassment",
	"harassment/threatening",
	"hate",
	"hate/threatening",
	"illicit",
	"illicit/violent",
	"self-harm",
	"self-harm/intent",
	"self-harm/instructions",
	"sexual",
	"sexual/minors",
	"violence",
	"violence/graphic",
}

type ModerationRequest struct {
	Input  json.RawMessage `json:"input"`
	Model  string          `json:"model,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
}

type OpenAIContentPart struct {
	Type     string        `json:"type"`
	Text     string        `json:"text,omitempty"`
	ImageURL *ImageURLPart `json:"image_url,omitempty"`
}

type ImageURLPart struct {
	URL string `json:"url"`
}

type ModerationResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []ModerationResult `json:"results"`
}

type ModerationResult struct {
	Flagged                   bool                `json:"flagged"`
	Categories                map[string]bool     `json:"categories"`
	CategoryScores            map[string]float64  `json:"category_scores"`
	CategoryAppliedInputTypes map[string][]string `json:"category_applied_input_types"`
}

type NVIDIARequest struct {
	Model              string                 `json:"model"`
	Messages           []NVIDIAMessage        `json:"messages"`
	MaxTokens          int                    `json:"max_tokens"`
	Temperature        float64                `json:"temperature"`
	TopP               float64                `json:"top_p"`
	Stream             bool                   `json:"stream"`
	ChatTemplateKwargs map[string]interface{} `json:"chat_template_kwargs"`
}

type NVIDIAMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type NVIDIAContentPart struct {
	Type     string              `json:"type"`
	Text     string              `json:"text,omitempty"`
	ImageURL *NVIDIAImageURLPart `json:"image_url,omitempty"`
}

type NVIDIAImageURLPart struct {
	URL string `json:"url"`
}

type NVIDIAResponse struct {
	Choices []NVIDIAChoice `json:"choices"`
}

type NVIDIAChoice struct {
	Message NVIDIAMessage `json:"message"`
}

type ParsedSafety struct {
	Unsafe        bool
	Categories    []string
	RawOutput     string
	ParseDegraded bool
}
