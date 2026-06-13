package adapter

import "strings"

const (
	MappingConfidenceStrong   = "strong"
	MappingConfidenceWeak     = "weak"
	MappingConfidenceFallback = "fallback"
)

type categoryMapping struct {
	OpenAICategory string
	Score          float64
	Confidence     string
}

type MappingAudit struct {
	AegisCategory  string  `json:"aegis_category"`
	OpenAICategory string  `json:"openai_category"`
	Score          float64 `json:"score"`
	Confidence     string  `json:"mapping_confidence"`
}

type ModerationAudit struct {
	Mappings          []MappingAudit `json:"mappings"`
	WeakMappings      []MappingAudit `json:"weak_mappings"`
	UnknownCategories []string       `json:"unknown_categories"`
	FallbackCategory  bool           `json:"fallback_category"`
}

var aegisMappings = map[string]categoryMapping{
	"violence":                        {OpenAICategory: "violence", Score: 0.99, Confidence: MappingConfidenceStrong},
	"violence/graphic":                {OpenAICategory: "violence/graphic", Score: 0.99, Confidence: MappingConfidenceStrong},
	"sexual":                          {OpenAICategory: "sexual", Score: 0.99, Confidence: MappingConfidenceStrong},
	"sexual (minor)":                  {OpenAICategory: "sexual/minors", Score: 0.99, Confidence: MappingConfidenceStrong},
	"hate/identity hate":              {OpenAICategory: "hate", Score: 0.99, Confidence: MappingConfidenceStrong},
	"harassment":                      {OpenAICategory: "harassment", Score: 0.99, Confidence: MappingConfidenceStrong},
	"threat":                          {OpenAICategory: "harassment/threatening", Score: 0.99, Confidence: MappingConfidenceStrong},
	"suicide and self harm":           {OpenAICategory: "self-harm", Score: 0.99, Confidence: MappingConfidenceStrong},
	"controlled/regulated substances": {OpenAICategory: "illicit", Score: 0.99, Confidence: MappingConfidenceStrong},
	"criminal planning/confessions":   {OpenAICategory: "illicit", Score: 0.99, Confidence: MappingConfidenceStrong},
	"guns and illegal weapons":        {OpenAICategory: "violence", Score: 0.99, Confidence: MappingConfidenceStrong},
	"pii/privacy":                     {OpenAICategory: "illicit", Score: 0.99, Confidence: MappingConfidenceWeak},
	"fraud/deception":                 {OpenAICategory: "illicit/violent", Score: 0.99, Confidence: MappingConfidenceWeak},
	"profanity":                       {OpenAICategory: "harassment", Score: 0.99, Confidence: MappingConfidenceStrong},
	"manipulation":                    {OpenAICategory: "harassment", Score: 0.99, Confidence: MappingConfidenceWeak},
	"malware":                         {OpenAICategory: "illicit", Score: 0.99, Confidence: MappingConfidenceStrong},
	"illegal activity":                {OpenAICategory: "illicit", Score: 0.99, Confidence: MappingConfidenceStrong},
}

func MapSafety(parsed ParsedSafety) ModerationResult {
	result, _ := MapSafetyWithAudit(parsed)
	return result
}

func MapSafetyWithAudit(parsed ParsedSafety) (ModerationResult, ModerationAudit) {
	categories := make(map[string]bool, len(OpenAICategories))
	scores := make(map[string]float64, len(OpenAICategories))
	applied := make(map[string][]string, len(OpenAICategories))
	for _, category := range OpenAICategories {
		categories[category] = false
		scores[category] = 0.01
		applied[category] = []string{"text"}
	}

	var audit ModerationAudit
	if parsed.Unsafe {
		for _, aegisCategory := range parsed.Categories {
			normalized := normalizeCategory(aegisCategory)
			mapping, ok := aegisMappings[normalized]
			if !ok {
				mapping = categoryMapping{OpenAICategory: "violence", Score: 0.99, Confidence: MappingConfidenceFallback}
				audit.UnknownCategories = append(audit.UnknownCategories, aegisCategory)
			}

			categories[mapping.OpenAICategory] = true
			if scores[mapping.OpenAICategory] < mapping.Score {
				scores[mapping.OpenAICategory] = mapping.Score
			}

			mappingAudit := MappingAudit{
				AegisCategory:  aegisCategory,
				OpenAICategory: mapping.OpenAICategory,
				Score:          mapping.Score,
				Confidence:     mapping.Confidence,
			}
			audit.Mappings = append(audit.Mappings, mappingAudit)
			if mapping.Confidence != MappingConfidenceStrong {
				audit.WeakMappings = append(audit.WeakMappings, mappingAudit)
			}
		}

		if len(parsed.Categories) == 0 {
			categories["violence"] = true
			scores["violence"] = 0.99
			audit.FallbackCategory = true
			audit.Mappings = append(audit.Mappings, MappingAudit{
				AegisCategory:  "",
				OpenAICategory: "violence",
				Score:          0.99,
				Confidence:     MappingConfidenceFallback,
			})
		}
	}

	return ModerationResult{
		Flagged:                   parsed.Unsafe,
		Categories:                categories,
		CategoryScores:            scores,
		CategoryAppliedInputTypes: applied,
	}, audit
}

func normalizeCategory(category string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(category)), " "))
}
