package adapter

import "strings"

const (
	MappingConfidenceStrong   = "strong"
	MappingConfidenceWeak     = "weak"
	MappingConfidenceFallback = "fallback"

	SafeCategoryScore = 0.0

	RiskLevelSafe                = "safe"
	RiskLevelStrong              = "strong"
	RiskLevelWeak                = "weak"
	RiskLevelFallback            = "fallback"
	RiskLevelUnknownSuppressed   = "unknown_suppressed"
	RiskLevelBusinessSuppressed  = "business_context_suppressed"
	RiskLevelAdjudicationAllowed = "adjudication_allowed"

	UnknownCategoryPolicyAuditOnly          = "audit_only"
	UnknownCategoryPolicyFallbackToViolence = "fallback_to_violence"
)

type categoryMapping struct {
	OpenAICategory string
	Score          float64
	Confidence     string
}

type MappingOptions struct {
	FallbackUnsafeWithoutCategories bool
}

var DefaultMappingOptions = MappingOptions{
	FallbackUnsafeWithoutCategories: true,
}

type MappingAudit struct {
	AegisCategory  string  `json:"aegis_category"`
	OpenAICategory string  `json:"openai_category"`
	Score          float64 `json:"score"`
	Confidence     string  `json:"mapping_confidence"`
}

type ModerationAudit struct {
	Mappings                  []MappingAudit `json:"mappings"`
	WeakMappings              []MappingAudit `json:"weak_mappings"`
	UnknownCategories         []string       `json:"unknown_categories"`
	FallbackCategory          bool           `json:"fallback_category"`
	RiskLevel                 string         `json:"risk_level"`
	BlockedBy                 []string       `json:"blocked_by"`
	BusinessContext           bool           `json:"business_context"`
	SuppressedBusinessContext bool           `json:"suppressed_business_context"`
	UnknownCategoryPolicy     string         `json:"unknown_category_policy"`
	SuppressedUnknownCategory bool           `json:"suppressed_unknown_category"`
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
	return MapSafetyWithAuditOptions(parsed, DefaultMappingOptions)
}

func MapSafetyWithAuditOptions(parsed ParsedSafety, options MappingOptions) (ModerationResult, ModerationAudit) {
	return MapSafetyWithAuditInputTypes(parsed, options, []string{"text"})
}

func MapSafetyWithAuditInputTypes(parsed ParsedSafety, options MappingOptions, inputTypes []string) (ModerationResult, ModerationAudit) {
	appliedInputTypes := normalizeInputTypes(inputTypes)
	categories := make(map[string]bool, len(OpenAICategories))
	scores := make(map[string]float64, len(OpenAICategories))
	applied := make(map[string][]string, len(OpenAICategories))
	for _, category := range OpenAICategories {
		categories[category] = false
		scores[category] = SafeCategoryScore
		applied[category] = append([]string(nil), appliedInputTypes...)
	}

	audit := ModerationAudit{RiskLevel: RiskLevelSafe}
	strongApplied := false
	weakApplied := false
	fallbackApplied := false
	if parsed.Unsafe {
		audit.RiskLevel = RiskLevelUnknownSuppressed
		audit.UnknownCategoryPolicy = UnknownCategoryPolicyAuditOnly
		for _, aegisCategory := range parsed.Categories {
			normalized := normalizeCategory(aegisCategory)
			mapping, ok := aegisMappings[normalized]
			if !ok {
				audit.UnknownCategories = append(audit.UnknownCategories, aegisCategory)
				audit.SuppressedUnknownCategory = true
				continue
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
			audit.BlockedBy = append(audit.BlockedBy, aegisCategory)
			audit.Mappings = append(audit.Mappings, mappingAudit)
			if mapping.Confidence == MappingConfidenceStrong {
				strongApplied = true
			} else {
				weakApplied = true
				audit.WeakMappings = append(audit.WeakMappings, mappingAudit)
			}
		}

		if len(parsed.Categories) == 0 && options.FallbackUnsafeWithoutCategories {
			categories["violence"] = true
			scores["violence"] = 0.99
			audit.FallbackCategory = true
			audit.UnknownCategoryPolicy = UnknownCategoryPolicyFallbackToViolence
			audit.BlockedBy = append(audit.BlockedBy, "unsafe_without_categories")
			audit.Mappings = append(audit.Mappings, MappingAudit{
				AegisCategory:  "",
				OpenAICategory: "violence",
				Score:          0.99,
				Confidence:     MappingConfidenceFallback,
			})
			fallbackApplied = true
		}
	}

	flagged := anyCategoryTrue(categories)
	switch {
	case strongApplied:
		audit.RiskLevel = RiskLevelStrong
	case weakApplied:
		audit.RiskLevel = RiskLevelWeak
	case fallbackApplied:
		audit.RiskLevel = RiskLevelFallback
	case parsed.Unsafe:
		audit.RiskLevel = RiskLevelUnknownSuppressed
	default:
		audit.RiskLevel = RiskLevelSafe
	}

	return ModerationResult{
		Flagged:                   flagged,
		Categories:                categories,
		CategoryScores:            scores,
		CategoryAppliedInputTypes: applied,
	}, audit
}

func normalizeInputTypes(inputTypes []string) []string {
	seen := map[string]bool{}
	var normalized []string
	for _, inputType := range inputTypes {
		switch strings.ToLower(strings.TrimSpace(inputType)) {
		case "text":
			if !seen["text"] {
				normalized = append(normalized, "text")
				seen["text"] = true
			}
		case "image", "image_url":
			if !seen["image"] {
				normalized = append(normalized, "image")
				seen["image"] = true
			}
		}
	}
	if len(normalized) == 0 {
		return []string{"text"}
	}
	return normalized
}

func normalizeCategory(category string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(category)), " "))
}

func anyCategoryTrue(categories map[string]bool) bool {
	for _, value := range categories {
		if value {
			return true
		}
	}
	return false
}
