package adapter

import "testing"

func TestMapSafetyAllSpecifiedMappings(t *testing.T) {
	cases := map[string]string{
		"Violence":                        "violence",
		"Violence/Graphic":                "violence/graphic",
		"Sexual":                          "sexual",
		"Sexual (minor)":                  "sexual/minors",
		"Hate/Identity Hate":              "hate",
		"Harassment":                      "harassment",
		"Threat":                          "harassment/threatening",
		"Suicide and Self Harm":           "self-harm",
		"Controlled/Regulated Substances": "illicit",
		"Criminal Planning/Confessions":   "illicit",
		"Guns and Illegal Weapons":        "violence",
		"PII/Privacy":                     "illicit",
		"Fraud/Deception":                 "illicit/violent",
		"Profanity":                       "harassment",
		"Manipulation":                    "harassment",
		"Malware":                         "illicit",
		"Illegal Activity":                "illicit",
	}

	for aegis, openai := range cases {
		result := MapSafety(ParsedSafety{Unsafe: true, Categories: []string{aegis}})
		if !result.Flagged {
			t.Fatalf("%s: expected flagged", aegis)
		}
		if !result.Categories[openai] {
			t.Fatalf("%s: expected %s to be true", aegis, openai)
		}
		if result.CategoryScores[openai] != 0.99 {
			t.Fatalf("%s: expected score 0.99, got %v", aegis, result.CategoryScores[openai])
		}
	}
}

func TestMapSafetyDuplicateTargetsKeepHighest(t *testing.T) {
	result := MapSafety(ParsedSafety{Unsafe: true, Categories: []string{"Harassment", "Profanity", "Manipulation"}})

	if !result.Categories["harassment"] {
		t.Fatal("expected harassment to be true")
	}
	if result.CategoryScores["harassment"] != 0.99 {
		t.Fatalf("expected score 0.99, got %v", result.CategoryScores["harassment"])
	}
}

func TestMapSafetyKnownAndUnknownCategoriesOnlyKnownCategoryBlocks(t *testing.T) {
	result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true, Categories: []string{"Needs Caution", "Malware"}})

	if !result.Flagged || !result.Categories["illicit"] {
		t.Fatalf("expected malware to flag illicit: %#v", result)
	}
	if result.Categories["violence"] {
		t.Fatalf("unknown category must not fallback to violence: %#v", result.Categories)
	}
	if len(audit.UnknownCategories) != 1 || audit.UnknownCategories[0] != "Needs Caution" {
		t.Fatalf("unexpected unknown category audit: %#v", audit)
	}
	if audit.RiskLevel != RiskLevelStrong {
		t.Fatalf("expected strong risk level: %#v", audit)
	}
}

func TestMapSafetyUnknownCategoriesAreAuditOnly(t *testing.T) {
	cases := []string{"Unmapped Category", "Unauthorized Advice", "Needs Caution"}

	for _, aegis := range cases {
		result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true, Categories: []string{aegis}})

		if result.Flagged {
			t.Fatalf("%s: expected audit-only result, got flagged", aegis)
		}
		for _, category := range OpenAICategories {
			if result.Categories[category] {
				t.Fatalf("%s: expected %s false", aegis, category)
			}
			if result.CategoryScores[category] != SafeCategoryScore {
				t.Fatalf("%s: expected %s score SafeCategoryScore, got %v", aegis, category, result.CategoryScores[category])
			}
		}
		if len(audit.UnknownCategories) != 1 || audit.UnknownCategories[0] != aegis {
			t.Fatalf("%s: unexpected unknown category audit: %#v", aegis, audit.UnknownCategories)
		}
		if !audit.SuppressedUnknownCategory {
			t.Fatalf("%s: expected suppressed unknown category audit: %#v", aegis, audit)
		}
		if audit.UnknownCategoryPolicy != UnknownCategoryPolicyAuditOnly {
			t.Fatalf("%s: expected audit-only policy, got %#v", aegis, audit)
		}
		if audit.RiskLevel != RiskLevelUnknownSuppressed {
			t.Fatalf("%s: expected unknown suppressed risk, got %#v", aegis, audit)
		}
	}
}

func TestMapSafetyUnsafeWithoutCategoriesFallsBackToViolence(t *testing.T) {
	result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true})

	if !result.Flagged || !result.Categories["violence"] {
		t.Fatalf("expected violence fallback result: %#v", result)
	}
	if result.CategoryScores["violence"] != 0.99 {
		t.Fatalf("expected score 0.99, got %v", result.CategoryScores["violence"])
	}
	if !audit.FallbackCategory {
		t.Fatalf("expected fallback audit: %#v", audit)
	}
	if audit.UnknownCategoryPolicy != UnknownCategoryPolicyFallbackToViolence {
		t.Fatalf("expected fallback policy: %#v", audit)
	}
	if audit.RiskLevel != RiskLevelFallback {
		t.Fatalf("expected fallback risk level: %#v", audit)
	}
}

func TestMapSafetyUnsafeWithoutCategoriesFallbackCanBeDisabled(t *testing.T) {
	result, audit := MapSafetyWithAuditOptions(ParsedSafety{Unsafe: true}, MappingOptions{})

	if result.Flagged {
		t.Fatalf("expected unflagged result when fallback is disabled: %#v", result)
	}
	for _, category := range OpenAICategories {
		if result.Categories[category] {
			t.Fatalf("expected %s false", category)
		}
	}
	if audit.FallbackCategory {
		t.Fatalf("did not expect fallback audit: %#v", audit)
	}
	if audit.RiskLevel != RiskLevelUnknownSuppressed {
		t.Fatalf("expected unknown suppressed risk level: %#v", audit)
	}
}

func TestMapSafetyWeakMappingAudit(t *testing.T) {
	result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true, Categories: []string{"PII/Privacy", "Fraud/Deception"}})

	if !result.Categories["illicit"] || !result.Categories["illicit/violent"] {
		t.Fatalf("expected weak mapped categories: %#v", result.Categories)
	}
	if len(audit.WeakMappings) != 2 {
		t.Fatalf("expected two weak mappings, got %#v", audit.WeakMappings)
	}
	if audit.RiskLevel != RiskLevelWeak {
		t.Fatalf("expected weak risk level, got %#v", audit)
	}
	for _, mapping := range audit.WeakMappings {
		if mapping.Confidence != MappingConfidenceWeak {
			t.Fatalf("expected weak confidence, got %#v", mapping)
		}
	}
}

func TestMapSafetySafeDefaults(t *testing.T) {
	result := MapSafety(ParsedSafety{})

	if result.Flagged {
		t.Fatal("expected not flagged")
	}
	for _, category := range OpenAICategories {
		if result.Categories[category] {
			t.Fatalf("expected %s false", category)
		}
		if result.CategoryScores[category] != SafeCategoryScore {
			t.Fatalf("expected %s score SafeCategoryScore, got %v", category, result.CategoryScores[category])
		}
		if len(result.CategoryAppliedInputTypes[category]) != 1 || result.CategoryAppliedInputTypes[category][0] != "text" {
			t.Fatalf("unexpected applied input types for %s: %#v", category, result.CategoryAppliedInputTypes[category])
		}
	}
}
