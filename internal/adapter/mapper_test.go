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

func TestMapSafetyUnknownFallsBackToViolence(t *testing.T) {
	result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true, Categories: []string{"Unmapped Category"}})

	if !result.Categories["violence"] {
		t.Fatal("expected violence fallback")
	}
	if result.CategoryScores["violence"] != 0.99 {
		t.Fatalf("expected score 0.99, got %v", result.CategoryScores["violence"])
	}
	if len(audit.UnknownCategories) != 1 || audit.UnknownCategories[0] != "Unmapped Category" {
		t.Fatalf("unexpected unknown category audit: %#v", audit.UnknownCategories)
	}
	if len(audit.WeakMappings) != 1 || audit.WeakMappings[0].Confidence != MappingConfidenceFallback {
		t.Fatalf("expected fallback mapping audit, got %#v", audit.WeakMappings)
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
}

func TestMapSafetyWeakMappingAudit(t *testing.T) {
	result, audit := MapSafetyWithAudit(ParsedSafety{Unsafe: true, Categories: []string{"PII/Privacy", "Fraud/Deception"}})

	if !result.Categories["illicit"] || !result.Categories["illicit/violent"] {
		t.Fatalf("expected weak mapped categories: %#v", result.Categories)
	}
	if len(audit.WeakMappings) != 2 {
		t.Fatalf("expected two weak mappings, got %#v", audit.WeakMappings)
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
		if result.CategoryScores[category] != 0.01 {
			t.Fatalf("expected %s score 0.01, got %v", category, result.CategoryScores[category])
		}
		if len(result.CategoryAppliedInputTypes[category]) != 1 || result.CategoryAppliedInputTypes[category][0] != "text" {
			t.Fatalf("unexpected applied input types for %s: %#v", category, result.CategoryAppliedInputTypes[category])
		}
	}
}
