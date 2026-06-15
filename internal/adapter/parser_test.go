package adapter

import "testing"

func TestParseSafetyOutputPlainTextUnsafe(t *testing.T) {
	raw := "User Safety: unsafe\nSafety Categories: Criminal Planning/Confessions"
	got := ParseSafetyOutput(raw)

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if len(got.Categories) != 1 || got.Categories[0] != "Criminal Planning/Confessions" {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
	if got.RawOutput != raw {
		t.Fatalf("unexpected raw output: %q", got.RawOutput)
	}
}

func TestParseSafetyOutputJSON(t *testing.T) {
	got := ParseSafetyOutput(`{"User Safety":"unsafe","Safety Categories":"Violence/Graphic"}`)

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if len(got.Categories) != 1 || got.Categories[0] != "Violence/Graphic" {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
}

func TestParseSafetyOutputMarkdownJSON(t *testing.T) {
	got := ParseSafetyOutput("```json\n{\"Response Safety\":\"unsafe\",\"Safety Categories\":[\"Threat\",\"Profanity\"]}\n```")

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if len(got.Categories) != 2 {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
}

func TestParseSafetyOutputEmbeddedJSON(t *testing.T) {
	got := ParseSafetyOutput("Result:\n{\"User Safety\":\"unsafe\",\"Safety Categories\":\"Malware\"}\nDone.")

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if len(got.Categories) != 1 || got.Categories[0] != "Malware" {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
}

func TestParseSafetyOutputMultilineMixed(t *testing.T) {
	got := ParseSafetyOutput("- User Safety = unsafe\n* Safety Categories: Malware; Fraud/Deception")

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if len(got.Categories) != 2 {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
}

func TestParseSafetyOutputSafeEmptyCategories(t *testing.T) {
	got := ParseSafetyOutput("User Safety: safe\nSafety Categories: none")

	if got.Unsafe {
		t.Fatal("expected safe")
	}
	if len(got.Categories) != 0 {
		t.Fatalf("unexpected categories: %#v", got.Categories)
	}
}

func TestParseSafetyOutputDegradedUnsafe(t *testing.T) {
	got := ParseSafetyOutput("The model says this is unsafe, but did not use expected keys.")

	if !got.Unsafe {
		t.Fatal("expected unsafe")
	}
	if !got.ParseDegraded {
		t.Fatal("expected degraded parse")
	}
}

func TestParseAdjudicationOutputMarkdownJSON(t *testing.T) {
	got, err := ParseAdjudicationOutput("```json\n{\"decision\":\"allow\",\"risk_level\":\"none\",\"reason\":\"benign\",\"categories\":[]}\n```")
	if err != nil {
		t.Fatalf("parse adjudication: %v", err)
	}
	if got.Decision != "allow" || got.RiskLevel != "none" || got.Reason != "benign" {
		t.Fatalf("unexpected adjudication result: %#v", got)
	}
}

func TestParseAdjudicationOutputRejectsInvalidDecision(t *testing.T) {
	if _, err := ParseAdjudicationOutput(`{"decision":"maybe","risk_level":"low","reason":"no","categories":[]}`); err == nil {
		t.Fatal("expected invalid decision error")
	}
}
