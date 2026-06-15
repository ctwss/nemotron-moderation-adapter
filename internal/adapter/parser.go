package adapter

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

var fencedJSONPattern = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

func ParseSafetyOutput(content string) ParsedSafety {
	content = strings.TrimSpace(content)
	if content == "" {
		return ParsedSafety{}
	}

	if parsed, ok := parseSafetyJSON(content); ok {
		parsed.RawOutput = content
		return parsed
	}

	if match := fencedJSONPattern.FindStringSubmatch(content); len(match) == 2 {
		if parsed, ok := parseSafetyJSON(match[1]); ok {
			parsed.RawOutput = content
			return parsed
		}
	}

	if jsonObject := extractJSONObject(content); jsonObject != "" {
		if parsed, ok := parseSafetyJSON(jsonObject); ok {
			parsed.RawOutput = content
			return parsed
		}
	}

	parsed := parseSafetyText(content)
	parsed.RawOutput = content
	return parsed
}

func ParseAdjudicationOutput(content string) (AdjudicationResult, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return AdjudicationResult{}, errors.New("empty adjudication output")
	}

	if result, ok := parseAdjudicationJSON(content); ok {
		result.RawOutput = content
		return result, nil
	}
	if match := fencedJSONPattern.FindStringSubmatch(content); len(match) == 2 {
		if result, ok := parseAdjudicationJSON(match[1]); ok {
			result.RawOutput = content
			return result, nil
		}
	}
	if jsonObject := extractJSONObject(content); jsonObject != "" {
		if result, ok := parseAdjudicationJSON(jsonObject); ok {
			result.RawOutput = content
			return result, nil
		}
	}

	return AdjudicationResult{RawOutput: content}, errors.New("invalid adjudication JSON")
}

func parseAdjudicationJSON(content string) (AdjudicationResult, bool) {
	var result AdjudicationResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return AdjudicationResult{}, false
	}
	result.Decision = strings.ToLower(strings.TrimSpace(result.Decision))
	result.RiskLevel = strings.ToLower(strings.TrimSpace(result.RiskLevel))
	if result.Decision != "allow" && result.Decision != "block" {
		return AdjudicationResult{}, false
	}
	switch result.RiskLevel {
	case "", "none", "low", "medium", "high":
	default:
		return AdjudicationResult{}, false
	}
	return result, true
}

func parseSafetyJSON(content string) (ParsedSafety, bool) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return ParsedSafety{}, false
	}

	var result ParsedSafety
	for key, value := range raw {
		normalizedKey := normalizeKey(key)
		switch normalizedKey {
		case "user safety", "response safety":
			if strings.Contains(strings.ToLower(stringValue(value)), "unsafe") {
				result.Unsafe = true
			}
		case "safety categories":
			result.Categories = append(result.Categories, splitCategories(stringValue(value))...)
		}
	}
	return result, true
}

func parseSafetyText(content string) ParsedSafety {
	var result ParsedSafety
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "-*` "))
		if line == "" {
			continue
		}

		key, value, ok := splitKeyValue(line)
		if !ok {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "unsafe") {
				result.Unsafe = true
				result.ParseDegraded = true
			}
			continue
		}

		switch normalizeKey(key) {
		case "user safety", "response safety":
			if strings.Contains(strings.ToLower(value), "unsafe") {
				result.Unsafe = true
			}
		case "safety categories":
			result.Categories = append(result.Categories, splitCategories(value)...)
		default:
			if strings.Contains(strings.ToLower(value), "unsafe") {
				result.Unsafe = true
				result.ParseDegraded = true
			}
		}
	}
	return result
}

func splitKeyValue(line string) (string, string, bool) {
	if idx := strings.Index(line, ":"); idx >= 0 {
		return line[:idx], line[idx+1:], true
	}
	if idx := strings.Index(line, "="); idx >= 0 {
		return line[:idx], line[idx+1:], true
	}
	return "", "", false
}

func splitCategories(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") || strings.EqualFold(value, "n/a") {
		return nil
	}

	value = strings.NewReplacer("\r", ",", "\n", ",", ";", ",").Replace(value)
	var categories []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(strings.Trim(part, "[]\"'"))
		if part != "" {
			categories = append(categories, part)
		}
	}
	return categories
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(key, "\"'")))
}

func stringValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, stringValue(item))
		}
		return strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func extractJSONObject(content string) string {
	start := strings.Index(content, "{")
	if start < 0 {
		return ""
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		ch := content[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}

		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[start : i+1]
			}
		}
	}
	return ""
}
