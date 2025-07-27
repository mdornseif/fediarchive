package main

import (
	"reflect"
	"testing"
)

func TestExtractURLs(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "simple http url",
			content:  "Check out this link: http://example.com",
			expected: []string{"http://example.com"},
		},
		{
			name:     "simple https url",
			content:  "Visit https://secure.example.com for more info",
			expected: []string{"https://secure.example.com"},
		},
		{
			name:     "multiple urls",
			content:  "Link 1: http://example1.com and Link 2: https://example2.com",
			expected: []string{"http://example1.com", "https://example2.com"},
		},
		{
			name:     "url with trailing punctuation",
			content:  "Check this out: https://example.com!",
			expected: []string{"https://example.com"},
		},
		{
			name:     "url with query parameters",
			content:  "Search here: https://example.com/search?q=test&page=1",
			expected: []string{"https://example.com/search?q=test&page=1"},
		},
		{
			name:     "no urls",
			content:  "This is just plain text without any URLs.",
			expected: nil,
		},
		{
			name:     "url with port",
			content:  "Local server: http://localhost:8080/api",
			expected: []string{"http://localhost:8080/api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractURLs(tt.content)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractURLs() = %v, want %v", result, tt.expected)
			}
		})
	}
} 