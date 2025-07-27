package main

import (
	"reflect"
	"testing"
)

func TestExtractURLs(t *testing.T) {
	// Create a test fediverseHostnames map
	fediverseHostnames := make(map[string]bool)
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "simple_http_url",
			content:  "Check out this link: http://example.com",
			expected: []string{"http://example.com"},
		},
		{
			name:     "simple_https_url",
			content:  "Visit https://example.com for more info",
			expected: []string{"https://example.com"},
		},
		{
			name:     "multiple_urls",
			content:  "Links: http://example1.com and https://example2.com",
			expected: []string{"http://example1.com", "https://example2.com"},
		},
		{
			name:     "url_with_trailing_punctuation",
			content:  "Visit https://example.com!",
			expected: []string{"https://example.com"},
		},
		{
			name:     "url_with_query_parameters",
			content:  "Search: https://example.com/search?q=test",
			expected: []string{"https://example.com/search?q=test"},
		},
		{
			name:     "no_urls",
			content:  "This is just text without any URLs.",
			expected: []string{},
		},
		{
			name:     "url_with_port",
			content:  "Server: http://example.com:8080",
			expected: []string{"http://example.com:8080"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractURLs(tt.content, "", fediverseHostnames)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractURLs() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsInternalFediverseLink(t *testing.T) {
	// Create a test fediverseHostnames map with known Fediverse domains
	fediverseHostnames := make(map[string]bool)
	fediverseHostnames["natur.23.nu"] = true
	fediverseHostnames["social.23.nu"] = true
	fediverseHostnames["mastodon.social"] = true
	fediverseHostnames["pleroma.social"] = true
	fediverseHostnames["lemmy.world"] = true
	fediverseHostnames["social.cologne"] = true
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "mastodon_user_profile",
			url:      "https://mastodon.social/@username",
			expected: true,
		},
		{
			name:     "social_23_nu_user_profile",
			url:      "https://social.23.nu/@wetterbot",
			expected: true,
		},
		{
			name:     "natur_23_nu_user_profile",
			url:      "https://natur.23.nu/u/wetterbot",
			expected: true,
		},
		{
			name:     "mastodon_hashtag",
			url:      "https://mastodon.social/tags/example",
			expected: true,
		},
		{
			name:     "external_website",
			url:      "https://example.com/article",
			expected: false,
		},
		{
			name:     "news_website",
			url:      "https://news.bbc.com/story",
			expected: false,
		},
		{
			name:     "github_repository",
			url:      "https://github.com/user/repo",
			expected: false,
		},
		{
			name:     "lemmy_community",
			url:      "https://lemmy.world/c/community",
			expected: true,
		},
		{
			name:     "pleroma_user",
			url:      "https://pleroma.social/users/username",
			expected: true,
		},
		{
			name:     "same_instance_hostname",
			url:      "https://social.cologne/tags/Obstanbau",
			expected: true,
		},
		{
			name:     "social_cologne_tags_anpacken",
			url:      "https://social.cologne/tags/Anpacken",
			expected: true,
		},
		{
			name:     "social_cologne_tags_obstanbau",
			url:      "https://social.cologne/tags/Obstanbau",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the same_instance_hostname test, use the actual hostname
			instanceHostname := ""
			if tt.name == "same_instance_hostname" {
				instanceHostname = "social.cologne"
			}
			result := isInternalFediverseLink(tt.url, instanceHostname, fediverseHostnames)
			if result != tt.expected {
				t.Errorf("isInternalFediverseLink(%s) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
} 