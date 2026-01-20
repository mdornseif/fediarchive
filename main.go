package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/mmcdole/gofeed"
	"gopkg.in/yaml.v3"
)

// Config holds application configuration
type Config struct {
	Fediverse struct {
		InstanceURL string `json:"instance_url" yaml:"instance_url"`
		Username    string `json:"username" yaml:"username"`
		Password    string `json:"password" yaml:"password"`
		Token       string `json:"token" yaml:"token"`
		TokenExp    string `json:"token_exp" yaml:"token_exp"`
	} `json:"fediverse" yaml:"fediverse"`
	S3 struct {
		Endpoint  string `json:"endpoint" yaml:"endpoint"`
		AccessKey string `json:"access_key" yaml:"access_key"`
		SecretKey string `json:"secret_key" yaml:"secret_key"`
		Bucket    string `json:"bucket" yaml:"bucket"`
		UseSSL    bool   `json:"use_ssl" yaml:"use_ssl"`
	} `json:"s3" yaml:"s3"`
	Settings struct {
		MaxPostsPerUser    int      `json:"max_posts_per_user" yaml:"max_posts_per_user"`
		IncludeVisibility  []string `json:"include_visibility" yaml:"include_visibility"`
		BlacklistedDomains []string `json:"blacklisted_domains" yaml:"blacklisted_domains"`
		RSSFeeds           []string `json:"rss_feeds" yaml:"rss_feeds"`
	} `json:"settings" yaml:"settings"`
}

// GoToSocial API types
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	CreatedAt   int64  `json:"created_at"`
}

type Account struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Acct           string `json:"acct"`
	DisplayName    string `json:"display_name"`
	Locked         bool   `json:"locked"`
	Bot            bool   `json:"bot"`
	Group          bool   `json:"group"`
	CreatedAt      string `json:"created_at"`
	Note           string `json:"note"`
	URL            string `json:"url"`
	Avatar         string `json:"avatar"`
	Header         string `json:"header"`
	FollowersCount int    `json:"followers_count"`
	FollowingCount int    `json:"following_count"`
	StatusesCount  int    `json:"statuses_count"`
	Following      bool   `json:"following"`
	FollowedBy     bool   `json:"followed_by"`
	Requested      bool   `json:"requested"`
	Muting         bool   `json:"muting"`
	Blocking       bool   `json:"blocking"`
}

type Relationship struct {
	ID         string `json:"id"`
	Following  bool   `json:"following"`
	FollowedBy bool   `json:"followed_by"`
	Requested  bool   `json:"requested"`
	Muting     bool   `json:"muting"`
	Blocking   bool   `json:"blocking"`
}

type Status struct {
	ID                 string      `json:"id"`
	CreatedAt          string      `json:"created_at"`
	InReplyToID        *string     `json:"in_reply_to_id"`
	InReplyToAccountID *string     `json:"in_reply_to_account_id"`
	Sensitive          bool        `json:"sensitive"`
	SpoilerText        string      `json:"spoiler_text"`
	Visibility         string      `json:"visibility"`
	Language           string      `json:"language"`
	URI                string      `json:"uri"`
	URL                string      `json:"url"`
	RepliesCount       int         `json:"replies_count"`
	ReblogsCount       int         `json:"reblogs_count"`
	FavouritesCount    int         `json:"favourites_count"`
	Content            string      `json:"content"`
	Account            Account     `json:"account"`
	Reblogged          interface{} `json:"reblogged"` // Can be bool or Status object
	Application        *struct {
		Name    string `json:"name"`
		Website string `json:"website"`
	} `json:"application"`
	MediaAttachments []struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		URL        string `json:"url"`
		RemoteURL  string `json:"remote_url"`
		PreviewURL string `json:"preview_url"`
		TextURL    string `json:"text_url"`
		Meta       struct {
			Original struct {
				Width  int     `json:"width"`
				Height int     `json:"height"`
				Size   string  `json:"size"`
				Aspect float64 `json:"aspect"`
			} `json:"original"`
		} `json:"meta"`
		Description string `json:"description"`
		Blurhash    string `json:"blurhash"`
	} `json:"media_attachments"`
	Mentions []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Acct     string `json:"acct"`
		URL      string `json:"url"`
	} `json:"mentions"`
	Tags []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"tags"`
	Emojis []struct {
		Shortcode       string `json:"shortcode"`
		URL             string `json:"url"`
		StaticURL       string `json:"static_url"`
		VisibleInPicker bool   `json:"visible_in_picker"`
	} `json:"emojis"`
	Card *struct {
		URL          string `json:"url"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		Type         string `json:"type"`
		AuthorName   string `json:"author_name"`
		AuthorURL    string `json:"author_url"`
		ProviderName string `json:"provider_name"`
		ProviderURL  string `json:"provider_url"`
		HTML         string `json:"html"`
		Width        int    `json:"width"`
		Height       int    `json:"height"`
		Image        string `json:"image"`
		EmbedURL     string `json:"embed_url"`
		Blurhash     string `json:"blurhash"`
	} `json:"card"`
	Poll *struct {
		ID          string `json:"id"`
		ExpiresAt   string `json:"expires_at"`
		Expired     bool   `json:"expired"`
		Multiple    bool   `json:"multiple"`
		VotesCount  int    `json:"votes_count"`
		VotersCount int    `json:"voters_count"`
		Voted       bool   `json:"voted"`
		OwnVotes    []int  `json:"own_votes"`
		Options     []struct {
			Title      string `json:"title"`
			VotesCount int    `json:"votes_count"`
		} `json:"options"`
		Emojis []struct {
			Shortcode       string `json:"shortcode"`
			URL             string `json:"url"`
			StaticURL       string `json:"static_url"`
			VisibleInPicker bool   `json:"visible_in_picker"`
		} `json:"emojis"`
	} `json:"poll"`
}

type FediverseClient struct {
	config      *Config
	httpClient  *http.Client
	accessToken string
}

func NewFediverseClient(config *Config) *FediverseClient {
	return &FediverseClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *FediverseClient) authenticate() error {
	// Check if we have a valid token
	if c.config.Fediverse.Token != "" {
		// Try to use existing token
		c.accessToken = c.config.Fediverse.Token
		if err := c.verifyToken(); err == nil {
			log.Println("Using existing token for authentication")
			return nil
		}
		log.Println("Existing token is invalid, getting new token")
	}

	// Get new token using username/password
	return c.getNewToken()
}

func (c *FediverseClient) verifyToken() error {
	req, err := http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/accounts/verify_credentials", nil)
	if err != nil {
		return fmt.Errorf("failed to create verify credentials request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to verify credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token verification failed with status %d", resp.StatusCode)
	}

	return nil
}

func (c *FediverseClient) getNewToken() error {
	// Step 1: Create application
	appData := map[string]string{
		"client_name":   "ArchiveMastodon",
		"redirect_uris": "urn:ietf:wg:oauth:2.0:oob",
		"scopes":        "read write follow",
		"website":       "",
	}

	appJSON, _ := json.Marshal(appData)
	req, err := http.NewRequest("POST", c.config.Fediverse.InstanceURL+"/api/v1/apps", bytes.NewBuffer(appJSON))
	if err != nil {
		return fmt.Errorf("failed to create app request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}
	defer resp.Body.Close()

	var appResponse struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&appResponse); err != nil {
		return fmt.Errorf("failed to decode app response: %w", err)
	}

	// Step 2: Get authorization code
	authURL := fmt.Sprintf("%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=read%%20write%%20follow",
		c.config.Fediverse.InstanceURL, appResponse.ClientID)

	log.Printf("Please visit this URL to authorize the application: %s", authURL)
	log.Print("Enter the authorization code: ")

	var authCode string
	fmt.Scanln(&authCode)

	// Step 3: Exchange code for access token
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", appResponse.ClientID)
	tokenData.Set("client_secret", appResponse.ClientSecret)
	tokenData.Set("code", authCode)
	tokenData.Set("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")

	req, err = http.NewRequest("POST", c.config.Fediverse.InstanceURL+"/oauth/token", strings.NewReader(tokenData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResponse AccessToken
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResponse.AccessToken

	// Save token to config
	c.config.Fediverse.Token = tokenResponse.AccessToken
	c.config.Fediverse.TokenExp = time.Now().AddDate(0, 0, 30).Format(time.RFC3339) // Token expires in 30 days

	// Save updated config
	if err := c.saveConfig(); err != nil {
		log.Printf("Warning: Failed to save token to config: %v", err)
	}

	log.Println("Successfully authenticated with Fediverse instance")
	return nil
}

func (c *FediverseClient) saveConfig() error {
	// Determine config file name and format
	configFilename := "config.json"
	if _, err := os.Stat("config.yaml"); err == nil {
		configFilename = "config.yaml"
	} else if _, err := os.Stat("config.yml"); err == nil {
		configFilename = "config.yml"
	}

	// Read existing config to preserve user settings
	configFile, err := os.Open(configFilename)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer configFile.Close()

	var existingConfig Config
	ext := strings.ToLower(filepath.Ext(configFilename))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.NewDecoder(configFile).Decode(&existingConfig); err != nil {
			return fmt.Errorf("failed to decode existing YAML config: %w", err)
		}
	default:
		if err := json.NewDecoder(configFile).Decode(&existingConfig); err != nil {
			return fmt.Errorf("failed to decode existing JSON config: %w", err)
		}
	}

	// Only update the token fields, preserve everything else
	existingConfig.Fediverse.Token = c.config.Fediverse.Token
	existingConfig.Fediverse.TokenExp = c.config.Fediverse.TokenExp

	// Write back the updated config
	configFile.Close() // Close before reopening for writing
	configFile, err = os.Create(configFilename)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer configFile.Close()

	switch ext {
	case ".yaml", ".yml":
		encoder := yaml.NewEncoder(configFile)
		defer encoder.Close()
		return encoder.Encode(existingConfig)
	default:
		encoder := json.NewEncoder(configFile)
		encoder.SetIndent("", "  ")
		return encoder.Encode(existingConfig)
	}
}

func (c *FediverseClient) getCurrentAccount() (*Account, error) {
	req, err := http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/accounts/verify_credentials", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create verify credentials request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to verify credentials: %w", err)
	}
	defer resp.Body.Close()

	var currentAccount Account
	if err := json.NewDecoder(resp.Body).Decode(&currentAccount); err != nil {
		return nil, fmt.Errorf("failed to decode account response: %w", err)
	}

	return &currentAccount, nil
}

func (c *FediverseClient) getFollowers() ([]Account, error) {
	currentAccount, err := c.getCurrentAccount()
	if err != nil {
		return nil, err
	}

	// Get followers
	req, err := http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/accounts/"+currentAccount.ID+"/followers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create followers request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get followers: %w", err)
	}
	defer resp.Body.Close()

	var followers []Account
	if err := json.NewDecoder(resp.Body).Decode(&followers); err != nil {
		return nil, fmt.Errorf("failed to decode followers response: %w", err)
	}

	return followers, nil
}

func (c *FediverseClient) followUser(accountID string) error {
	req, err := http.NewRequest("POST", c.config.Fediverse.InstanceURL+"/api/v1/accounts/"+accountID+"/follow", nil)
	if err != nil {
		return fmt.Errorf("failed to create follow request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to follow user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("follow request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *FediverseClient) getRelationship(accountID string) (*Relationship, error) {
	req, err := http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/accounts/relationships?id="+accountID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create relationship request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get relationship: %w", err)
	}
	defer resp.Body.Close()

	var relationships []Relationship
	if err := json.NewDecoder(resp.Body).Decode(&relationships); err != nil {
		return nil, fmt.Errorf("failed to decode relationship response: %w", err)
	}

	if len(relationships) == 0 {
		return nil, fmt.Errorf("no relationship data returned")
	}

	return &relationships[0], nil
}

func (c *FediverseClient) getHomeTimeline() ([]Status, error) {
	req, err := http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/timelines/home", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create timeline request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get home timeline: %w", err)
	}
	defer resp.Body.Close()

	var statuses []Status
	if err := json.NewDecoder(resp.Body).Decode(&statuses); err != nil {
		return nil, fmt.Errorf("failed to decode timeline response: %w", err)
	}
	return statuses, nil
}

func (c *FediverseClient) getUserStatuses(accountID string, limit int) ([]Status, error) {
	// Get user's status history
	url := fmt.Sprintf("%s/api/v1/accounts/%s/statuses?limit=%d", c.config.Fediverse.InstanceURL, accountID, limit)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user statuses request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user statuses: %w", err)
	}
	defer resp.Body.Close()

	var statuses []Status
	if err := json.NewDecoder(resp.Body).Decode(&statuses); err != nil {
		return nil, fmt.Errorf("failed to decode user statuses response: %w", err)
	}
	return statuses, nil
}

func (c *FediverseClient) getAllUserStatuses(accountID string, maxPosts int) ([]Status, error) {
	// Get all user's statuses using pagination
	var allStatuses []Status
	var maxID string
	postsPerPage := 80 // Maximum allowed by most Fediverse instances
	totalPosts := 0
	pageCount := 0

	log.Printf("Starting to fetch posts for user %s (max: %d)", accountID, maxPosts)

	for {
		pageCount++
		// Build URL with pagination
		url := fmt.Sprintf("%s/api/v1/accounts/%s/statuses?limit=%d", c.config.Fediverse.InstanceURL, accountID, postsPerPage)
		if maxID != "" {
			url += fmt.Sprintf("&max_id=%s", maxID)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create user statuses request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.accessToken)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to get user statuses: %w", err)
		}
		defer resp.Body.Close()

		var statuses []Status
		if err := json.NewDecoder(resp.Body).Decode(&statuses); err != nil {
			return nil, fmt.Errorf("failed to decode user statuses response: %w", err)
		}

		// If no more statuses, break
		if len(statuses) == 0 {
			log.Printf("No more posts found for user %s (page %d)", accountID, pageCount)
			break
		}

		// Add statuses to our collection
		allStatuses = append(allStatuses, statuses...)
		totalPosts += len(statuses)

		// Log the date range of this page
		if len(statuses) > 0 {
			oldestInPage := statuses[len(statuses)-1].CreatedAt
			newestInPage := statuses[0].CreatedAt
			log.Printf("Page %d: Fetched %d posts from user %s (total: %d) - Date range: %s to %s",
				pageCount, len(statuses), accountID, totalPosts, oldestInPage, newestInPage)
		}

		// Check if we've reached the maximum
		if maxPosts > 0 && totalPosts >= maxPosts {
			log.Printf("Reached maximum posts limit (%d) for user %s", maxPosts, accountID)
			allStatuses = allStatuses[:maxPosts]
			break
		}

		// Set max_id for next page (use the ID of the last status)
		maxID = statuses[len(statuses)-1].ID

		// Add a small delay to avoid rate limiting
		time.Sleep(500 * time.Millisecond)
	}

	// Log final summary with date range
	if len(allStatuses) > 0 {
		oldestPost := allStatuses[len(allStatuses)-1].CreatedAt
		newestPost := allStatuses[0].CreatedAt
		log.Printf("Total posts fetched from user %s: %d (pages: %d) - Date range: %s to %s",
			accountID, len(allStatuses), pageCount, oldestPost, newestPost)
	} else {
		log.Printf("No posts found for user %s", accountID)
	}

	return allStatuses, nil
}

func extractURLs(content string, instanceHostname string, fediverseHostnames map[string]bool, blacklistedDomains []string) []string {
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	matches := urlRegex.FindAllString(content, -1)

	urls := make([]string, 0)
	for _, match := range matches {
		// Clean up the URL (remove trailing punctuation)
		cleanURL := strings.TrimRight(match, ".,;:!?")

		// Skip internal Fediverse links
		if isInternalFediverseLink(cleanURL, instanceHostname, fediverseHostnames) {
			log.Printf("Skipping internal Fediverse link: %s", cleanURL)
			continue
		}

		// Skip blacklisted domains
		if isBlacklistedDomain(cleanURL, blacklistedDomains) {
			log.Printf("Skipping blacklisted domain: %s", cleanURL)
			continue
		}

		// Skip media attachments
		if isMediaAttachment(cleanURL) {
			log.Printf("Skipping media attachment: %s", cleanURL)
			continue
		}

		urls = append(urls, cleanURL)
	}

	return urls
}

// extractURLsFromStatus extracts all URLs from a status, including boosts
func extractURLsFromStatus(status Status, instanceHostname string, fediverseHostnames map[string]bool, blacklistedDomains []string) []string {
	var urls []string

	// Log visibility for debugging
	log.Printf("Processing status %s (visibility: %s)", status.ID, status.Visibility)

	// Extract URLs from main status content
	contentURLs := extractURLs(status.Content, instanceHostname, fediverseHostnames, blacklistedDomains)
	urls = append(urls, contentURLs...)

	// Handle boosts (reblogs) - extract URLs from the boosted content
	if status.Reblogged != nil {
		switch reblogged := status.Reblogged.(type) {
		case bool:
			if reblogged {
				log.Printf("Status %s is a reblog (boolean flag)", status.ID)
			}
		case map[string]interface{}:
			// This is a boosted status object
			log.Printf("Status %s contains a boost", status.ID)
			if content, ok := reblogged["content"].(string); ok {
				reblogURLs := extractURLs(content, instanceHostname, fediverseHostnames, blacklistedDomains)
				urls = append(urls, reblogURLs...)
				log.Printf("Extracted %d URLs from boosted content", len(reblogURLs))
			}

			// Also check media attachments in the boosted status (but skip the media files themselves)
			if mediaAttachments, ok := reblogged["media_attachments"].([]interface{}); ok {
				for _, media := range mediaAttachments {
					if mediaMap, ok := media.(map[string]interface{}); ok {
						// Skip the actual media files, but we could potentially archive the text URL if it exists
						if textURL, ok := mediaMap["text_url"].(string); ok && textURL != "" && !isMediaAttachment(textURL) {
							urls = append(urls, textURL)
						}
					}
				}
			}

			// Check card in the boosted status
			if card, ok := reblogged["card"].(map[string]interface{}); ok {
				if cardURL, ok := card["url"].(string); ok && cardURL != "" {
					urls = append(urls, cardURL)
				}
			}
		}
	}

	// Extract URLs from media attachments (but skip the media files themselves)
	for _, media := range status.MediaAttachments {
		// Skip the actual media files, but we could potentially archive the text URL if it exists
		if media.TextURL != "" && !isMediaAttachment(media.TextURL) {
			urls = append(urls, media.TextURL)
		}
	}

	// Extract URLs from card
	if status.Card != nil && status.Card.URL != "" {
		urls = append(urls, status.Card.URL)
	}

	// Remove duplicates while preserving order
	seen := make(map[string]bool)
	var uniqueURLs []string
	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			uniqueURLs = append(uniqueURLs, url)
		}
	}

	return uniqueURLs
}

func processRSSFeeds(config *Config, urlsToArchive map[string]bool) {
	if len(config.Settings.RSSFeeds) == 0 {
		log.Println("No RSS feeds configured, skipping RSS processing")
		return
	}

	log.Printf("Processing %d RSS feeds...", len(config.Settings.RSSFeeds))

	fp := gofeed.NewParser()

	for _, feedURL := range config.Settings.RSSFeeds {
		log.Printf("Processing RSS feed: %s", feedURL)

		// Check if the URL is a direct link to an RSS feed or a page to discover the feed from
		if !strings.HasSuffix(feedURL, ".xml") {
			log.Printf("URL does not end in .xml, attempting to discover RSS feed from page...")
			discoveredURL, err := discoverRSSFeed(feedURL)
			if err != nil {
				log.Printf("Error discovering RSS feed from %s: %v", feedURL, err)
				continue
			}
			log.Printf("Discovered RSS feed: %s", discoveredURL)
			feedURL = discoveredURL
		}

		// Extract hostname from the RSS feed URL to filter out internal links
		feedURLParsed, err := url.Parse(feedURL)
		if err != nil {
			log.Printf("Error parsing RSS feed URL %s: %v", feedURL, err)
			continue
		}
		feedHostname := feedURLParsed.Hostname()
		log.Printf("RSS feed hostname: %s", feedHostname)

		parsedFeed, err := fp.ParseURL(feedURL)
		if err != nil {
			log.Printf("Error parsing RSS feed %s: %v", feedURL, err)
			continue
		}

		log.Printf("Found %d items in RSS feed %s", len(parsedFeed.Items), feedURL)

		feedURLCount := 0
		for _, item := range parsedFeed.Items {
			// Extract URLs from the item link
			if item.Link != "" {
				// Check if the link is on the same hostname as the RSS feed
				itemURL, err := url.Parse(item.Link)
				if err == nil && itemURL.Hostname() != feedHostname {
					if !urlsToArchive[item.Link] {
						feedURLCount++
					}
					urlsToArchive[item.Link] = true
				} else {
					log.Printf("Skipping internal link from RSS feed: %s", item.Link)
				}
			}

			// Extract URLs from the item description/content
			if item.Description != "" {
				urls := extractURLs(item.Description, "", make(map[string]bool), config.Settings.BlacklistedDomains)
				for _, urlStr := range urls {
					// Check if the URL is on the same hostname as the RSS feed
					urlParsed, err := url.Parse(urlStr)
					if err == nil && urlParsed.Hostname() != feedHostname {
						if !urlsToArchive[urlStr] {
							feedURLCount++
						}
						urlsToArchive[urlStr] = true
					} else {
						log.Printf("Skipping internal link from RSS feed: %s", urlStr)
					}
				}
			}

			// Check for enclosures (media links)
			for _, enclosure := range item.Enclosures {
				if enclosure.URL != "" && !isMediaAttachment(enclosure.URL) {
					// Check if the enclosure URL is on the same hostname as the RSS feed
					enclosureURL, err := url.Parse(enclosure.URL)
					if err == nil && enclosureURL.Hostname() != feedHostname {
						if !urlsToArchive[enclosure.URL] {
							feedURLCount++
						}
						urlsToArchive[enclosure.URL] = true
					} else {
						log.Printf("Skipping internal enclosure from RSS feed: %s", enclosure.URL)
					}
				}
			}
		}

		log.Printf("Processed RSS feed %s: found %d new unique URLs", feedURL, feedURLCount)
	}
}

// shouldProcessStatus checks if a status should be processed based on visibility settings
func shouldProcessStatus(status Status, includeVisibility []string) bool {
	// If no visibility filter is set, process all statuses
	if len(includeVisibility) == 0 {
		return true
	}

	// Check if the status visibility is in the allowed list
	for _, allowedVisibility := range includeVisibility {
		if status.Visibility == allowedVisibility {
			return true
		}
	}

	return false
}

// extractHostnamesFromStatuses extracts all hostnames from a list of statuses
func extractHostnamesFromStatuses(statuses []Status) map[string]bool {
	hostnames := make(map[string]bool)

	for _, status := range statuses {
		// Extract hostname from the status author's URL
		if status.Account.URL != "" {
			if parsedURL, err := url.Parse(status.Account.URL); err == nil {
				hostnames[strings.ToLower(parsedURL.Host)] = true
			}
		}

		// Extract hostname from the status URI
		if status.URI != "" {
			if parsedURL, err := url.Parse(status.URI); err == nil {
				hostnames[strings.ToLower(parsedURL.Host)] = true
			}
		}

		// Extract hostname from the status URL
		if status.URL != "" {
			if parsedURL, err := url.Parse(status.URL); err == nil {
				hostnames[strings.ToLower(parsedURL.Host)] = true
			}
		}

		// Check reblogged content
		if status.Reblogged != nil {
			switch reblogged := status.Reblogged.(type) {
			case map[string]interface{}:
				// Extract hostname from reblogged account URL
				if account, ok := reblogged["account"].(map[string]interface{}); ok {
					if accountURL, ok := account["url"].(string); ok && accountURL != "" {
						if parsedURL, err := url.Parse(accountURL); err == nil {
							hostnames[strings.ToLower(parsedURL.Host)] = true
						}
					}
				}
				// Extract hostname from reblogged URI
				if rebloggedURI, ok := reblogged["uri"].(string); ok && rebloggedURI != "" {
					if parsedURL, err := url.Parse(rebloggedURI); err == nil {
						hostnames[strings.ToLower(parsedURL.Host)] = true
					}
				}
			}
		}
	}

	return hostnames
}

// getKeys returns a slice of keys from a map[string]bool
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func isInternalFediverseLink(urlStr string, instanceHostname string, fediverseHostnames map[string]bool) bool {
	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsedURL.Host)
	path := parsedURL.Path

	// Check if the URL is from the same hostname as the user's Fediverse instance
	if instanceHostname != "" && strings.ToLower(instanceHostname) == host {
		log.Printf("Skipping internal link from same instance: %s", urlStr)
		return true
	}

	// Check if the URL is from any of the Fediverse hostnames we've discovered
	if fediverseHostnames[host] {
		log.Printf("Skipping internal link from discovered Fediverse hostname: %s", urlStr)
		return true
	}

	// Check for common Fediverse keywords in hostname (fallback for new instances)
	fediverseKeywords := []string{"social", "mastodon", "pleroma", "misskey", "pixelfed", "lemmy", "kbin", "peertube", "writeas", "bookwyrm", "funkwhale", "mobilizon", "hubzilla", "friendica", "diaspora", "gnusocial", "fedi", "fediverse"}
	for _, keyword := range fediverseKeywords {
		if strings.Contains(host, keyword) {
			// Check for internal Fediverse paths
			internalPaths := []string{
				"/tags/", "/@", "/users/", "/accounts/", "/web/", "/api/",
				"/oauth/", "/admin/", "/settings/", "/filters/", "/blocks/",
				"/mutes/", "/follow_requests/", "/lists/", "/circles/",
				"/conversations/", "/notifications/", "/favourites/",
				"/bookmarks/", "/pinned/", "/statuses/", "/media/",
				"/search", "/explore", "/public", "/local", "/federated",
				"/home", "/direct", "/mentions", "/reports", "/appeals",
				"/domain_blocks", "/email_domain_blocks", "/ip_blocks",
				"/retention", "/instances", "/peers", "/announcements",
				"/custom_emojis", "/trends", "/suggestions", "/endorsements",
				"/featured_tags", "/preferences", "/push_subscriptions",
				"/apps", "/instance", "/nodeinfo", "/.well-known/",
				"/u/", "/c/", "/post/", "/comment/", "/community/",
				"/modlog", "/admin", "/settings", "/inbox", "/outbox",
				"/followers", "/following", "/featured", "/pinned",
				"/status/", "/activity", "/collections", "/liked",
				"/shared", "/bookmarks", "/mutes", "/blocks",
			}

			for _, internalPath := range internalPaths {
				if strings.HasPrefix(path, internalPath) {
					return true
				}
			}

			// Also check for user profile patterns (e.g., /@username, /u/username)
			if strings.Contains(path, "/@") || strings.Contains(path, "/u/") {
				return true
			}

			// Check for hashtag patterns
			if strings.Contains(path, "/tags/") || strings.Contains(path, "/hashtag/") {
				return true
			}

			// If it's a Fediverse domain, it's likely internal unless it's a specific external link
			return true
		}
	}

	return false
}

func isBlacklistedDomain(urlStr string, blacklistedDomains []string) bool {
	if len(blacklistedDomains) == 0 {
		return false
	}

	// Parse the URL to get the hostname
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(u.Hostname())

	// Check if the hostname matches any blacklisted domain
	for _, blacklistedDomain := range blacklistedDomains {
		blacklistedDomain = strings.ToLower(strings.TrimSpace(blacklistedDomain))

		// Exact match
		if hostname == blacklistedDomain {
			return true
		}

		// Subdomain match (e.g., blacklisted "example.com" matches "sub.example.com")
		if strings.HasSuffix(hostname, "."+blacklistedDomain) {
			return true
		}
	}

	return false
}

func isMediaAttachment(urlStr string) bool {
	// Parse the URL to get the path
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Check for common media attachment patterns
	path := strings.ToLower(u.Path)

	// Check for file server patterns
	if strings.Contains(path, "/fileserver/") {
		return true
	}

	// Check for media attachment patterns
	if strings.Contains(path, "/media_attachments/") {
		return true
	}

	// Check for common media file extensions
	mediaExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mov", ".avi", ".webm", ".mp3", ".wav", ".ogg"}
	for _, ext := range mediaExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	// Check for attachment patterns in path
	if strings.Contains(path, "/attachment/") {
		return true
	}

	return false
}

// loadConfig loads configuration from either JSON or YAML file
func loadConfig(filename string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s does not exist", filename)
	}

	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", filename, err)
	}

	var config Config

	// Try to determine file type by extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		// Parse as YAML
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config file %s: %v", filename, err)
		}
		log.Printf("Loaded configuration from YAML file: %s", filename)
	case ".json":
		// Parse as JSON
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config file %s: %v", filename, err)
		}
		log.Printf("Loaded configuration from JSON file: %s", filename)
	default:
		// Try to auto-detect format
		// First try JSON
		if err := json.Unmarshal(data, &config); err == nil {
			log.Printf("Auto-detected and loaded configuration from JSON file: %s", filename)
		} else {
			// Try YAML
			if err := yaml.Unmarshal(data, &config); err != nil {
				return nil, fmt.Errorf("failed to parse config file %s as JSON or YAML: %v", filename, err)
			}
			log.Printf("Auto-detected and loaded configuration from YAML file: %s", filename)
		}
	}

	return &config, nil
}

// convertJSONToYAML converts an existing JSON config file to YAML format
func convertJSONToYAML(jsonFilename string) error {
	// Read the JSON file
	data, err := os.ReadFile(jsonFilename)
	if err != nil {
		return fmt.Errorf("failed to read JSON config file %s: %v", jsonFilename, err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse JSON config file %s: %v", jsonFilename, err)
	}

	// Create YAML filename
	yamlFilename := strings.TrimSuffix(jsonFilename, ".json") + ".yaml"

	// Write YAML file
	yamlData, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %v", err)
	}

	if err := os.WriteFile(yamlFilename, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write YAML config file %s: %v", yamlFilename, err)
	}

	// Backup the original JSON file
	backupFilename := jsonFilename + ".backup"
	if err := os.Rename(jsonFilename, backupFilename); err != nil {
		return fmt.Errorf("failed to backup JSON config file: %v", err)
	}

	log.Printf("Converted %s to %s and backed up original as %s", jsonFilename, yamlFilename, backupFilename)
	return nil
}

type S3Client struct {
	config      *Config
	minioClient *minio.Client
}

func NewS3Client(config *Config) (*S3Client, error) {
	endpoint := config.S3.Endpoint
	accessKeyID := config.S3.AccessKey
	secretAccessKey := config.S3.SecretKey
	useSSL := config.S3.UseSSL
	bucket := config.S3.Bucket

	log.Printf("Initializing S3 client...")
	log.Printf("  Endpoint: %s", endpoint)
	log.Printf("  Access Key ID: %s", accessKeyID)
	secretKeyPreview := secretAccessKey
	if len(secretAccessKey) > 8 {
		secretKeyPreview = secretAccessKey[:8]
	}
	log.Printf("  Secret Key: %s... (length: %d)", secretKeyPreview, len(secretAccessKey))
	log.Printf("  Bucket: %s", bucket)
	log.Printf("  Use SSL: %v", useSSL)

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Printf("ERROR: Failed to create S3 client: %v", err)
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}
	log.Printf("S3 client created successfully")

	return &S3Client{
		config:      config,
		minioClient: minioClient,
	}, nil
}

func (c *S3Client) uploadURLs(urls []string, accountName string) error {
	log.Printf("=== Starting S3 upload process ===")
	log.Printf("Number of URLs to upload: %d", len(urls))
	log.Printf("Account name: %s", accountName)

	if len(urls) == 0 {
		log.Println("No URLs to upload, skipping")
		return nil
	}

	// Sanitize account name for filename (remove special characters, replace @ with -)
	sanitizedAccountName := strings.ReplaceAll(accountName, "@", "-")
	sanitizedAccountName = strings.ReplaceAll(sanitizedAccountName, "/", "-")
	sanitizedAccountName = strings.ReplaceAll(sanitizedAccountName, "\\", "-")
	sanitizedAccountName = strings.ReplaceAll(sanitizedAccountName, " ", "-")

	// Create timestamped filename with account name
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-urls-%s.txt", sanitizedAccountName, timestamp)
	log.Printf("Generated filename: %s", filename)

	// Create temporary file
	log.Printf("Creating temporary file...")
	tmpFile, err := os.CreateTemp("", filename)
	if err != nil {
		log.Printf("ERROR: Failed to create temporary file: %v", err)
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	log.Printf("Temporary file created: %s", tmpFile.Name())
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Printf("Warning: Failed to remove temporary file %s: %v", tmpFile.Name(), err)
		} else {
			log.Printf("Cleaned up temporary file: %s", tmpFile.Name())
		}
	}()
	defer tmpFile.Close()

	// Write URLs to file (one per line)
	log.Printf("Writing %d URLs to temporary file...", len(urls))
	writtenCount := 0
	for i, urlStr := range urls {
		if _, err := tmpFile.WriteString(urlStr + "\n"); err != nil {
			log.Printf("ERROR: Failed to write URL #%d to file: %v", i+1, err)
			log.Printf("  URL was: %s", urlStr)
			return fmt.Errorf("failed to write URL to file: %w", err)
		}
		writtenCount++
		if (i+1)%100 == 0 {
			log.Printf("  Written %d/%d URLs...", i+1, len(urls))
		}
	}
	log.Printf("Successfully wrote %d URLs to temporary file", writtenCount)

	// Close file before uploading
	log.Printf("Closing temporary file...")
	if err := tmpFile.Close(); err != nil {
		log.Printf("ERROR: Failed to close temporary file: %v", err)
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	log.Printf("Temporary file closed successfully")

	// Open file for reading
	log.Printf("Opening temporary file for reading...")
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		log.Printf("ERROR: Failed to open file for upload: %v", err)
		return fmt.Errorf("failed to open file for upload: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Warning: Failed to close file: %v", err)
		}
	}()

	// Get file info for size
	log.Printf("Getting file information...")
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("ERROR: Failed to get file info: %v", err)
		return fmt.Errorf("failed to get file info: %w", err)
	}
	fileSize := fileInfo.Size()
	log.Printf("File size: %d bytes (%.2f KB)", fileSize, float64(fileSize)/1024.0)

	// Upload to S3
	ctx := context.Background()
	bucketName := c.config.S3.Bucket
	log.Printf("Preparing to upload to S3...")
	log.Printf("  Bucket: %s", bucketName)
	log.Printf("  Object key: %s", filename)
	log.Printf("  File size: %d bytes", fileSize)
	log.Printf("Note: Skipping bucket existence check (write-only permissions)")

	// Upload the file directly (skip bucket existence check due to write-only permissions)
	log.Printf("Starting file upload to S3...")
	log.Printf("  Bucket: %s", bucketName)
	log.Printf("  Object key: %s", filename)
	log.Printf("  Content-Type: text/plain")
	log.Printf("  File size: %d bytes", fileSize)

	uploadInfo, err := c.minioClient.PutObject(ctx, bucketName, filename, file, fileInfo.Size(), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		log.Printf("ERROR: Failed to upload file to S3: %v", err)
		log.Printf("  Bucket: %s", bucketName)
		log.Printf("  Object key: %s", filename)
		log.Printf("  Endpoint: %s", c.config.S3.Endpoint)
		log.Printf("  Access Key ID: %s", c.config.S3.AccessKey)
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	log.Printf("=== S3 upload completed successfully ===")
	log.Printf("Upload Info:")
	log.Printf("  ETag: %s", uploadInfo.ETag)
	log.Printf("  Location: %s", uploadInfo.Location)
	log.Printf("  Version ID: %s", uploadInfo.VersionID)
	log.Printf("Successfully uploaded %d URLs to S3: s3://%s/%s", len(urls), bucketName, filename)
	log.Printf("Full S3 URL: s3://%s/%s", bucketName, filename)
	return nil
}

func discoverRSSFeed(pageURL string) (string, error) {
	// Make a GET request to the page
	res, err := http.Get(pageURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", fmt.Errorf("failed to fetch page: status code %d", res.StatusCode)
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", err
	}

	// Find the RSS link
	rssLink, exists := doc.Find(`a[title="RSS"]`).Attr("href")
	if !exists {
		// Try another common pattern
		rssLink, exists = doc.Find(`link[type="application/rss+xml"]`).Attr("href")
	}

	if !exists {
		return "", fmt.Errorf("could not find RSS feed link on page %s", pageURL)
	}

	// If the link is relative, make it absolute
	if !strings.HasPrefix(rssLink, "http") {
		baseURL, err := url.Parse(pageURL)
		if err != nil {
			return "", err
		}
		rssURL, err := baseURL.Parse(rssLink)
		if err != nil {
			return "", err
		}
		return rssURL.String(), nil
	}

	return rssLink, nil
}

func main() {
	// Parse command line flags
	singleRun := flag.Bool("single", false, "Run only once instead of continuously")
	flag.Parse()

	// Load configuration
	var config *Config
	var err error

	// Try to load config in order: config.yaml, config.yml, config.json
	configFiles := []string{"config.yaml", "config.yml", "config.json"}
	for _, filename := range configFiles {
		config, err = loadConfig(filename)
		if err == nil {
			break
		}
		log.Printf("Failed to load %s: %v", filename, err)
	}

	if config == nil {
		log.Fatalf("Failed to load any configuration file. Tried: %v", configFiles)
	}

	// If we loaded from JSON, automatically convert it to YAML for future use
	if strings.HasSuffix(configFiles[len(configFiles)-1], ".json") {
		// Check if we actually loaded from JSON (not YAML)
		if _, err := os.Stat("config.json"); err == nil {
			// Check if YAML doesn't exist
			if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
				log.Println("Converting JSON configuration to YAML format...")
				if err := convertJSONToYAML("config.json"); err != nil {
					log.Printf("Warning: Failed to convert JSON to YAML: %v", err)
				}
			}
		}
	}

	// Initialize clients
	fediverseClient := NewFediverseClient(config)
	s3Client, err := NewS3Client(config)
	if err != nil {
		log.Fatalf("Failed to create S3 client: %v", err)
	}

	// Extract instance hostname for internal link filtering
	instanceURL, err := url.Parse(config.Fediverse.InstanceURL)
	if err != nil {
		log.Fatalf("Failed to parse instance URL: %v", err)
	}
	instanceHostname := instanceURL.Host
	log.Printf("Using instance hostname for filtering: %s", instanceHostname)

	if *singleRun {
		log.Println("Starting Archive Mastodon service (single run mode)...")
	} else {
		log.Println("Starting Archive Mastodon service (continuous mode)...")
	}

	for {
		// Authenticate with Fediverse instance
		if err := fediverseClient.authenticate(); err != nil {
			log.Printf("Authentication failed: %v", err)
			if !*singleRun {
				log.Println("Waiting 1 hour before retry...")
				time.Sleep(1 * time.Hour)
				continue
			} else {
				break
			}
		}

		// Get followers and follow them back
		followers, err := fediverseClient.getFollowers()
		if err != nil {
			log.Printf("Failed to get followers: %v", err)
			if !*singleRun {
				log.Println("Waiting 1 hour before retry...")
				time.Sleep(1 * time.Hour)
				continue
			} else {
				break
			}
		}

		log.Printf("Found %d followers", len(followers))

		for _, follower := range followers {
			// Check if we're already following this user
			if !follower.Following {
				log.Printf("Checking if already following: %s (@%s)", follower.DisplayName, follower.Username)

				// Get the relationship to see if we're already following
				relationship, err := fediverseClient.getRelationship(follower.ID)
				if err != nil {
					log.Printf("Failed to get relationship for %s: %v", follower.Username, err)
					continue
				}

				if relationship.Following {
					log.Printf("Already following %s (@%s), skipping", follower.DisplayName, follower.Username)
					continue
				}

				log.Printf("Following back user: %s (@%s)", follower.DisplayName, follower.Username)
				if err := fediverseClient.followUser(follower.ID); err != nil {
					log.Printf("Failed to follow user %s: %v", follower.Username, err)
				} else {
					log.Printf("Successfully followed back: %s", follower.Username)
				}
				// Add a small delay to avoid rate limiting
				time.Sleep(1 * time.Second)
			}
		}

		// Get authenticated account for filename
		currentAccount, err := fediverseClient.getCurrentAccount()
		if err != nil {
			log.Printf("Failed to get current account: %v", err)
			currentAccount = &Account{Username: "unknown", Acct: "unknown"}
		}
		homeTimelineAccountName := currentAccount.Acct
		if homeTimelineAccountName == "" {
			homeTimelineAccountName = currentAccount.Username
		}

		// Get home timeline and extract URLs
		statuses, err := fediverseClient.getHomeTimeline()
		if err != nil {
			log.Printf("Failed to get home timeline: %v", err)
			if !*singleRun {
				log.Println("Waiting 1 hour before retry...")
				time.Sleep(1 * time.Hour)
				continue
			} else {
				break
			}
		}

		log.Printf("Retrieved %d statuses from home timeline", len(statuses))

		// Extract hostnames from all statuses to build dynamic Fediverse domain list
		fediverseHostnames := extractHostnamesFromStatuses(statuses)
		log.Printf("Discovered %d Fediverse hostnames: %v", len(fediverseHostnames), getKeys(fediverseHostnames))

		urlsToArchive := make(map[string]bool) // Use map to avoid duplicates
		visibilityStats := make(map[string]int)
		processedCount := 0
		skippedCount := 0

		for _, status := range statuses {
			visibilityStats[status.Visibility]++

			// Check if we should process this status based on visibility
			if !shouldProcessStatus(status, config.Settings.IncludeVisibility) {
				skippedCount++
				continue
			}

			processedCount++
			// Extract all URLs from status (including boosts)
			urls := extractURLsFromStatus(status, instanceHostname, fediverseHostnames, config.Settings.BlacklistedDomains)
			for _, url := range urls {
				urlsToArchive[url] = true
			}
		}

		log.Printf("Home timeline visibility stats: %v", visibilityStats)
		log.Printf("Processed %d statuses, skipped %d statuses", processedCount, skippedCount)

		log.Printf("Found %d unique URLs to archive from home timeline", len(urlsToArchive))

		// Upload home timeline URLs separately
		if len(urlsToArchive) > 0 {
			homeTimelineURLList := make([]string, 0, len(urlsToArchive))
			for url := range urlsToArchive {
				homeTimelineURLList = append(homeTimelineURLList, url)
			}
			log.Printf("Uploading %d unique URLs from home timeline to S3...", len(homeTimelineURLList))
			if err := s3Client.uploadURLs(homeTimelineURLList, homeTimelineAccountName); err != nil {
				log.Printf("Failed to upload home timeline URLs to S3: %v", err)
			}
		}

		// Process older posts from followed users
		log.Println("Processing older posts from followed users...")
		processedUsers := make(map[string]bool) // Track processed users to avoid duplicates

		for _, follower := range followers {
			if processedUsers[follower.ID] {
				continue
			}
			processedUsers[follower.ID] = true

			log.Printf("Processing older posts from user: %s (@%s)", follower.DisplayName, follower.Username)

			// Get user's statuses (up to configured limit for comprehensive coverage)
			maxPosts := config.Settings.MaxPostsPerUser
			if maxPosts <= 0 {
				maxPosts = 1000 // Default to 1000 if not configured
			}
			userStatuses, err := fediverseClient.getAllUserStatuses(follower.ID, maxPosts)
			if err != nil {
				log.Printf("Failed to get statuses for user %s: %v", follower.Username, err)
				continue
			}

			log.Printf("Retrieved %d statuses from user %s", len(userStatuses), follower.Username)

			// Extract hostnames from user's statuses and merge with existing ones
			userFediverseHostnames := extractHostnamesFromStatuses(userStatuses)
			for hostname := range userFediverseHostnames {
				fediverseHostnames[hostname] = true
			}
			log.Printf("Updated Fediverse hostnames (now %d total): %v", len(fediverseHostnames), getKeys(fediverseHostnames))

			userURLsToArchive := make(map[string]bool)
			userVisibilityStats := make(map[string]int)
			userProcessedCount := 0
			userSkippedCount := 0

			for _, status := range userStatuses {
				userVisibilityStats[status.Visibility]++

				// Check if we should process this status based on visibility
				if !shouldProcessStatus(status, config.Settings.IncludeVisibility) {
					userSkippedCount++
					continue
				}

				userProcessedCount++
				// Extract all URLs from status (including boosts)
				urls := extractURLsFromStatus(status, instanceHostname, fediverseHostnames, config.Settings.BlacklistedDomains)
				for _, url := range urls {
					userURLsToArchive[url] = true
				}
			}

			log.Printf("User %s visibility stats: %v", follower.Username, userVisibilityStats)
			log.Printf("User %s: processed %d statuses, skipped %d statuses", follower.Username, userProcessedCount, userSkippedCount)

			log.Printf("Found %d unique URLs to archive from user %s", len(userURLsToArchive), follower.Username)

			// Upload user URLs separately with account name in filename
			if len(userURLsToArchive) > 0 {
				userURLList := make([]string, 0, len(userURLsToArchive))
				for url := range userURLsToArchive {
					userURLList = append(userURLList, url)
				}
				accountName := follower.Acct
				if accountName == "" {
					accountName = follower.Username
				}
				log.Printf("Uploading %d unique URLs from user %s to S3...", len(userURLList), accountName)
				if err := s3Client.uploadURLs(userURLList, accountName); err != nil {
					log.Printf("Failed to upload URLs for user %s to S3: %v", accountName, err)
				}
			}

			// Add delay between users to avoid rate limiting
			time.Sleep(2 * time.Second)
		}

		// Process RSS feeds (upload separately with feed identifier)
		rssURLsToArchive := make(map[string]bool)
		processRSSFeeds(config, rssURLsToArchive)

		// Upload RSS feed URLs separately
		if len(rssURLsToArchive) > 0 {
			rssURLList := make([]string, 0, len(rssURLsToArchive))
			for url := range rssURLsToArchive {
				rssURLList = append(rssURLList, url)
			}
			log.Printf("Uploading %d unique URLs from RSS feeds to S3...", len(rssURLList))
			if err := s3Client.uploadURLs(rssURLList, "rss-feeds"); err != nil {
				log.Printf("Failed to upload RSS feed URLs to S3: %v", err)
			}
		}

		log.Println("Archive process completed")

		// If single run mode, exit after one iteration
		if *singleRun {
			log.Println("Single run mode - exiting after completion")
			break
		}

		// Wait before next run
		log.Println("Waiting 30 minutes before next run...")
		time.Sleep(30 * time.Minute)
	}
}
