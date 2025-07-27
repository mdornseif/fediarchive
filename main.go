package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration
type Config struct {
	Fediverse struct {
		InstanceURL string `json:"instance_url"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Token       string `json:"token"`
		TokenExp    string `json:"token_exp"`
	} `json:"fediverse"`
	ArchiveBox struct {
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Tag      string `json:"tag"`
	} `json:"archivebox"`
	Settings struct {
		MaxPostsPerUser   int      `json:"max_posts_per_user"`
		IncludeVisibility []string `json:"include_visibility"`
	} `json:"settings"`
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
	// Read existing config to preserve user settings
	configFile, err := os.Open("config.json")
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer configFile.Close()

	var existingConfig Config
	if err := json.NewDecoder(configFile).Decode(&existingConfig); err != nil {
		return fmt.Errorf("failed to decode existing config: %w", err)
	}

	// Only update the token fields, preserve everything else
	existingConfig.Fediverse.Token = c.config.Fediverse.Token
	existingConfig.Fediverse.TokenExp = c.config.Fediverse.TokenExp

	// Write back the updated config
	configFile.Close() // Close before reopening for writing
	configFile, err = os.Create("config.json")
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer configFile.Close()

	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	return encoder.Encode(existingConfig)
}

func (c *FediverseClient) getFollowers() ([]Account, error) {
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

	// Get followers
	req, err = http.NewRequest("GET", c.config.Fediverse.InstanceURL+"/api/v1/accounts/"+currentAccount.ID+"/followers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create followers request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err = c.httpClient.Do(req)
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

func extractURLs(content string, instanceHostname string, fediverseHostnames map[string]bool) []string {
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

		urls = append(urls, cleanURL)
	}

	return urls
}

// extractURLsFromStatus extracts all URLs from a status, including boosts
func extractURLsFromStatus(status Status, instanceHostname string, fediverseHostnames map[string]bool) []string {
	var urls []string

	// Log visibility for debugging
	log.Printf("Processing status %s (visibility: %s)", status.ID, status.Visibility)

	// Extract URLs from main status content
	contentURLs := extractURLs(status.Content, instanceHostname, fediverseHostnames)
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
				reblogURLs := extractURLs(content, instanceHostname, fediverseHostnames)
				urls = append(urls, reblogURLs...)
				log.Printf("Extracted %d URLs from boosted content", len(reblogURLs))
			}

			// Also check media attachments in the boosted status
			if mediaAttachments, ok := reblogged["media_attachments"].([]interface{}); ok {
				for _, media := range mediaAttachments {
					if mediaMap, ok := media.(map[string]interface{}); ok {
						if url, ok := mediaMap["url"].(string); ok && url != "" {
							urls = append(urls, url)
						}
						if remoteURL, ok := mediaMap["remote_url"].(string); ok && remoteURL != "" {
							urls = append(urls, remoteURL)
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

	// Extract URLs from media attachments
	for _, media := range status.MediaAttachments {
		if media.URL != "" {
			urls = append(urls, media.URL)
		}
		if media.RemoteURL != "" {
			urls = append(urls, media.RemoteURL)
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

type ArchiveBoxClient struct {
	config        *Config
	httpClient    *http.Client
	sessionCookie string
	csrfToken     string
	isLoggedIn    bool
}

func NewArchiveBoxClient(config *Config) *ArchiveBoxClient {
	// Load existing session cookie from cookies.txt
	sessionCookie := loadSessionCookieFromFile("cookies.txt")
	if sessionCookie != "" {
		log.Printf("Loaded existing session cookie: %s", sessionCookie)
	}

	return &ArchiveBoxClient{
		config:        config,
		httpClient:    &http.Client{Timeout: 60 * time.Second},
		sessionCookie: sessionCookie,
		isLoggedIn:    sessionCookie != "",
	}
}

func loadSessionCookieFromFile(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Could not open cookies file %s: %v", filename, err)
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_")) {
			continue
		}

		// Handle HttpOnly cookies (remove #HttpOnly_ prefix)
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = strings.TrimPrefix(line, "#HttpOnly_")
		}

		// Parse Netscape cookie format
		fields := strings.Split(line, "\t")
		if len(fields) >= 7 {
			name := fields[5]
			value := fields[6]
			if name == "sessionid" {
				return value
			}
		}
	}

	return ""
}

func saveSessionCookieToFile(filename string, sessionCookie string) error {
	if sessionCookie == "" {
		return fmt.Errorf("no session cookie to save")
	}

	// Create or truncate the cookies file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create cookies file %s: %v", filename, err)
	}
	defer file.Close()

	// Write Netscape cookie format header
	_, err = file.WriteString("# Netscape HTTP Cookie File\n")
	if err != nil {
		return fmt.Errorf("failed to write cookie header: %v", err)
	}

	// Get current time for cookie expiration (1 year from now)
	expiry := time.Now().AddDate(1, 0, 0)
	expiryStr := strconv.FormatInt(expiry.Unix(), 10)

	// Write session cookie in Netscape format
	// Format: domain, subdomain, path, secure, expiry, name, value
	cookieLine := fmt.Sprintf("archive.23.nu\tTRUE\t/\tTRUE\t%s\tsessionid\t%s\n", expiryStr, sessionCookie)
	_, err = file.WriteString(cookieLine)
	if err != nil {
		return fmt.Errorf("failed to write session cookie: %v", err)
	}

	log.Printf("Saved new session cookie to %s", filename)
	return nil
}

func (c *ArchiveBoxClient) login() error {
	if c.isLoggedIn && c.sessionCookie != "" {
		log.Printf("Already logged in with session cookie")
		return nil
	}

	// If we have a session cookie from cookies.txt, try to use it
	if c.sessionCookie != "" {
		log.Printf("Testing existing session cookie")
		// Test if the session is still valid by accessing the add page
		addURL := c.config.ArchiveBox.URL + "/add/"
		req, err := http.NewRequest("GET", addURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		// Add the session cookie
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to test session: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "Add URLs to Archive") || strings.Contains(string(body), "Archived Sites") {
			log.Printf("Existing session cookie is valid")
			c.isLoggedIn = true
			return nil
		} else {
			log.Printf("Existing session cookie is invalid, will try to login")
			c.sessionCookie = ""
			c.isLoggedIn = false
		}
	}

	// Step 1: Try to access the add page directly first
	addURL := c.config.ArchiveBox.URL + "/add/"
	resp, err := c.httpClient.Get(addURL)
	if err != nil {
		return fmt.Errorf("failed to access add page: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read add page: %v", err)
	}

	// Check if we're already authenticated (got the add page)
	if strings.Contains(string(body), "Add URLs to Archive") || strings.Contains(string(body), "Archived Sites") {
		// Extract CSRF token from the add page
		csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
		csrfMatches := csrfRegex.FindStringSubmatch(string(body))
		if len(csrfMatches) >= 2 {
			c.csrfToken = csrfMatches[1]
			log.Printf("Already authenticated, extracted CSRF token from add page: %s", c.csrfToken)

			// Check for session cookie
			for _, cookie := range resp.Cookies() {
				if cookie.Name == "sessionid" {
					c.sessionCookie = cookie.Value
					log.Printf("Found existing session cookie: %s", cookie.Value)
				}
			}

			if c.sessionCookie != "" {
				c.isLoggedIn = true
				log.Printf("Successfully authenticated using existing session")
				// Save the session cookie to file
				if err := saveSessionCookieToFile("cookies.txt", c.sessionCookie); err != nil {
					log.Printf("Warning: failed to save session cookie: %v", err)
				}
				return nil
			}
		}
	}

	// Check if we got the login page directly (not a redirect)
	if strings.Contains(string(body), "Log in") || strings.Contains(string(body), "login-form") {
		log.Printf("Got login page directly, extracting CSRF token")
		// Extract CSRF token from the login form
		csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
		csrfMatches := csrfRegex.FindStringSubmatch(string(body))
		if len(csrfMatches) >= 2 {
			c.csrfToken = csrfMatches[1]
			log.Printf("Extracted CSRF token from login page: %s", c.csrfToken)

			// Try both /admin/login/ and /accounts/login/ endpoints
			loginEndpoints := []string{"/admin/login/", "/accounts/login/"}
			for _, endpoint := range loginEndpoints {
				loginURL := c.config.ArchiveBox.URL + endpoint
				loginData := url.Values{}
				loginData.Set("username", c.config.ArchiveBox.Username)
				loginData.Set("password", c.config.ArchiveBox.Password)
				loginData.Set("csrfmiddlewaretoken", c.csrfToken)
				loginData.Set("next", "/add/")

				loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(loginData.Encode()))
				if err != nil {
					log.Printf("Failed to create login request for %s: %v", endpoint, err)
					continue
				}

				loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				loginReq.Header.Set("Referer", addURL)

				// Add cookies from the response
				for _, cookie := range resp.Cookies() {
					loginReq.AddCookie(cookie)
				}
				// Also add CSRF token as a cookie
				loginReq.AddCookie(&http.Cookie{Name: "csrftoken", Value: c.csrfToken})

				loginResp, err := c.httpClient.Do(loginReq)
				if err != nil {
					log.Printf("Failed to submit login to %s: %v", endpoint, err)
					continue
				}
				defer loginResp.Body.Close()

				// Store session cookies
				for _, cookie := range loginResp.Cookies() {
					if cookie.Name == "sessionid" {
						c.sessionCookie = cookie.Value
						log.Printf("Got session cookie: %s", cookie.Value)
					}
				}

				if c.sessionCookie != "" {
					c.isLoggedIn = true
					log.Printf("Successfully logged in to ArchiveBox using %s", endpoint)
					// Save the session cookie to file
					if err := saveSessionCookieToFile("cookies.txt", c.sessionCookie); err != nil {
						log.Printf("Warning: failed to save session cookie: %v", err)
					}
					return nil
				}
				// If login was successful, we should get a redirect
				if loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusMovedPermanently {
					location := loginResp.Header.Get("Location")
					if location != "" {
						if !strings.HasPrefix(location, "http") {
							if strings.HasPrefix(location, "/") {
								location = c.config.ArchiveBox.URL + location
							} else {
								location = addURL + "/" + location
							}
						}
						followReq, err := http.NewRequest("GET", location, nil)
						if err == nil {
							for _, cookie := range loginResp.Cookies() {
								followReq.AddCookie(cookie)
							}
							followResp, err := c.httpClient.Do(followReq)
							if err == nil {
								defer followResp.Body.Close()
								for _, cookie := range followResp.Cookies() {
									if cookie.Name == "sessionid" {
										c.sessionCookie = cookie.Value
										log.Printf("Got session cookie after redirect: %s", cookie.Value)
									}
								}
								if c.sessionCookie != "" {
									c.isLoggedIn = true
									log.Printf("Successfully logged in to ArchiveBox using %s (after redirect)", endpoint)
									// Save the session cookie to file
									if err := saveSessionCookieToFile("cookies.txt", c.sessionCookie); err != nil {
										log.Printf("Warning: failed to save session cookie: %v", err)
									}
									return nil
								}
							}
						}
					}
				}
			}

			return fmt.Errorf("login failed: no session cookie received from any endpoint")
		}
	}

	// If not authenticated, follow redirects to get to the login page
	currentURL := addURL
	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Handle relative URLs
		if !strings.HasPrefix(location, "http") {
			if strings.HasPrefix(location, "/") {
				location = c.config.ArchiveBox.URL + location
			} else {
				location = currentURL + "/" + location
			}
		}

		currentURL = location
		resp, err = c.httpClient.Get(location)
		if err != nil {
			return fmt.Errorf("failed to follow redirect to %s: %v", location, err)
		}
		defer resp.Body.Close()
	}

	// Now we should be at the login page
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login page: %v", err)
	}

	// Extract CSRF token from the login form
	csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
	csrfMatches := csrfRegex.FindStringSubmatch(string(body))
	if len(csrfMatches) < 2 {
		return fmt.Errorf("failed to extract CSRF token from login page")
	}
	c.csrfToken = csrfMatches[1]
	log.Printf("Extracted CSRF token: %s", c.csrfToken)

	// Try both /admin/login/ and /accounts/login/ endpoints
	loginEndpoints := []string{"/admin/login/", "/accounts/login/"}
	for _, endpoint := range loginEndpoints {
		loginURL := c.config.ArchiveBox.URL + endpoint
		loginData := url.Values{}
		loginData.Set("username", c.config.ArchiveBox.Username)
		loginData.Set("password", c.config.ArchiveBox.Password)
		loginData.Set("csrfmiddlewaretoken", c.csrfToken)
		loginData.Set("next", "/add/")

		loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(loginData.Encode()))
		if err != nil {
			log.Printf("Failed to create login request for %s: %v", endpoint, err)
			continue
		}

		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginReq.Header.Set("Referer", currentURL)

		// Add cookies from the login page response
		for _, cookie := range resp.Cookies() {
			loginReq.AddCookie(cookie)
		}
		// Also add CSRF token as a cookie
		loginReq.AddCookie(&http.Cookie{Name: "csrftoken", Value: c.csrfToken})

		loginResp, err := c.httpClient.Do(loginReq)
		if err != nil {
			log.Printf("Failed to submit login to %s: %v", endpoint, err)
			continue
		}
		defer loginResp.Body.Close()

		// Store session cookies
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "sessionid" {
				c.sessionCookie = cookie.Value
				log.Printf("Got session cookie: %s", cookie.Value)
			}
		}

		if c.sessionCookie != "" {
			c.isLoggedIn = true
			log.Printf("Successfully logged in to ArchiveBox using %s", endpoint)
			return nil
		}
		// If login was successful, we should get a redirect
		if loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusMovedPermanently {
			location := loginResp.Header.Get("Location")
			if location != "" {
				if !strings.HasPrefix(location, "http") {
					if strings.HasPrefix(location, "/") {
						location = c.config.ArchiveBox.URL + location
					} else {
						location = currentURL + "/" + location
					}
				}
				followReq, err := http.NewRequest("GET", location, nil)
				if err == nil {
					for _, cookie := range loginResp.Cookies() {
						followReq.AddCookie(cookie)
					}
					followResp, err := c.httpClient.Do(followReq)
					if err == nil {
						defer followResp.Body.Close()
						for _, cookie := range followResp.Cookies() {
							if cookie.Name == "sessionid" {
								c.sessionCookie = cookie.Value
								log.Printf("Got session cookie after redirect: %s", cookie.Value)
							}
						}
						if c.sessionCookie != "" {
							c.isLoggedIn = true
							log.Printf("Successfully logged in to ArchiveBox using %s (after redirect)", endpoint)
							return nil
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("login failed: no session cookie received from any endpoint")
}

func (c *ArchiveBoxClient) verifyLogin() error {
	log.Printf("Verifying login by accessing admin page...")

	req, err := http.NewRequest("GET", c.config.ArchiveBox.URL+"/admin/", nil)
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}

	// Add cookies
	var cookies []string
	if c.sessionCookie != "" {
		cookies = append(cookies, "sessionid="+c.sessionCookie)
	}
	if c.csrfToken != "" { // Changed from c.csrfCookie to c.csrfToken
		cookies = append(cookies, "csrftoken="+c.csrfToken)
	}
	if len(cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to verify login: %w", err)
	}
	defer resp.Body.Close()

	// Get session cookie from verification response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sessionid" {
			c.sessionCookie = cookie.Value
			break
		}
	}

	if c.sessionCookie == "" {
		return fmt.Errorf("still no session cookie after verification")
	}

	c.isLoggedIn = true
	log.Printf("Login verified successfully")
	return nil
}

func (c *ArchiveBoxClient) archiveURL(urlStr string, username string) error {
	if err := c.login(); err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	// Step 1: Get the add page to extract CSRF token
	addURL := c.config.ArchiveBox.URL + "/add/"
	req, err := http.NewRequest("GET", addURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add session cookie
	if c.sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to access add page: %v", err)
	}
	defer resp.Body.Close()

	// Check if we got redirected to login (session expired)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "login") {
			// Session expired, try to login again
			c.isLoggedIn = false
			if err := c.login(); err != nil {
				return fmt.Errorf("re-login failed: %v", err)
			}
			// Retry the request
			return c.archiveURL(urlStr, username)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read add page: %v", err)
	}

	// Extract CSRF token from the add form
	csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
	csrfMatches := csrfRegex.FindStringSubmatch(string(body))
	if len(csrfMatches) < 2 {
		return fmt.Errorf("failed to extract CSRF token from add page")
	}
	c.csrfToken = csrfMatches[1]

	// Step 2: Submit the URL addition form
	addData := url.Values{}
	addData.Set("url", urlStr)
	addData.Set("parser", "url_list")
	addData.Set("depth", "0")

	// Combine base tag with username tag if provided
	tag := c.config.ArchiveBox.Tag
	if username != "" {
		tag = fmt.Sprintf("%s,fediarchive-%s", tag, username)
	}
	addData.Set("tag", tag)
	log.Printf("Archiving URL with tags: %s", tag)
	addData.Set("force", "true")
	addData.Set("csrfmiddlewaretoken", c.csrfToken)

	addReq, err := http.NewRequest("POST", addURL, strings.NewReader(addData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create add request: %v", err)
	}

	addReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addReq.Header.Set("Referer", addURL)

	// Add session cookie
	if c.sessionCookie != "" {
		addReq.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})
	}

	// Add CSRF cookie if available
	if c.csrfToken != "" { // Changed from c.csrfCookie to c.csrfToken
		addReq.AddCookie(&http.Cookie{Name: "csrftoken", Value: c.csrfToken})
	}

	addResp, err := c.httpClient.Do(addReq)
	if err != nil {
		return fmt.Errorf("failed to submit add request: %v", err)
	}
	defer addResp.Body.Close()

	// Check if we got redirected to login (session expired)
	if addResp.StatusCode == http.StatusFound || addResp.StatusCode == http.StatusMovedPermanently {
		location := addResp.Header.Get("Location")
		if strings.Contains(location, "login") {
			// Session expired, try to login again
			c.isLoggedIn = false
			if err := c.login(); err != nil {
				return fmt.Errorf("re-login failed: %v", err)
			}
			// Retry the request
			return c.archiveURL(urlStr, username)
		}
	}

	// Success - URL was added to the queue
	if addResp.StatusCode == http.StatusOK || addResp.StatusCode == http.StatusFound {
		log.Printf("Successfully queued URL for archiving: %s", urlStr)
		return nil
	}

	// Read response body for error details
	responseBody, _ := io.ReadAll(addResp.Body)
	log.Printf("Failed to archive URL %s - status: %d, response: %s", urlStr, addResp.StatusCode, string(responseBody))
	return fmt.Errorf("failed to archive URL %s - status: %d", urlStr, addResp.StatusCode)
}

func (c *ArchiveBoxClient) testConnection() error {
	// Test ArchiveBox connection by trying to access the main page
	req, err := http.NewRequest("GET", c.config.ArchiveBox.URL+"/", nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to ArchiveBox: %w", err)
	}
	defer resp.Body.Close()

	// Accept 200 as successful response (ArchiveBox is accessible)
	if resp.StatusCode == http.StatusOK {
		log.Printf("ArchiveBox connection successful (status: %d)", resp.StatusCode)
		return nil
	}

	return fmt.Errorf("ArchiveBox connection failed - status: %d", resp.StatusCode)
}

func main() {
	// Parse command line flags
	singleRun := flag.Bool("single", false, "Run only once instead of continuously")
	flag.Parse()

	// Load configuration
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to parse config.json: %v", err)
	}

	// Initialize clients
	fediverseClient := NewFediverseClient(&config)
	archiveClient := NewArchiveBoxClient(&config)

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
		// Test ArchiveBox connection and authentication
		if err := archiveClient.testConnection(); err != nil {
			log.Printf("ArchiveBox connection test failed: %v", err)
			log.Println("Please check your ArchiveBox configuration and ensure the service is running")
			if !*singleRun {
				log.Println("Waiting 1 hour before retry...")
				time.Sleep(1 * time.Hour)
				continue
			} else {
				break
			}
		}
		log.Println("ArchiveBox connection test successful")

		// Authenticate with ArchiveBox
		if err := archiveClient.login(); err != nil {
			log.Printf("ArchiveBox authentication failed: %v", err)
			log.Println("Please check your ArchiveBox credentials in config.json")
			if !*singleRun {
				log.Println("Waiting 1 hour before retry...")
				time.Sleep(1 * time.Hour)
				continue
			} else {
				break
			}
		}
		log.Println("ArchiveBox authentication successful")
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
			urls := extractURLsFromStatus(status, instanceHostname, fediverseHostnames)
			for _, url := range urls {
				urlsToArchive[url] = true
			}
		}

		log.Printf("Home timeline visibility stats: %v", visibilityStats)
		log.Printf("Processed %d statuses, skipped %d statuses", processedCount, skippedCount)

		log.Printf("Found %d unique URLs to archive from home timeline", len(urlsToArchive))

		// Archive URLs from home timeline
		for url := range urlsToArchive {
			log.Printf("Archiving URL from home timeline: %s", url)
			if err := archiveClient.archiveURL(url, ""); err != nil {
				log.Printf("Failed to archive URL %s: %v", url, err)
			}
			// Add a small delay to avoid overwhelming the ArchiveBox instance
			time.Sleep(500 * time.Millisecond)
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
				urls := extractURLsFromStatus(status, instanceHostname, fediverseHostnames)
				for _, url := range urls {
					userURLsToArchive[url] = true
				}
			}

			log.Printf("User %s visibility stats: %v", follower.Username, userVisibilityStats)
			log.Printf("User %s: processed %d statuses, skipped %d statuses", follower.Username, userProcessedCount, userSkippedCount)

			log.Printf("Found %d unique URLs to archive from user %s", len(userURLsToArchive), follower.Username)

			// Archive URLs from user's posts
			for url := range userURLsToArchive {
				log.Printf("Archiving URL from user %s: %s", follower.Username, url)
				if err := archiveClient.archiveURL(url, follower.Username); err != nil {
					log.Printf("Failed to archive URL %s: %v", url, err)
				}
				// Add a small delay to avoid overwhelming the ArchiveBox instance
				time.Sleep(500 * time.Millisecond)
			}

			// Add delay between users to avoid rate limiting
			time.Sleep(2 * time.Second)
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
