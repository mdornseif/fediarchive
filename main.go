package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	} `json:"archivebox"`
}

// GoToSocial API types
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	CreatedAt   int64  `json:"created_at"`
}

type Account struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Acct        string `json:"acct"`
	DisplayName string `json:"display_name"`
	Locked      bool   `json:"locked"`
	Bot         bool   `json:"bot"`
	Group       bool   `json:"group"`
	CreatedAt   string `json:"created_at"`
	Note        string `json:"note"`
	URL         string `json:"url"`
	Avatar      string `json:"avatar"`
	Header      string `json:"header"`
	FollowersCount int `json:"followers_count"`
	FollowingCount int `json:"following_count"`
	StatusesCount int `json:"statuses_count"`
	Following   bool   `json:"following"`
	FollowedBy  bool   `json:"followed_by"`
	Requested   bool   `json:"requested"`
	Muting      bool   `json:"muting"`
	Blocking    bool   `json:"blocking"`
}

type Relationship struct {
	ID          string `json:"id"`
	Following   bool   `json:"following"`
	FollowedBy  bool   `json:"followed_by"`
	Requested   bool   `json:"requested"`
	Muting      bool   `json:"muting"`
	Blocking    bool   `json:"blocking"`
}

type Status struct {
	ID          string    `json:"id"`
	CreatedAt   string    `json:"created_at"`
	InReplyToID *string   `json:"in_reply_to_id"`
	InReplyToAccountID *string `json:"in_reply_to_account_id"`
	Sensitive   bool      `json:"sensitive"`
	SpoilerText string    `json:"spoiler_text"`
	Visibility  string    `json:"visibility"`
	Language    string    `json:"language"`
	URI         string    `json:"uri"`
	URL         string    `json:"url"`
	RepliesCount int      `json:"replies_count"`
	ReblogsCount int      `json:"reblogs_count"`
	FavouritesCount int   `json:"favourites_count"`
	Content     string    `json:"content"`
	Account     Account   `json:"account"`
	Reblogged   interface{} `json:"reblogged"` // Can be bool or Status object
	Application *struct {
		Name    string `json:"name"`
		Website string `json:"website"`
	} `json:"application"`
	MediaAttachments []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		URL         string `json:"url"`
		RemoteURL   string `json:"remote_url"`
		PreviewURL  string `json:"preview_url"`
		TextURL     string `json:"text_url"`
		Meta        struct {
			Original struct {
				Width  int `json:"width"`
				Height int `json:"height"`
				Size   string `json:"size"`
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
		Shortcode string `json:"shortcode"`
		URL       string `json:"url"`
		StaticURL string `json:"static_url"`
		VisibleInPicker bool `json:"visible_in_picker"`
	} `json:"emojis"`
	Card *struct {
		URL         string `json:"url"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Type        string `json:"type"`
		AuthorName  string `json:"author_name"`
		AuthorURL   string `json:"author_url"`
		ProviderName string `json:"provider_name"`
		ProviderURL string `json:"provider_url"`
		HTML        string `json:"html"`
		Width       int    `json:"width"`
		Height      int    `json:"height"`
		Image       string `json:"image"`
		EmbedURL    string `json:"embed_url"`
		Blurhash    string `json:"blurhash"`
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
			Shortcode string `json:"shortcode"`
			URL       string `json:"url"`
			StaticURL string `json:"static_url"`
			VisibleInPicker bool `json:"visible_in_picker"`
		} `json:"emojis"`
	} `json:"poll"`
}

type FediverseClient struct {
	config     *Config
	httpClient *http.Client
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

func extractURLs(content string) []string {
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^`+"`"+`\[\]]+`)
	matches := urlRegex.FindAllString(content, -1)
	
	var urls []string
	for _, match := range matches {
		// Clean up the URL (remove trailing punctuation)
		cleanURL := strings.TrimRight(match, ".,;:!?")
		
		// Skip internal Fediverse links
		if isInternalFediverseLink(cleanURL) {
			log.Printf("Skipping internal Fediverse link: %s", cleanURL)
			continue
		}
		
		urls = append(urls, cleanURL)
	}
	
	return urls
}

func isInternalFediverseLink(urlStr string) bool {
	// Common Fediverse domains to skip
	fediverseDomains := []string{
		"mstdn.social",
		"mastodon.social", 
		"mastodon.online",
		"mastodon.world",
		"mastodon.xyz",
		"mastodon.cloud",
		"mastodon.art",
		"mastodon.technology",
		"mastodon.green",
		"mastodon.lol",
		"mastodon.nu",
		"mastodon.org",
		"mastodon.com",
		"mastodon.net",
		"mastodon.co",
		"mastodon.io",
		"mastodon.me",
		"mastodon.space",
		"mastodon.work",
		"mastodon.cafe",
		"mastodon.zone",
		"mastodon.uno",
		"mastodon.one",
		"mastodon.town",
		"mastodon.city",
		"mastodon.country",
		"mastodon.state",
		"mastodon.land",
		"mastodon.earth",
		"mastodon.moon",
		"mastodon.sun",
		"mastodon.star",
		"mastodon.galaxy",
		"mastodon.universe",
		"mastodon.cosmos",
		"mastodon.void",
		"mastodon.null",
		"mastodon.zero",
		"mastodon.one",
		"mastodon.two",
		"mastodon.three",
		"mastodon.four",
		"mastodon.five",
		"mastodon.six",
		"mastodon.seven",
		"mastodon.eight",
		"mastodon.nine",
		"mastodon.ten",
	}
	
	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	// Check if it's a Fediverse domain
	for _, domain := range fediverseDomains {
		if strings.HasSuffix(parsedURL.Host, domain) {
			// Check for internal Fediverse paths
			path := parsedURL.Path
			if strings.HasPrefix(path, "/tags/") ||
			   strings.HasPrefix(path, "/@") ||
			   strings.HasPrefix(path, "/users/") ||
			   strings.HasPrefix(path, "/accounts/") ||
			   strings.HasPrefix(path, "/web/") ||
			   strings.HasPrefix(path, "/api/") ||
			   strings.HasPrefix(path, "/oauth/") ||
			   strings.HasPrefix(path, "/admin/") ||
			   strings.HasPrefix(path, "/settings/") ||
			   strings.HasPrefix(path, "/filters/") ||
			   strings.HasPrefix(path, "/blocks/") ||
			   strings.HasPrefix(path, "/mutes/") ||
			   strings.HasPrefix(path, "/follow_requests/") ||
			   strings.HasPrefix(path, "/lists/") ||
			   strings.HasPrefix(path, "/circles/") ||
			   strings.HasPrefix(path, "/conversations/") ||
			   strings.HasPrefix(path, "/notifications/") ||
			   strings.HasPrefix(path, "/favourites/") ||
			   strings.HasPrefix(path, "/bookmarks/") ||
			   strings.HasPrefix(path, "/pinned/") ||
			   strings.HasPrefix(path, "/statuses/") ||
			   strings.HasPrefix(path, "/media/") ||
			   strings.HasPrefix(path, "/search") ||
			   strings.HasPrefix(path, "/explore") ||
			   strings.HasPrefix(path, "/public") ||
			   strings.HasPrefix(path, "/local") ||
			   strings.HasPrefix(path, "/federated") ||
			   strings.HasPrefix(path, "/home") ||
			   strings.HasPrefix(path, "/direct") ||
			   strings.HasPrefix(path, "/mentions") ||
			   strings.HasPrefix(path, "/reports") ||
			   strings.HasPrefix(path, "/appeals") ||
			   strings.HasPrefix(path, "/domain_blocks") ||
			   strings.HasPrefix(path, "/email_domain_blocks") ||
			   strings.HasPrefix(path, "/ip_blocks") ||
			   strings.HasPrefix(path, "/retention") ||
			   strings.HasPrefix(path, "/instances") ||
			   strings.HasPrefix(path, "/peers") ||
			   strings.HasPrefix(path, "/announcements") ||
			   strings.HasPrefix(path, "/custom_emojis") ||
			   strings.HasPrefix(path, "/trends") ||
			   strings.HasPrefix(path, "/suggestions") ||
			   strings.HasPrefix(path, "/endorsements") ||
			   strings.HasPrefix(path, "/featured_tags") ||
			   strings.HasPrefix(path, "/preferences") ||
			   strings.HasPrefix(path, "/push_subscriptions") ||
			   strings.HasPrefix(path, "/apps") ||
			   strings.HasPrefix(path, "/instance") ||
			   strings.HasPrefix(path, "/nodeinfo") ||
			   strings.HasPrefix(path, "/.well-known/") {
				return true
			}
		}
	}
	
	return false
}

type ArchiveBoxClient struct {
	config     *Config
	httpClient *http.Client
}

func NewArchiveBoxClient(config *Config) *ArchiveBoxClient {
	return &ArchiveBoxClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *ArchiveBoxClient) archiveURL(url string) error {
	// ArchiveBox API endpoint for adding URLs
	archiveData := map[string]interface{}{
		"url": url,
		"depth": 0,
		"force": true,
	}

	archiveJSON, _ := json.Marshal(archiveData)
	req, err := http.NewRequest("POST", c.config.ArchiveBox.URL+"/api/add", bytes.NewBuffer(archiveJSON))
	if err != nil {
		return fmt.Errorf("failed to create archive request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add basic auth if configured
	if c.config.ArchiveBox.Username != "" && c.config.ArchiveBox.Password != "" {
		req.SetBasicAuth(c.config.ArchiveBox.Username, c.config.ArchiveBox.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to archive URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("archive request failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully queued URL for archiving: %s", url)
	return nil
}

func (c *ArchiveBoxClient) testConnection() error {
	// Test ArchiveBox connection
	req, err := http.NewRequest("GET", c.config.ArchiveBox.URL+"/api/", nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	// Add basic auth if configured
	if c.config.ArchiveBox.Username != "" && c.config.ArchiveBox.Password != "" {
		req.SetBasicAuth(c.config.ArchiveBox.Username, c.config.ArchiveBox.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to test ArchiveBox connection: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ArchiveBox API test failed with status %d", resp.StatusCode)
	}

	return nil
}

func main() {
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

	log.Println("Starting Archive Mastodon service...")

	for {
		// Test ArchiveBox connection
		if err := archiveClient.testConnection(); err != nil {
			log.Printf("ArchiveBox connection test failed: %v", err)
			log.Println("Please check your ArchiveBox configuration and ensure the service is running")
			log.Println("Waiting 1 hour before retry...")
			time.Sleep(1 * time.Hour)
			continue
		}
		log.Println("ArchiveBox connection test successful")
		// Authenticate with Fediverse instance
		if err := fediverseClient.authenticate(); err != nil {
			log.Printf("Authentication failed: %v", err)
			log.Println("Waiting 1 hour before retry...")
			time.Sleep(1 * time.Hour)
			continue
		}

		// Get followers and follow them back
		followers, err := fediverseClient.getFollowers()
		if err != nil {
			log.Printf("Failed to get followers: %v", err)
			log.Println("Waiting 1 hour before retry...")
			time.Sleep(1 * time.Hour)
			continue
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
			log.Println("Waiting 1 hour before retry...")
			time.Sleep(1 * time.Hour)
			continue
		}

		log.Printf("Retrieved %d statuses from home timeline", len(statuses))

		urlsToArchive := make(map[string]bool) // Use map to avoid duplicates

		for _, status := range statuses {
			// Extract URLs from status content
			urls := extractURLs(status.Content)
			for _, url := range urls {
				urlsToArchive[url] = true
			}

					// Extract URLs from reblogged status
		if status.Reblogged != nil {
			switch reblogged := status.Reblogged.(type) {
			case bool:
				// reblogged is just a boolean flag
				if reblogged {
					log.Printf("Status is a reblog (boolean flag)")
				}
			case map[string]interface{}:
				// reblogged is a Status object
				if content, ok := reblogged["content"].(string); ok {
					reblogURLs := extractURLs(content)
					for _, url := range reblogURLs {
						urlsToArchive[url] = true
					}
				}
			}
		}

			// Extract URLs from media attachments
			for _, media := range status.MediaAttachments {
				if media.URL != "" {
					urlsToArchive[media.URL] = true
				}
				if media.RemoteURL != "" {
					urlsToArchive[media.RemoteURL] = true
				}
			}

			// Extract URLs from card
			if status.Card != nil && status.Card.URL != "" {
				urlsToArchive[status.Card.URL] = true
			}
		}

		log.Printf("Found %d unique URLs to archive", len(urlsToArchive))

		// Archive URLs
		for url := range urlsToArchive {
			log.Printf("Archiving URL: %s", url)
			if err := archiveClient.archiveURL(url); err != nil {
				log.Printf("Failed to archive URL %s: %v", url, err)
			}
			// Add a small delay to avoid overwhelming the ArchiveBox instance
			time.Sleep(500 * time.Millisecond)
		}

		log.Println("Archive process completed")

		// Wait before next run
		log.Println("Waiting 30 minutes before next run...")
		time.Sleep(30 * time.Minute)
	}
} 